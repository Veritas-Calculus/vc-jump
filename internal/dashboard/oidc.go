// OIDC authentication handlers for the dashboard.
package dashboard

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Veritas-Calculus/vc-jump/internal/config"
	"github.com/Veritas-Calculus/vc-jump/internal/storage"
)

// oidcProvider holds the OIDC provider configuration discovered from the issuer.
type oidcProvider struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

// oidcTokenResponse represents the token endpoint response.
type oidcTokenResponse struct {
	AccessToken  string `json:"access_token"` //nolint:gosec // G117: OAuth2 token field
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"` //nolint:gosec // G117: OAuth2 token field
}

// oidcUserInfo represents the userinfo endpoint response.
type oidcUserInfo struct {
	Sub               string `json:"sub"`
	Email             string `json:"email"`
	EmailVerified     bool   `json:"email_verified"`
	Name              string `json:"name"`
	PreferredUsername string `json:"preferred_username"`
}

// oidcState stores pending authorization states.
type oidcState struct {
	CreatedAt time.Time
	Nonce     string
}

var (
	oidcStates   = make(map[string]*oidcState)
	oidcStatesMu sync.Mutex
)

// discoverOIDCProvider fetches the OIDC discovery document.
func discoverOIDCProvider(issuerURL string) (*oidcProvider, error) {
	discoveryURL := strings.TrimRight(issuerURL, "/") + "/.well-known/openid-configuration"

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create discovery request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req) //nolint:gosec // G704: URL from admin-configured OIDC issuer
	if err != nil {
		return nil, fmt.Errorf("failed to fetch OIDC discovery document: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OIDC discovery returned status %d", resp.StatusCode)
	}

	var provider oidcProvider
	if err := json.NewDecoder(resp.Body).Decode(&provider); err != nil {
		return nil, fmt.Errorf("failed to decode OIDC discovery document: %w", err)
	}

	if provider.AuthorizationEndpoint == "" || provider.TokenEndpoint == "" {
		return nil, fmt.Errorf("OIDC discovery document missing required endpoints")
	}

	return &provider, nil
}

// generateRandomState creates a random state parameter for CSRF protection.
func generateRandomState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// handleOIDCLogin initiates the OIDC authorization flow.
// GET /api/auth/oidc/login — redirects to the OIDC provider.
func (s *Server) handleOIDCLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	authCfg := s.authCfg
	if authCfg.OIDCIssuer == "" || authCfg.OIDCClientID == "" {
		s.jsonError(w, "OIDC not configured", http.StatusNotImplemented)
		return
	}

	provider, err := discoverOIDCProvider(authCfg.OIDCIssuer)
	if err != nil {
		s.jsonError(w, "failed to discover OIDC provider: "+err.Error(), http.StatusInternalServerError)
		return
	}

	state, err := generateRandomState()
	if err != nil {
		s.jsonError(w, "failed to generate state", http.StatusInternalServerError)
		return
	}

	nonce, err := generateRandomState()
	if err != nil {
		s.jsonError(w, "failed to generate nonce", http.StatusInternalServerError)
		return
	}

	// Store state for verification on callback.
	oidcStatesMu.Lock()
	oidcStates[state] = &oidcState{CreatedAt: time.Now(), Nonce: nonce}
	// Clean up old states (> 10 minutes).
	for k, v := range oidcStates {
		if time.Since(v.CreatedAt) > 10*time.Minute {
			delete(oidcStates, k)
		}
	}
	oidcStatesMu.Unlock()

	// Build authorization URL.
	authURL, _ := url.Parse(provider.AuthorizationEndpoint)
	q := authURL.Query()
	q.Set("response_type", "code")
	q.Set("client_id", authCfg.OIDCClientID)
	q.Set("redirect_uri", authCfg.OIDCRedirectURL)
	q.Set("scope", "openid email profile")
	q.Set("state", state)
	q.Set("nonce", nonce)
	authURL.RawQuery = q.Encode()

	http.Redirect(w, r, authURL.String(), http.StatusFound)
}

// handleOIDCCallback handles the OIDC provider callback.
// GET /api/auth/oidc/callback?code=...&state=...
func (s *Server) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	authCfg := s.authCfg
	if authCfg.OIDCIssuer == "" || authCfg.OIDCClientID == "" {
		s.jsonError(w, "OIDC not configured", http.StatusNotImplemented)
		return
	}

	// Validate state parameter.
	state := r.URL.Query().Get("state")
	if state == "" {
		s.jsonError(w, "missing state parameter", http.StatusBadRequest)
		return
	}

	oidcStatesMu.Lock()
	savedState, ok := oidcStates[state]
	if ok {
		delete(oidcStates, state)
	}
	oidcStatesMu.Unlock()

	if !ok {
		s.jsonError(w, "invalid or expired state", http.StatusBadRequest)
		return
	}

	// Check for provider errors.
	if errMsg := r.URL.Query().Get("error"); errMsg != "" {
		desc := r.URL.Query().Get("error_description")
		s.jsonError(w, fmt.Sprintf("OIDC error: %s — %s", errMsg, desc), http.StatusUnauthorized)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		s.jsonError(w, "missing authorization code", http.StatusBadRequest)
		return
	}

	// Exchange code for tokens.
	provider, err := discoverOIDCProvider(authCfg.OIDCIssuer)
	if err != nil {
		s.jsonError(w, "failed to discover OIDC provider", http.StatusInternalServerError)
		return
	}

	tokenResp, err := s.exchangeOIDCCode(provider, code, authCfg)
	if err != nil {
		s.jsonError(w, "failed to exchange authorization code: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Get user info.
	userInfo, err := s.getOIDCUserInfo(provider, tokenResp.AccessToken)
	if err != nil {
		s.jsonError(w, "failed to get user info: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Determine username.
	username := userInfo.PreferredUsername
	if username == "" {
		username = userInfo.Email
	}
	if username == "" {
		username = userInfo.Sub
	}

	// Auto-provision or find user in local storage.
	user, err := s.provisionOIDCUser(r.Context(), username, userInfo)
	if err != nil {
		s.jsonError(w, "failed to provision user: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Create a session token for the user.
	sessionToken, err := s.session.CreateSession(r.Context(), user.ID)
	if err != nil {
		s.jsonError(w, "failed to create session", http.StatusInternalServerError)
		return
	}

	// Audit log.
	s.logAudit("oidc_login", username, getClientIP(r), "", "OIDC login", "success", map[string]interface{}{
		"oidc_sub":   userInfo.Sub,
		"oidc_email": userInfo.Email,
		"nonce":      savedState.Nonce,
	})

	// Return JWT/session token as JSON (SPA can store it).
	s.jsonResponse(w, map[string]interface{}{
		"token":    sessionToken,
		"username": username,
		"user_id":  user.ID,
	})
}

// exchangeOIDCCode exchanges an authorization code for tokens.
func (s *Server) exchangeOIDCCode(provider *oidcProvider, code string, authCfg config.AuthConfig) (*oidcTokenResponse, error) {
	data := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {authCfg.OIDCRedirectURL},
		"client_id":     {authCfg.OIDCClientID},
		"client_secret": {authCfg.OIDCClientSecret},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, provider.TokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req) //nolint:gosec // G704: URL from OIDC discovery
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("token endpoint returned %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp oidcTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, err
	}
	return &tokenResp, nil
}

// getOIDCUserInfo fetches user information from the OIDC provider.
func (s *Server) getOIDCUserInfo(provider *oidcProvider, accessToken string) (*oidcUserInfo, error) {
	if provider.UserinfoEndpoint == "" {
		return nil, fmt.Errorf("OIDC provider does not support userinfo endpoint")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, provider.UserinfoEndpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req) //nolint:gosec // G704: URL from OIDC discovery
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo endpoint returned %d", resp.StatusCode)
	}

	var userInfo oidcUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, err
	}
	return &userInfo, nil
}

// provisionOIDCUser finds or creates a user from OIDC claims.
func (s *Server) provisionOIDCUser(ctx context.Context, username string, userInfo *oidcUserInfo) (*storage.User, error) { //nolint:unparam // userInfo reserved for future claim-based provisioning
	// Try to find existing user.
	existing, err := s.store.GetUserByUsername(ctx, username)
	if err == nil {
		return existing, nil
	}

	// Auto-create OIDC user.
	user := &storage.User{
		Username: username,
		Source:   storage.UserSourceOIDC,
		Groups:   []string{"oidc-users"},
		IsActive: true,
	}

	if err := s.store.CreateUser(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to create OIDC user: %w", err)
	}

	return user, nil
}
