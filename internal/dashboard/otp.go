// OTP API handlers for dashboard.
package dashboard

import (
	"encoding/json"
	"net/http"

	"github.com/Veritas-Calculus/vc-jump/internal/otp"
)

// OTP API request/response types.

type otpSetupResponse struct {
	Secret     string `json:"secret"`  //nolint:gosec // G117: OTP secret is intentional API response
	QRCode     string `json:"qr_code"` // Base64 encoded PNG.
	OTPAuthURL string `json:"otpauth_url"`
}

type otpVerifyRequest struct {
	Code string `json:"code"`
}

type otpStatusResponse struct {
	Enabled      bool `json:"enabled"`
	Verified     bool `json:"verified"`
	ForceEnabled bool `json:"force_enabled"` // Global setting.
}

// handleOTPStatus returns the OTP status for the current user.
// GET /api/otp/status
func (s *Server) handleOTPStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID, ok := r.Context().Value(contextKeyUserID).(string)
	if !ok || userID == "" {
		s.jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	user, err := s.store.GetUser(r.Context(), userID)
	if err != nil {
		s.jsonError(w, "user not found", http.StatusNotFound)
		return
	}

	// Check global force setting.
	forceEnabled := false
	if val, _ := s.store.GetSetting(r.Context(), "otp_force_enabled"); val == "true" {
		forceEnabled = true
	}

	s.jsonResponse(w, otpStatusResponse{
		Enabled:      user.OTPEnabled,
		Verified:     user.OTPVerified,
		ForceEnabled: forceEnabled,
	})
}

// handleOTPSetup generates a new OTP secret for the current user.
// POST /api/otp/setup
func (s *Server) handleOTPSetup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID, ok := r.Context().Value(contextKeyUserID).(string)
	if !ok || userID == "" {
		s.jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	user, err := s.store.GetUser(r.Context(), userID)
	if err != nil {
		s.jsonError(w, "user not found", http.StatusNotFound)
		return
	}

	// Generate new OTP secret.
	issuer := "VC-Jump"
	key, err := otp.GenerateSecret(user.Username, issuer)
	if err != nil {
		s.jsonError(w, "failed to generate OTP secret", http.StatusInternalServerError)
		return
	}

	// Save secret to database.
	if err := s.store.SetUserOTPSecret(r.Context(), userID, key.Secret()); err != nil {
		s.jsonError(w, "failed to save OTP secret", http.StatusInternalServerError)
		return
	}

	// Generate QR code.
	qrCode, err := otp.GenerateQRCode(key, 200, 200)
	if err != nil {
		s.jsonError(w, "failed to generate QR code", http.StatusInternalServerError)
		return
	}

	s.jsonResponse(w, otpSetupResponse{
		Secret:     key.Secret(),
		QRCode:     qrCode,
		OTPAuthURL: key.URL(),
	})
}

// handleOTPVerify verifies the OTP code and enables OTP for the user.
// POST /api/otp/verify
func (s *Server) handleOTPVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID, ok := r.Context().Value(contextKeyUserID).(string)
	if !ok || userID == "" {
		s.jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req otpVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	user, err := s.store.GetUser(r.Context(), userID)
	if err != nil {
		s.jsonError(w, "user not found", http.StatusNotFound)
		return
	}

	if user.OTPSecret == "" {
		s.jsonError(w, "OTP not set up, call /api/otp/setup first", http.StatusBadRequest)
		return
	}

	// Validate OTP code.
	if !otp.Validate(req.Code, user.OTPSecret) {
		s.jsonError(w, "invalid OTP code", http.StatusBadRequest)
		return
	}

	// Enable OTP for user.
	if err := s.store.EnableUserOTP(r.Context(), userID); err != nil {
		s.jsonError(w, "failed to enable OTP", http.StatusInternalServerError)
		return
	}

	s.jsonResponse(w, map[string]string{"status": "enabled"})
}

// handleOTPDisable disables OTP for the current user.
// DELETE /api/otp
func (s *Server) handleOTPDisable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		s.jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID, ok := r.Context().Value(contextKeyUserID).(string)
	if !ok || userID == "" {
		s.jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Check if OTP is globally forced.
	if val, _ := s.store.GetSetting(r.Context(), "otp_force_enabled"); val == "true" {
		s.jsonError(w, "OTP is globally enforced and cannot be disabled", http.StatusForbidden)
		return
	}

	if err := s.store.DisableUserOTP(r.Context(), userID); err != nil {
		s.jsonError(w, "failed to disable OTP", http.StatusInternalServerError)
		return
	}

	s.jsonResponse(w, map[string]string{"status": "disabled"})
}

// handleOTPSettings handles global OTP settings (admin only).
// GET/PUT /api/settings/otp
func (s *Server) handleOTPSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.getOTPSettings(w, r)
	case http.MethodPut:
		s.updateOTPSettings(w, r)
	default:
		s.jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) getOTPSettings(w http.ResponseWriter, r *http.Request) {
	forceEnabled := false
	if val, _ := s.store.GetSetting(r.Context(), "otp_force_enabled"); val == "true" {
		forceEnabled = true
	}

	s.jsonResponse(w, map[string]bool{"force_enabled": forceEnabled})
}

func (s *Server) updateOTPSettings(w http.ResponseWriter, r *http.Request) {
	if !s.hasPermission(r, "settings:update") {
		s.jsonError(w, "forbidden", http.StatusForbidden)
		return
	}

	var req struct {
		ForceEnabled bool `json:"force_enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	value := "false"
	if req.ForceEnabled {
		value = "true"
	}

	if err := s.store.SetSetting(r.Context(), "otp_force_enabled", value); err != nil {
		s.jsonError(w, "failed to update setting", http.StatusInternalServerError)
		return
	}

	s.jsonResponse(w, map[string]string{"status": "updated"})
}
