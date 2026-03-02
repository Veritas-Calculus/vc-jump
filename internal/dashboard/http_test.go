package dashboard

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Veritas-Calculus/vc-jump/internal/auth"
	"github.com/Veritas-Calculus/vc-jump/internal/config"
	"github.com/Veritas-Calculus/vc-jump/internal/storage"
)

// testHarness provides a complete test environment with real SQLite + Dashboard Server.
type testHarness struct {
	server *Server
	store  *storage.SQLiteStore
	t      *testing.T
	// adminToken is a valid session token for the admin user.
	adminToken string
	adminID    string
}

func newTestHarness(t *testing.T) *testHarness {
	t.Helper()

	dbPath := t.TempDir() + "/test-dashboard.db"
	store, err := storage.NewSQLiteStore(config.StorageConfig{
		Type:   "sqlite",
		DBPath: dbPath,
	})
	if err != nil {
		t.Fatalf("failed to create test store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	ctx := context.Background()
	if err := store.InitDefaultRoles(ctx); err != nil {
		t.Fatalf("failed to init default roles: %v", err)
	}

	// Create admin user.
	passwordHash, _ := auth.HashPassword("admin123")
	adminUser := &storage.UserWithPassword{
		User:         storage.User{Username: "admin", Source: "local"},
		PasswordHash: passwordHash,
		IsActive:     true,
	}
	if err := store.CreateUserWithPassword(ctx, adminUser); err != nil {
		t.Fatalf("failed to create admin user: %v", err)
	}
	dbUser, _ := store.GetUserByUsername(ctx, "admin")

	// Assign admin role.
	adminRole, _ := store.GetRoleByName(ctx, "admin")
	_ = store.AssignRole(ctx, dbUser.ID, adminRole.ID)

	dashCfg := DashboardConfig{
		ListenAddr:     ":0",
		SessionTimeout: 1 * time.Hour,
	}
	authCfg := config.AuthConfig{CacheDuration: 5 * time.Minute}

	srv, err := New(dashCfg, store, authCfg)
	if err != nil {
		t.Fatalf("failed to create dashboard server: %v", err)
	}

	// Login to get admin token.
	loginBody, _ := json.Marshal(map[string]string{
		"username": "admin",
		"password": "admin123",
	})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader(loginBody))
	req.Header.Set("Content-Type", "application/json")
	srv.mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("login failed: %d: %s", rr.Code, rr.Body.String())
	}
	var loginResp map[string]interface{}
	_ = json.Unmarshal(rr.Body.Bytes(), &loginResp)
	token, _ := loginResp["token"].(string)

	return &testHarness{
		server:     srv,
		store:      store,
		t:          t,
		adminToken: token,
		adminID:    dbUser.ID,
	}
}

// do sends an authenticated HTTP request and returns the recorder.
func (h *testHarness) do(method, path string, body interface{}) *httptest.ResponseRecorder {
	h.t.Helper()
	return h.doWithToken(method, path, body, h.adminToken)
}

// doWithToken sends a request with a specific token.
func (h *testHarness) doWithToken(method, path string, body interface{}, token string) *httptest.ResponseRecorder {
	h.t.Helper()
	var reqBody *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		reqBody = bytes.NewReader(b)
	} else {
		reqBody = bytes.NewReader(nil)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, reqBody)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	// Use s.server.Handler which includes securityHeaders middleware.
	h.server.server.Handler.ServeHTTP(rr, req)
	return rr
}

// doNoAuth sends an unauthenticated request.
func (h *testHarness) doNoAuth(method, path string, body interface{}) *httptest.ResponseRecorder {
	h.t.Helper()
	return h.doWithToken(method, path, body, "")
}

// unmarshal unmarshals the response body into v.
func (h *testHarness) unmarshal(rr *httptest.ResponseRecorder, v interface{}) {
	h.t.Helper()
	if err := json.Unmarshal(rr.Body.Bytes(), v); err != nil {
		h.t.Fatalf("failed to unmarshal response: %v\nbody: %s", err, rr.Body.String())
	}
}

// assertStatus checks the HTTP status code.
func (h *testHarness) assertStatus(rr *httptest.ResponseRecorder, want int) {
	h.t.Helper()
	if rr.Code != want {
		h.t.Errorf("status = %d, want %d\nbody: %s", rr.Code, want, rr.Body.String())
	}
}

// =============================================================================
// Auth flow tests
// =============================================================================

func TestHTTP_LoginLogoutFlow(t *testing.T) {
	t.Parallel()
	h := newTestHarness(t)

	t.Run("login success", func(t *testing.T) {
		rr := h.doNoAuth(http.MethodPost, "/api/login", map[string]string{
			"username": "admin",
			"password": "admin123",
		})
		h.assertStatus(rr, http.StatusOK)

		var resp map[string]interface{}
		h.unmarshal(rr, &resp)
		if resp["token"] == nil || resp["token"] == "" {
			t.Error("expected token in response")
		}
		user, ok := resp["user"].(map[string]interface{})
		if !ok {
			t.Fatal("expected user object in response")
		}
		if user["username"] != "admin" {
			t.Errorf("username = %v, want admin", user["username"])
		}

		// Session cookie should be set.
		cookies := rr.Result().Cookies()
		found := false
		for _, c := range cookies {
			if c.Name == "session" {
				found = true
				if !c.HttpOnly {
					t.Error("session cookie should be HttpOnly")
				}
			}
		}
		if !found {
			t.Error("session cookie not set")
		}
	})

	t.Run("login wrong password", func(t *testing.T) {
		rr := h.doNoAuth(http.MethodPost, "/api/login", map[string]string{
			"username": "admin",
			"password": "wrong",
		})
		h.assertStatus(rr, http.StatusUnauthorized)
	})

	t.Run("login invalid json", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader([]byte("not json")))
		req.Header.Set("Content-Type", "application/json")
		h.server.mux.ServeHTTP(rr, req)
		h.assertStatus(rr, http.StatusBadRequest)
	})

	t.Run("login GET not allowed", func(t *testing.T) {
		rr := h.doNoAuth(http.MethodGet, "/api/login", nil)
		h.assertStatus(rr, http.StatusMethodNotAllowed)
	})

	t.Run("logout", func(t *testing.T) {
		rr := h.do(http.MethodPost, "/api/logout", nil)
		h.assertStatus(rr, http.StatusOK)
	})
}

func TestHTTP_RequireAuth(t *testing.T) {
	t.Parallel()
	h := newTestHarness(t)

	t.Run("no token returns 401", func(t *testing.T) {
		rr := h.doNoAuth(http.MethodGet, "/api/me", nil)
		h.assertStatus(rr, http.StatusUnauthorized)
	})

	t.Run("invalid token returns 401", func(t *testing.T) {
		rr := h.doWithToken(http.MethodGet, "/api/me", nil, "invalid-token")
		h.assertStatus(rr, http.StatusUnauthorized)
	})

	t.Run("valid token returns 200", func(t *testing.T) {
		rr := h.do(http.MethodGet, "/api/me", nil)
		h.assertStatus(rr, http.StatusOK)
	})
}

func TestHTTP_Me(t *testing.T) {
	t.Parallel()
	h := newTestHarness(t)

	rr := h.do(http.MethodGet, "/api/me", nil)
	h.assertStatus(rr, http.StatusOK)

	var resp map[string]interface{}
	h.unmarshal(rr, &resp)

	if resp["username"] != "admin" {
		t.Errorf("username = %v, want admin", resp["username"])
	}
	if resp["roles"] == nil {
		t.Error("expected roles in response")
	}
	if resp["permissions"] == nil {
		t.Error("expected permissions in response")
	}
}

// =============================================================================
// Host CRUD tests
// =============================================================================

func TestHTTP_HostsCRUD(t *testing.T) {
	t.Parallel()
	h := newTestHarness(t)

	var createdID string

	t.Run("create host", func(t *testing.T) {
		rr := h.do(http.MethodPost, "/api/hosts", map[string]interface{}{
			"name": "test-server",
			"addr": "192.168.1.100",
			"port": 22,
			"user": "deploy",
		})
		h.assertStatus(rr, http.StatusOK)

		var host map[string]interface{}
		h.unmarshal(rr, &host)
		createdID, _ = host["id"].(string)
		if createdID == "" {
			t.Fatal("expected host ID in response")
		}
		if host["name"] != "test-server" {
			t.Errorf("name = %v, want test-server", host["name"])
		}
	})

	t.Run("list hosts", func(t *testing.T) {
		rr := h.do(http.MethodGet, "/api/hosts", nil)
		h.assertStatus(rr, http.StatusOK)

		var hosts []map[string]interface{}
		h.unmarshal(rr, &hosts)
		if len(hosts) < 1 {
			t.Error("expected at least 1 host")
		}
	})

	t.Run("get host", func(t *testing.T) {
		rr := h.do(http.MethodGet, "/api/hosts/"+createdID, nil)
		h.assertStatus(rr, http.StatusOK)

		var host map[string]interface{}
		h.unmarshal(rr, &host)
		if host["name"] != "test-server" {
			t.Errorf("name = %v, want test-server", host["name"])
		}
	})

	t.Run("get nonexistent host", func(t *testing.T) {
		rr := h.do(http.MethodGet, "/api/hosts/nonexistent-id", nil)
		h.assertStatus(rr, http.StatusNotFound)
	})

	t.Run("update host", func(t *testing.T) {
		rr := h.do(http.MethodPut, "/api/hosts/"+createdID, map[string]interface{}{
			"name": "updated-server",
			"addr": "10.0.0.1",
			"port": 2222,
		})
		h.assertStatus(rr, http.StatusOK)
	})

	t.Run("delete host", func(t *testing.T) {
		rr := h.do(http.MethodDelete, "/api/hosts/"+createdID, nil)
		h.assertStatus(rr, http.StatusOK)

		// Confirm deleted.
		rr = h.do(http.MethodGet, "/api/hosts/"+createdID, nil)
		h.assertStatus(rr, http.StatusNotFound)
	})

	t.Run("empty host ID", func(t *testing.T) {
		rr := h.do(http.MethodGet, "/api/hosts/", nil)
		h.assertStatus(rr, http.StatusBadRequest)
	})
}

// =============================================================================
// User CRUD tests
// =============================================================================

func TestHTTP_UsersCRUD(t *testing.T) {
	t.Parallel()
	h := newTestHarness(t)

	var createdID string

	t.Run("create user", func(t *testing.T) {
		rr := h.do(http.MethodPost, "/api/users", map[string]interface{}{
			"username": "testuser",
			"password": "P@ssw0rd!",
			"groups":   []string{"developers"},
		})
		h.assertStatus(rr, http.StatusOK)

		var user map[string]interface{}
		h.unmarshal(rr, &user)
		createdID, _ = user["id"].(string)
		if createdID == "" {
			t.Fatal("expected user ID in response")
		}
	})

	t.Run("list users", func(t *testing.T) {
		rr := h.do(http.MethodGet, "/api/users", nil)
		h.assertStatus(rr, http.StatusOK)

		var users []map[string]interface{}
		h.unmarshal(rr, &users)
		// admin + testuser.
		if len(users) < 2 {
			t.Errorf("expected at least 2 users, got %d", len(users))
		}
	})

	t.Run("get user", func(t *testing.T) {
		rr := h.do(http.MethodGet, "/api/users/"+createdID, nil)
		h.assertStatus(rr, http.StatusOK)

		var user map[string]interface{}
		h.unmarshal(rr, &user)
		if user["username"] != "testuser" {
			t.Errorf("username = %v, want testuser", user["username"])
		}
	})

	t.Run("update user", func(t *testing.T) {
		rr := h.do(http.MethodPut, "/api/users/"+createdID, map[string]interface{}{
			"username": "testuser-updated",
			"groups":   []string{"developers", "ops"},
		})
		h.assertStatus(rr, http.StatusOK)
	})

	t.Run("delete user", func(t *testing.T) {
		rr := h.do(http.MethodDelete, "/api/users/"+createdID, nil)
		h.assertStatus(rr, http.StatusOK)
	})
}

// =============================================================================
// Folder CRUD tests
// =============================================================================

func TestHTTP_FoldersCRUD(t *testing.T) {
	t.Parallel()
	h := newTestHarness(t)

	var createdID string

	t.Run("create folder", func(t *testing.T) {
		rr := h.do(http.MethodPost, "/api/folders", map[string]interface{}{
			"name":        "Production",
			"description": "Production servers",
		})
		h.assertStatus(rr, http.StatusOK)

		var folder map[string]interface{}
		h.unmarshal(rr, &folder)
		createdID, _ = folder["id"].(string)
		if createdID == "" {
			t.Fatal("expected folder ID")
		}
	})

	t.Run("list folders", func(t *testing.T) {
		rr := h.do(http.MethodGet, "/api/folders", nil)
		h.assertStatus(rr, http.StatusOK)

		var folders []map[string]interface{}
		h.unmarshal(rr, &folders)
		if len(folders) < 1 {
			t.Error("expected at least 1 folder")
		}
	})

	t.Run("list folders tree", func(t *testing.T) {
		rr := h.do(http.MethodGet, "/api/folders?tree=true", nil)
		h.assertStatus(rr, http.StatusOK)
	})

	t.Run("get folder", func(t *testing.T) {
		rr := h.do(http.MethodGet, "/api/folders/"+createdID, nil)
		h.assertStatus(rr, http.StatusOK)
	})

	t.Run("update folder", func(t *testing.T) {
		rr := h.do(http.MethodPut, "/api/folders/"+createdID, map[string]interface{}{
			"name":        "Production-Updated",
			"path":        "/production",
			"description": "Updated description",
		})
		h.assertStatus(rr, http.StatusOK)
	})

	t.Run("delete folder", func(t *testing.T) {
		rr := h.do(http.MethodDelete, "/api/folders/"+createdID, nil)
		h.assertStatus(rr, http.StatusOK)
	})
}

// =============================================================================
// IAM: Roles CRUD tests
// =============================================================================

func TestHTTP_RolesCRUD(t *testing.T) {
	t.Parallel()
	h := newTestHarness(t)

	var createdID string

	t.Run("list roles", func(t *testing.T) {
		rr := h.do(http.MethodGet, "/api/roles", nil)
		h.assertStatus(rr, http.StatusOK)

		var roles []map[string]interface{}
		h.unmarshal(rr, &roles)
		if len(roles) < 5 {
			t.Errorf("expected at least 5 default roles, got %d", len(roles))
		}
	})

	t.Run("create custom role", func(t *testing.T) {
		rr := h.do(http.MethodPost, "/api/roles", map[string]interface{}{
			"name":         "custom-role",
			"display_name": "Custom Role",
			"description":  "A custom test role",
			"permissions":  []string{"host:view", "host:connect"},
		})
		h.assertStatus(rr, http.StatusOK)

		var role map[string]interface{}
		h.unmarshal(rr, &role)
		createdID, _ = role["id"].(string)
	})

	t.Run("get role", func(t *testing.T) {
		rr := h.do(http.MethodGet, "/api/roles/"+createdID, nil)
		h.assertStatus(rr, http.StatusOK)
	})

	t.Run("get role via iam prefix", func(t *testing.T) {
		rr := h.do(http.MethodGet, "/api/iam/roles/"+createdID, nil)
		h.assertStatus(rr, http.StatusOK)
	})

	t.Run("update role", func(t *testing.T) {
		rr := h.do(http.MethodPut, "/api/roles/"+createdID, map[string]interface{}{
			"name":         "custom-role-updated",
			"display_name": "Updated Custom Role",
			"permissions":  []string{"host:view"},
		})
		h.assertStatus(rr, http.StatusOK)
	})

	t.Run("delete role", func(t *testing.T) {
		rr := h.do(http.MethodDelete, "/api/roles/"+createdID, nil)
		h.assertStatus(rr, http.StatusOK)
	})

	t.Run("permissions list", func(t *testing.T) {
		rr := h.do(http.MethodGet, "/api/iam/permissions", nil)
		h.assertStatus(rr, http.StatusOK)

		var perms []interface{}
		h.unmarshal(rr, &perms)
		if len(perms) < 20 {
			t.Errorf("expected at least 20 permissions, got %d", len(perms))
		}
	})
}

// =============================================================================
// Declarative IAM tests
// =============================================================================

func TestHTTP_DeclarativeUserRoles(t *testing.T) {
	t.Parallel()
	h := newTestHarness(t)

	// Create a test user.
	ctx := context.Background()
	passwordHash, _ := auth.HashPassword("test123")
	user := &storage.UserWithPassword{
		User:         storage.User{Username: "iam-test-user", Source: "local"},
		PasswordHash: passwordHash,
		IsActive:     true,
	}
	_ = h.store.CreateUserWithPassword(ctx, user)
	dbUser, _ := h.store.GetUserByUsername(ctx, "iam-test-user")

	t.Run("GET user roles initially empty", func(t *testing.T) {
		rr := h.do(http.MethodGet, "/api/users/"+dbUser.ID+"/roles", nil)
		h.assertStatus(rr, http.StatusOK)
	})

	t.Run("PUT set user roles", func(t *testing.T) {
		devRole, _ := h.store.GetRoleByName(ctx, "developer")
		rr := h.do(http.MethodPut, "/api/users/"+dbUser.ID+"/roles", map[string]interface{}{
			"role_ids": []string{devRole.ID},
		})
		h.assertStatus(rr, http.StatusOK)

		var resp map[string]interface{}
		h.unmarshal(rr, &resp)
		added, _ := resp["added"].([]interface{})
		if len(added) != 1 {
			t.Errorf("expected 1 added role, got %d", len(added))
		}
	})

	t.Run("PUT replace roles", func(t *testing.T) {
		opsRole, _ := h.store.GetRoleByName(ctx, "ops")
		rr := h.do(http.MethodPut, "/api/users/"+dbUser.ID+"/roles", map[string]interface{}{
			"role_ids": []string{opsRole.ID},
		})
		h.assertStatus(rr, http.StatusOK)

		var resp map[string]interface{}
		h.unmarshal(rr, &resp)
		// Should have removed developer and added ops.
		added, _ := resp["added"].([]interface{})
		removed, _ := resp["removed"].([]interface{})
		if len(added) != 1 {
			t.Errorf("expected 1 added, got %d", len(added))
		}
		if len(removed) != 1 {
			t.Errorf("expected 1 removed, got %d", len(removed))
		}
	})
}

func TestHTTP_DeclarativeHostPermissions(t *testing.T) {
	t.Parallel()
	h := newTestHarness(t)

	ctx := context.Background()

	// Create test user.
	passwordHash, _ := auth.HashPassword("test123")
	user := &storage.UserWithPassword{
		User:         storage.User{Username: "hp-test-user", Source: "local"},
		PasswordHash: passwordHash,
		IsActive:     true,
	}
	_ = h.store.CreateUserWithPassword(ctx, user)
	dbUser, _ := h.store.GetUserByUsername(ctx, "hp-test-user")

	// Create test hosts.
	host1 := &storage.Host{Name: "hp-host-1", Addr: "10.0.0.1", Port: 22}
	host2 := &storage.Host{Name: "hp-host-2", Addr: "10.0.0.2", Port: 22}
	_ = h.store.CreateHost(ctx, host1)
	_ = h.store.CreateHost(ctx, host2)

	t.Run("PUT set host permissions", func(t *testing.T) {
		rr := h.do(http.MethodPut, "/api/users/"+dbUser.ID+"/host-permissions", map[string]interface{}{
			"permissions": []map[string]interface{}{
				{"host_id": host1.ID, "can_sudo": true},
				{"host_id": host2.ID, "can_sudo": false},
			},
		})
		h.assertStatus(rr, http.StatusOK)

		var resp map[string]interface{}
		h.unmarshal(rr, &resp)
		added, _ := resp["added"].([]interface{})
		if len(added) != 2 {
			t.Errorf("expected 2 added, got %d", len(added))
		}
	})

	t.Run("GET host permissions", func(t *testing.T) {
		rr := h.do(http.MethodGet, "/api/users/"+dbUser.ID+"/host-permissions", nil)
		h.assertStatus(rr, http.StatusOK)
	})
}

// =============================================================================
// API Key tests
// =============================================================================

func TestHTTP_APIKeysCRUD(t *testing.T) {
	t.Parallel()
	h := newTestHarness(t)

	var keyID string
	var rawToken string

	t.Run("create api key", func(t *testing.T) {
		rr := h.do(http.MethodPost, "/api/api-keys", map[string]interface{}{
			"name":        "test-key",
			"description": "a test api key",
			"scopes":      []string{"host:view", "host:connect"},
			"expires_in":  "90d",
		})
		h.assertStatus(rr, http.StatusOK)

		var resp map[string]interface{}
		h.unmarshal(rr, &resp)
		keyID, _ = resp["id"].(string)
		rawToken, _ = resp["token"].(string)
		if keyID == "" {
			t.Fatal("expected key ID")
		}
		if rawToken == "" {
			t.Fatal("expected raw token")
		}
		if len(rawToken) < 10 {
			t.Errorf("token too short: %s", rawToken)
		}
	})

	t.Run("list api keys", func(t *testing.T) {
		rr := h.do(http.MethodGet, "/api/api-keys", nil)
		h.assertStatus(rr, http.StatusOK)

		var keys []map[string]interface{}
		h.unmarshal(rr, &keys)
		if len(keys) < 1 {
			t.Error("expected at least 1 API key")
		}
		// Token hash should not be exposed.
		for _, k := range keys {
			if k["token_hash"] != nil {
				t.Error("token_hash should not be in list response")
			}
		}
	})

	t.Run("get api key", func(t *testing.T) {
		rr := h.do(http.MethodGet, "/api/api-keys/"+keyID, nil)
		h.assertStatus(rr, http.StatusOK)
	})

	t.Run("authenticate with api key", func(t *testing.T) {
		rr := h.doWithToken(http.MethodGet, "/api/me", nil, rawToken)
		h.assertStatus(rr, http.StatusOK)

		var resp map[string]interface{}
		h.unmarshal(rr, &resp)
		if resp["username"] != "admin" {
			t.Errorf("username = %v, want admin", resp["username"])
		}
	})

	t.Run("rotate api key", func(t *testing.T) {
		rr := h.do(http.MethodPost, "/api/api-keys/"+keyID+"/rotate", nil)
		h.assertStatus(rr, http.StatusOK)

		var resp map[string]interface{}
		h.unmarshal(rr, &resp)
		newToken, _ := resp["token"].(string)
		if newToken == "" {
			t.Fatal("expected new token after rotation")
		}
		if newToken == rawToken {
			t.Error("rotated token should be different")
		}

		// New token should work.
		rr = h.doWithToken(http.MethodGet, "/api/me", nil, newToken)
		h.assertStatus(rr, http.StatusOK)

		// Rotate creates a new key with a new ID — update our references.
		newKeyID, _ := resp["id"].(string)
		if newKeyID == "" {
			t.Fatal("expected new key ID after rotation")
		}
		keyID = newKeyID
		rawToken = newToken
	})

	t.Run("delete api key", func(t *testing.T) {
		rr := h.do(http.MethodDelete, "/api/api-keys/"+keyID, nil)
		h.assertStatus(rr, http.StatusOK)

		// Deleted key should return 404.
		rr = h.do(http.MethodGet, "/api/api-keys/"+keyID, nil)
		h.assertStatus(rr, http.StatusNotFound)

		// Token should no longer authenticate.
		rr = h.doWithToken(http.MethodGet, "/api/me", nil, rawToken)
		h.assertStatus(rr, http.StatusUnauthorized)
	})
}

// =============================================================================
// Sessions & Stats tests
// =============================================================================

func TestHTTP_SessionsAndStats(t *testing.T) {
	t.Parallel()
	h := newTestHarness(t)

	t.Run("list sessions", func(t *testing.T) {
		rr := h.do(http.MethodGet, "/api/sessions", nil)
		h.assertStatus(rr, http.StatusOK)
	})

	t.Run("active sessions", func(t *testing.T) {
		rr := h.do(http.MethodGet, "/api/sessions/active", nil)
		h.assertStatus(rr, http.StatusOK)
	})

	t.Run("live sessions", func(t *testing.T) {
		rr := h.do(http.MethodGet, "/api/sessions/live", nil)
		h.assertStatus(rr, http.StatusOK)
	})

	t.Run("stats", func(t *testing.T) {
		rr := h.do(http.MethodGet, "/api/stats", nil)
		h.assertStatus(rr, http.StatusOK)

		var stats map[string]interface{}
		h.unmarshal(rr, &stats)
		// Should have standard stat fields.
		for _, key := range []string{"hosts", "users", "active_sessions"} {
			if _, ok := stats[key]; !ok {
				t.Errorf("missing stat field: %s", key)
			}
		}
	})
}

// =============================================================================
// Audit logs tests
// =============================================================================

func TestHTTP_AuditLogs(t *testing.T) {
	t.Parallel()
	h := newTestHarness(t)

	t.Run("list audit logs", func(t *testing.T) {
		rr := h.do(http.MethodGet, "/api/audit", nil)
		h.assertStatus(rr, http.StatusOK)
	})

	t.Run("audit stats", func(t *testing.T) {
		rr := h.do(http.MethodGet, "/api/audit/stats", nil)
		h.assertStatus(rr, http.StatusOK)
	})
}

// =============================================================================
// SSH Key tests
// =============================================================================

func TestHTTP_SSHKeys(t *testing.T) {
	t.Parallel()
	h := newTestHarness(t)

	t.Run("generate ed25519 key", func(t *testing.T) {
		rr := h.do(http.MethodPost, "/api/keys", map[string]interface{}{
			"name":     "test-key",
			"key_type": "ed25519",
		})
		h.assertStatus(rr, http.StatusOK)

		var key map[string]interface{}
		h.unmarshal(rr, &key)
		if key["id"] == nil || key["id"] == "" {
			t.Error("expected key ID")
		}
		if key["public_key"] == nil || key["public_key"] == "" {
			t.Error("expected public key")
		}
		if key["fingerprint"] == nil || key["fingerprint"] == "" {
			t.Error("expected fingerprint")
		}
		// Private key should NOT be in response.
		if key["private_key"] != nil {
			t.Error("private key should not be returned in create response")
		}
	})

	t.Run("list keys", func(t *testing.T) {
		rr := h.do(http.MethodGet, "/api/keys", nil)
		h.assertStatus(rr, http.StatusOK)

		var keys []map[string]interface{}
		h.unmarshal(rr, &keys)
		if len(keys) < 1 {
			t.Error("expected at least 1 key")
		}
		// Private keys should never be in list.
		for _, k := range keys {
			if k["private_key"] != nil {
				t.Error("private key must not appear in list response")
			}
		}
	})
}

// =============================================================================
// Security headers tests
// =============================================================================

func TestHTTP_SecurityHeaders(t *testing.T) {
	t.Parallel()
	h := newTestHarness(t)

	rr := h.do(http.MethodGet, "/api/me", nil)

	headers := map[string]string{
		"X-Frame-Options":            "DENY",
		"X-Content-Type-Options":     "nosniff",
		"X-XSS-Protection":           "1; mode=block",
		"Cross-Origin-Opener-Policy": "same-origin",
		"Cache-Control":              "no-store, no-cache, must-revalidate, private",
	}

	for name, want := range headers {
		got := rr.Header().Get(name)
		if got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
}

// =============================================================================
// SEO handlers tests
// =============================================================================

func TestHTTP_SEO(t *testing.T) {
	t.Parallel()
	h := newTestHarness(t)

	t.Run("robots.txt", func(t *testing.T) {
		rr := h.doNoAuth(http.MethodGet, "/robots.txt", nil)
		h.assertStatus(rr, http.StatusOK)
		if ct := rr.Header().Get("Content-Type"); ct != "text/plain; charset=utf-8" {
			t.Errorf("Content-Type = %q", ct)
		}
	})

	t.Run("sitemap.xml", func(t *testing.T) {
		rr := h.doNoAuth(http.MethodGet, "/sitemap.xml", nil)
		h.assertStatus(rr, http.StatusOK)
	})
}

// =============================================================================
// Deprecated endpoint tests
// =============================================================================

func TestHTTP_DeprecatedEndpointHeaders(t *testing.T) {
	t.Parallel()
	h := newTestHarness(t)

	// Create user to have a valid user ID for the deprecated endpoint.
	ctx := context.Background()
	passwordHash, _ := auth.HashPassword("test123")
	user := &storage.UserWithPassword{
		User:         storage.User{Username: "dep-user", Source: "local"},
		PasswordHash: passwordHash,
		IsActive:     true,
	}
	_ = h.store.CreateUserWithPassword(ctx, user)
	dbUser, _ := h.store.GetUserByUsername(ctx, "dep-user")

	rr := h.do(http.MethodGet, "/api/iam/user-roles/"+dbUser.ID, nil)
	// Should have deprecation headers.
	if dep := rr.Header().Get("Deprecation"); dep != "true" {
		t.Errorf("Deprecation header = %q, want 'true'", dep)
	}
	if link := rr.Header().Get("Link"); link == "" {
		t.Error("Link header should be set for deprecated endpoints")
	}
}

// =============================================================================
// Health check tests
// =============================================================================

func TestHTTP_HealthCheck(t *testing.T) {
	t.Parallel()
	h := newTestHarness(t)

	t.Run("healthz always returns 200", func(t *testing.T) {
		rr := h.doNoAuth(http.MethodGet, "/healthz", nil)
		h.assertStatus(rr, http.StatusOK)
		if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", ct)
		}
	})

	t.Run("readyz returns 200 when DB is ready", func(t *testing.T) {
		rr := h.doNoAuth(http.MethodGet, "/readyz", nil)
		h.assertStatus(rr, http.StatusOK)
	})

	t.Run("healthz no auth required", func(t *testing.T) {
		rr := h.doNoAuth(http.MethodGet, "/healthz", nil)
		h.assertStatus(rr, http.StatusOK)
	})
}
