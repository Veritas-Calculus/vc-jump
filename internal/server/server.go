// Package server provides the SSH server implementation for vc-jump.
package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Veritas-Calculus/vc-jump/internal/audit"
	"github.com/Veritas-Calculus/vc-jump/internal/auth"
	"github.com/Veritas-Calculus/vc-jump/internal/config"
	"github.com/Veritas-Calculus/vc-jump/internal/logger"
	"github.com/Veritas-Calculus/vc-jump/internal/otp"
	"github.com/Veritas-Calculus/vc-jump/internal/proxy"
	"github.com/Veritas-Calculus/vc-jump/internal/rbac"
	"github.com/Veritas-Calculus/vc-jump/internal/recording"
	"github.com/Veritas-Calculus/vc-jump/internal/selector"
	"github.com/Veritas-Calculus/vc-jump/internal/storage"
	"golang.org/x/crypto/ssh"
)

// Server represents the SSH bastion server.
type Server struct {
	cfg         *config.Config
	sshConfig   *ssh.ServerConfig
	listener    net.Listener
	auth        *auth.Authenticator
	recorder    *recording.Recorder
	proxy       *proxy.Proxy
	selector    *selector.Selector
	logger      *logger.Logger
	auditor     *audit.Auditor
	sqliteStore *storage.SQLiteStore
	connSem     chan struct{}
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	mu          sync.RWMutex
	started     bool
}

// New creates a new SSH server with the given configuration.
func New(cfg *config.Config) (*Server, error) {
	if cfg == nil {
		return nil, errors.New("config cannot be nil")
	}

	ctx, cancel := context.WithCancel(context.Background())

	s := &Server{
		cfg:     cfg,
		connSem: make(chan struct{}, cfg.Server.MaxConnections),
		ctx:     ctx,
		cancel:  cancel,
	}

	// Initialize logger.
	l, err := logger.New(cfg.Logging)
	if err != nil {
		// Fallback to stdout logger.
		l, _ = logger.New(config.LoggingConfig{
			Level:  "info",
			Format: "text",
			Output: "stdout",
		})
	}
	s.logger = l

	// Initialize auditor if enabled.
	if cfg.Audit.Enabled {
		auditor, err := audit.New(cfg.Audit)
		if err != nil {
			s.logger.Warnf("failed to create auditor: %v", err)
		} else {
			s.auditor = auditor
		}
	}

	// Initialize authenticator.
	authenticator, err := auth.New(cfg.Auth)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create authenticator: %w", err)
	}
	s.auth = authenticator

	// Initialize recorder if enabled.
	if cfg.Recording.Enabled {
		recorder, err := recording.New(cfg.Recording)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("failed to create recorder: %w", err)
		}
		s.recorder = recorder
	}

	// Initialize proxy.
	s.proxy = proxy.New()

	// Initialize selector.
	s.selector = selector.New(cfg.Hosts)

	// Load or generate host key.
	sshConfig, err := s.createSSHConfig()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create SSH config: %w", err)
	}
	s.sshConfig = sshConfig

	return s, nil
}

// SetSQLiteStore sets the SQLite store and updates the selector and auth to use it.
func (s *Server) SetSQLiteStore(store *storage.SQLiteStore) {
	s.sqliteStore = store
	// Update selector to use database.
	s.selector = selector.NewWithStore(store)
	// Update auth to use database.
	authenticator, err := auth.NewWithStore(s.cfg.Auth, store)
	if err != nil {
		s.logger.Warnf("failed to create authenticator with store: %v", err)
		return
	}
	s.auth = authenticator
	// Update SSH config with new auth callbacks.
	s.sshConfig.PasswordCallback = s.passwordCallback
	s.sshConfig.PublicKeyCallback = s.publicKeyCallback
}

// GetRecorder returns the session recorder if recording is enabled.
func (s *Server) GetRecorder() *recording.Recorder {
	return s.recorder
}

// Start begins accepting SSH connections.
func (s *Server) Start() error {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return errors.New("server already started")
	}
	s.started = true
	s.mu.Unlock()

	listener, err := net.Listen("tcp", s.cfg.Server.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}
	s.listener = listener

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-s.ctx.Done():
				return nil
			default:
				s.logger.Infof("failed to accept connection: %v", err)
				continue
			}
		}

		// Rate limit connections.
		select {
		case s.connSem <- struct{}{}:
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				defer func() { <-s.connSem }()
				s.handleConnection(conn)
			}()
		default:
			s.logger.Infof("max connections reached, rejecting connection from %s", conn.RemoteAddr())
			_ = conn.Close()
		}
	}
}

// ReloadHosts updates the configured hosts list at runtime.
// This is safe to call while the server is running.
func (s *Server) ReloadHosts(hosts []config.HostConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg.Hosts = hosts
	if s.selector != nil {
		s.selector.UpdateHosts(hosts)
	}
}

// Stop gracefully shuts down the server.
func (s *Server) Stop() error {
	s.cancel()

	if s.listener != nil {
		if err := s.listener.Close(); err != nil {
			return fmt.Errorf("failed to close listener: %w", err)
		}
	}

	// Wait for all connections to finish with timeout.
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		s.logger.Info("timeout waiting for connections to close")
	}

	// Close resources.
	if s.auditor != nil {
		_ = s.auditor.Close()
	}
	if s.logger != nil {
		_ = s.logger.Close()
	}

	return nil
}

func (s *Server) createSSHConfig() (*ssh.ServerConfig, error) {
	sshConfig := &ssh.ServerConfig{
		PasswordCallback:  s.passwordCallback,
		PublicKeyCallback: s.publicKeyCallback,
		// SSH hardening: configure secure algorithms
		Config: ssh.Config{
			// Key exchange algorithms - exclude NIST curves and SHA-1 based algorithms
			KeyExchanges: []string{
				"curve25519-sha256",
				"curve25519-sha256@libssh.org",
				// Post-quantum hybrid (OpenSSH 9.9+)
				// "mlkem768x25519-sha256", // Uncomment when Go crypto/ssh supports it
			},
			// Ciphers - use only authenticated encryption modes
			Ciphers: []string{
				"chacha20-poly1305@openssh.com",
				"aes256-gcm@openssh.com",
				"aes128-gcm@openssh.com",
				"aes256-ctr",
				"aes192-ctr",
				"aes128-ctr",
			},
			// MACs - use only ETM (Encrypt-then-MAC) modes, avoid SHA-1
			MACs: []string{
				"hmac-sha2-256-etm@openssh.com",
				"hmac-sha2-512-etm@openssh.com",
			},
		},
	}

	hostKey, err := s.loadOrGenerateHostKey()
	if err != nil {
		return nil, err
	}
	sshConfig.AddHostKey(hostKey)

	return sshConfig, nil
}

func (s *Server) loadOrGenerateHostKey() (ssh.Signer, error) {
	keyPath := s.cfg.Server.HostKeyPath

	// Clean the path to prevent directory traversal.
	cleanPath := filepath.Clean(keyPath)

	keyData, err := os.ReadFile(cleanPath)
	if err != nil {
		if os.IsNotExist(err) {
			return s.generateHostKey(cleanPath)
		}
		return nil, fmt.Errorf("failed to read host key: %w", err)
	}

	signer, err := ssh.ParsePrivateKey(keyData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse host key: %w", err)
	}

	return signer, nil
}

func (s *Server) generateHostKey(keyPath string) (ssh.Signer, error) {
	key, err := generateED25519Key()
	if err != nil {
		return nil, fmt.Errorf("failed to generate host key: %w", err)
	}

	if err := os.WriteFile(keyPath, key, 0600); err != nil {
		return nil, fmt.Errorf("failed to write host key: %w", err)
	}

	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to parse generated key: %w", err)
	}

	return signer, nil
}

func (s *Server) passwordCallback(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	user, err := s.auth.AuthenticatePassword(s.ctx, conn.User(), string(password))
	if err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	return &ssh.Permissions{
		Extensions: map[string]string{
			"user":          user.Username,
			"groups":        joinGroups(user.Groups),
			"allowed_hosts": joinGroups(user.AllowedHosts),
		},
	}, nil
}

func (s *Server) publicKeyCallback(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	user, err := s.auth.AuthenticatePublicKey(s.ctx, conn.User(), key)
	if err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	return &ssh.Permissions{
		Extensions: map[string]string{
			"user":          user.Username,
			"groups":        joinGroups(user.Groups),
			"allowed_hosts": joinGroups(user.AllowedHosts),
		},
	}, nil
}

func (s *Server) handleConnection(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	sshConn, chans, reqs, err := ssh.NewServerConn(conn, s.sshConfig)
	if err != nil {
		s.logger.Infof("failed to handshake: %v", err)
		return
	}
	defer func() { _ = sshConn.Close() }()

	username := sshConn.User()
	sourceIP := sshConn.RemoteAddr().String()

	s.logger.Infof("new connection from %s (%s)", sourceIP, username)

	// Log login event.
	if s.auditor != nil {
		s.auditor.LogLogin(username, sourceIP, "success")
	}
	s.logAudit("ssh_login", username, sourceIP, "", "user login via SSH", "success", nil)

	// Discard global requests.
	go ssh.DiscardRequests(reqs)

	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			_ = newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}

		channel, requests, err := newChannel.Accept()
		if err != nil {
			s.logger.Infof("failed to accept channel: %v", err)
			continue
		}

		go s.handleSession(sshConn, channel, requests)
	}
}

func (s *Server) handleSession(sshConn *ssh.ServerConn, channel ssh.Channel, requests <-chan *ssh.Request) {
	defer func() { _ = channel.Close() }()

	username := sshConn.Permissions.Extensions["user"]
	groups := splitGroups(sshConn.Permissions.Extensions["groups"])
	allowedHosts := splitGroups(sshConn.Permissions.Extensions["allowed_hosts"])

	// Get list of accessible hosts for this user.
	hosts := s.selector.GetAccessibleHosts(username, groups, allowedHosts)

	// Apply RBAC filtering only if user doesn't have explicit allowed_hosts set.
	// If user has allowed_hosts, those already define their access (handled by GetAccessibleHosts).
	if len(allowedHosts) == 0 {
		hosts = s.filterHostsByRBAC(username, hosts)
	}

	if len(hosts) == 0 {
		_, _ = io.WriteString(channel, "No accessible hosts found.\r\n")
		return
	}

	// Handle shell/pty requests.
	var ptyReq *ptyRequest
	for req := range requests {
		switch req.Type {
		case "pty-req":
			ptyReq = parsePtyRequest(req.Payload)
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
		case "shell":
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
			s.runInteractiveSession(sshConn, channel, ptyReq, username, groups, hosts)
			return
		default:
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
}

func (s *Server) runInteractiveSession(
	sshConn *ssh.ServerConn,
	channel ssh.Channel,
	ptyReq *ptyRequest,
	username string,
	groups []string,
	hosts []config.HostConfig,
) {
	sourceIP := sshConn.RemoteAddr().String()
	isAdmin := s.isAdmin(username, groups)

	// Check if OTP verification is required.
	if !s.verifyOTP(channel, username) {
		return
	}

	selectedHost, err := s.selector.SelectHostWithAdmin(channel, hosts, isAdmin)
	if err != nil {
		s.logger.Infof("host selection failed: %v", err)
		return
	}

	if selectedHost.Name == "__admin__" {
		s.runAdminConsole(channel, username)
		return
	}

	s.logConnectEvent(username, sourceIP, selectedHost.Name)
	dbSession := s.createDBSession(username, sourceIP, selectedHost.Name)
	rec := s.startRecording(username, selectedHost.Name)

	defer s.cleanupSession(dbSession, rec)

	s.executeProxyConnection(channel, selectedHost, ptyReq, rec)
}

// verifyOTP checks if OTP is required and validates it.
// Returns true if OTP is not required or verification succeeds.
func (s *Server) verifyOTP(channel ssh.Channel, username string) bool {
	if s.sqliteStore == nil {
		return true // No database, skip OTP.
	}

	ctx := context.Background()

	// Check global OTP force setting.
	otpForced := s.cfg.OTP.ForceEnabled
	if !otpForced {
		// Check database setting.
		if val, _ := s.sqliteStore.GetSetting(ctx, "otp_force_enabled"); val == "true" {
			otpForced = true
		}
	}

	// Get user info.
	user, err := s.sqliteStore.GetUserByUsername(ctx, username)
	if err != nil {
		// User not in database, check if OTP is globally forced.
		if otpForced {
			_, _ = io.WriteString(channel, "\r\n⚠ OTP is required but not set up for your account.\r\n")
			_, _ = io.WriteString(channel, "Please contact an administrator to set up OTP.\r\n")
			return false
		}
		return true // No user record and OTP not forced, allow.
	}

	// Determine if OTP is required for this user.
	otpRequired := otpForced || user.OTPEnabled

	if !otpRequired {
		return true // OTP not required for this user.
	}

	// Check if user has OTP set up.
	if user.OTPSecret == "" {
		if otpForced {
			_, _ = io.WriteString(channel, "\r\n⚠ OTP is required but not set up for your account.\r\n")
			_, _ = io.WriteString(channel, "Please set up OTP in the dashboard first.\r\n")
			return false
		}
		return true // User enabled OTP but hasn't set it up yet.
	}

	// Prompt for OTP code.
	_, _ = io.WriteString(channel, "\r\n🔐 OTP Verification Required\r\n")
	_, _ = io.WriteString(channel, "Enter your 6-digit code: ")

	// Read OTP code from user.
	code, err := readLineMasked(channel)
	if err != nil {
		s.logger.Infof("failed to read OTP code: %v", err)
		return false
	}

	code = strings.TrimSpace(code)

	// Validate OTP.
	if !otp.Validate(code, user.OTPSecret) {
		_, _ = io.WriteString(channel, "\r\n❌ Invalid OTP code.\r\n")
		if s.auditor != nil {
			s.auditor.LogLogin(username, "", "otp_failed")
		}
		s.logAudit("login", username, "", "", "OTP verification failed", "failure", nil)
		return false
	}

	_, _ = io.WriteString(channel, "\r\n✓ OTP verified.\r\n\r\n")
	return true
}

func (s *Server) logConnectEvent(username, sourceIP, hostName string) {
	if s.auditor != nil {
		s.auditor.LogConnect(username, sourceIP, hostName, "success")
	}
	s.logAudit("connect", username, sourceIP, hostName, "connect to host", "success", nil)
}

func (s *Server) createDBSession(username, sourceIP, targetHost string) *storage.Session {
	if s.sqliteStore == nil {
		return nil
	}

	dbSession := &storage.Session{
		Username:   username,
		SourceIP:   sourceIP,
		TargetHost: targetHost,
		StartTime:  time.Now(),
	}
	if err := s.sqliteStore.CreateSession(s.ctx, dbSession); err != nil {
		s.logger.Infof("failed to create session record: %v", err)
	}
	return dbSession
}

func (s *Server) startRecording(username, hostName string) *recording.Session {
	if s.recorder == nil {
		return nil
	}

	rec, err := s.recorder.StartSession(username, hostName)
	if err != nil {
		s.logger.Infof("failed to start recording: %v", err)
		return nil
	}
	return rec
}

func (s *Server) cleanupSession(dbSession *storage.Session, rec *recording.Session) {
	if rec != nil {
		_ = rec.Close()
	}

	if dbSession != nil && s.sqliteStore != nil {
		dbSession.EndTime = time.Now()
		if rec != nil {
			dbSession.Recording = rec.FilePath()
		}
		if err := s.sqliteStore.UpdateSession(s.ctx, dbSession); err != nil {
			s.logger.Infof("failed to update session record: %v", err)
		}
	}
}

func (s *Server) executeProxyConnection(
	channel ssh.Channel,
	selectedHost config.HostConfig,
	ptyReq *ptyRequest,
	rec *recording.Session,
) {
	var proxyChannel io.ReadWriteCloser = channel
	if rec != nil {
		proxyChannel = rec.Wrap(channel)
	}

	proxyPtyReq := s.convertPtyRequest(ptyReq)
	proxyOpts := s.loadProxyOptions(selectedHost.Name)

	var err error
	if proxyOpts != nil {
		err = s.proxy.ConnectWithOptions(s.ctx, proxyChannel, selectedHost, proxyPtyReq, proxyOpts)
	} else {
		err = s.proxy.Connect(s.ctx, proxyChannel, selectedHost, proxyPtyReq)
	}

	if err != nil {
		s.logger.Infof("proxy connection failed: %v", err)
		_, _ = io.WriteString(channel, fmt.Sprintf("Connection failed: %v\r\n", err))
	}
}

func (s *Server) convertPtyRequest(ptyReq *ptyRequest) *proxy.PTYRequest {
	if ptyReq == nil {
		return nil
	}
	return &proxy.PTYRequest{
		Term:   ptyReq.Term,
		Width:  ptyReq.Width,
		Height: ptyReq.Height,
	}
}

func (s *Server) loadProxyOptions(hostName string) *proxy.ConnectOptions {
	if s.sqliteStore == nil {
		return nil
	}

	dbHost, err := s.sqliteStore.GetHostByName(s.ctx, hostName)
	if err != nil || dbHost.KeyID == "" {
		return nil
	}

	sshKey, err := s.sqliteStore.GetSSHKey(s.ctx, dbHost.KeyID)
	if err != nil {
		s.logger.Infof("failed to load SSH key %s: %v", dbHost.KeyID, err)
		return nil
	}

	return &proxy.ConnectOptions{
		PrivateKeyData: sshKey.PrivateKey,
	}
}

// isAdmin checks if a user has the admin role via RBAC.
// Falls back to group membership check if no database is available.
func (s *Server) isAdmin(username string, groups []string) bool {
	// If we have a database, check RBAC roles.
	if s.sqliteStore != nil {
		ctx := context.Background()
		user, err := s.sqliteStore.GetUserByUsername(ctx, username)
		if err == nil {
			userRoles, err := s.sqliteStore.GetUserRoles(ctx, user.ID)
			if err == nil {
				for _, role := range userRoles {
					if role.Name == rbac.RoleAdmin {
						return true
					}
				}
			}
		}
	}

	// Fallback: check group membership (for config-file-only mode).
	for _, g := range groups {
		if g == "admin" || g == "admins" {
			return true
		}
	}
	return false
}

// filterHostsByRBAC filters hosts based on RBAC permissions.
// Admin users (admin role) have access to all hosts.
// Other users only have access to hosts they have explicit permission for.
func (s *Server) filterHostsByRBAC(username string, hosts []config.HostConfig) []config.HostConfig {
	if s.sqliteStore == nil {
		return hosts // No RBAC if no database.
	}

	ctx := context.Background()

	// Get user from database.
	user, err := s.sqliteStore.GetUserByUsername(ctx, username)
	if err != nil {
		s.logger.Infof("failed to get user %s: %v", username, err)
		return nil // No access if user not found.
	}

	// Check if user has admin role.
	userRoles, err := s.sqliteStore.GetUserRoles(ctx, user.ID)
	if err != nil {
		s.logger.Infof("failed to get roles for user %s: %v", username, err)
	}

	for _, role := range userRoles {
		if role.Name == rbac.RoleAdmin {
			return hosts // Admin has access to all hosts.
		}
	}

	// Get all hosts from database to map name -> ID.
	dbHosts, err := s.sqliteStore.ListHosts(ctx)
	if err != nil {
		s.logger.Infof("failed to list hosts: %v", err)
		return nil
	}

	hostNameToID := make(map[string]string)
	for _, h := range dbHosts {
		hostNameToID[h.Name] = h.ID
	}

	// Get user's host permissions.
	hostPerms, err := s.sqliteStore.GetHostPermissions(ctx, user.ID)
	if err != nil {
		s.logger.Infof("failed to get host permissions for user %s: %v", username, err)
		return nil
	}

	// Build set of permitted host IDs.
	permittedHostIDs := make(map[string]bool)
	now := time.Now()
	for _, perm := range hostPerms {
		// Check if permission has expired.
		if !perm.ExpiresAt.IsZero() && perm.ExpiresAt.Before(now) {
			continue // Skip expired permissions.
		}
		permittedHostIDs[perm.HostID] = true
	}

	// Filter hosts by permissions.
	var filtered []config.HostConfig
	for _, host := range hosts {
		hostID, ok := hostNameToID[host.Name]
		if !ok {
			continue // Host not in database.
		}
		if permittedHostIDs[hostID] {
			filtered = append(filtered, host)
		}
	}

	return filtered
}

// logAudit logs an audit event to SQLite storage.
func (s *Server) logAudit(eventType, username, sourceIP, targetHost, action, result string, details map[string]interface{}) {
	if s.sqliteStore == nil {
		return
	}

	log := &storage.AuditLog{
		Timestamp:  time.Now(),
		EventType:  eventType,
		Username:   username,
		SourceIP:   sourceIP,
		TargetHost: targetHost,
		Action:     action,
		Result:     result,
		Details:    details,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := s.sqliteStore.CreateAuditLog(ctx, log); err != nil {
		s.logger.Warnf("failed to create audit log: %v", err)
	}
}
