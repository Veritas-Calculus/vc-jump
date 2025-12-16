// Package server provides the SSH server implementation for vc-jump.
package server

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
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
	store       *storage.FileStore
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

	// Initialize storage.
	store, err := storage.NewFileStore(cfg.Storage)
	if err != nil {
		s.logger.Warnf("failed to create storage: %v", err)
	} else {
		s.store = store
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
	if s.store != nil {
		_ = s.store.Close()
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
	code, err := s.readLine(channel)
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
		return false
	}

	_, _ = io.WriteString(channel, "\r\n✓ OTP verified.\r\n\r\n")
	return true
}

// readLine reads a line of input from the channel.
func (s *Server) readLine(channel ssh.Channel) (string, error) {
	reader := bufio.NewReader(channel)
	var line strings.Builder

	for {
		b, err := reader.ReadByte()
		if err != nil {
			return "", err
		}

		// Handle Enter key.
		if b == '\r' || b == '\n' {
			break
		}

		// Handle backspace.
		if b == 127 || b == 8 {
			if line.Len() > 0 {
				str := line.String()
				line.Reset()
				line.WriteString(str[:len(str)-1])
				_, _ = channel.Write([]byte("\b \b"))
			}
			continue
		}

		// Ignore control characters.
		if b < 32 {
			continue
		}

		line.WriteByte(b)
		// Echo asterisk for OTP input.
		_, _ = channel.Write([]byte("*"))
	}

	return line.String(), nil
}

func (s *Server) logConnectEvent(username, sourceIP, hostName string) {
	if s.auditor != nil {
		s.auditor.LogConnect(username, sourceIP, hostName, "success")
	}
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

type ptyRequest struct {
	Term   string
	Width  uint32
	Height uint32
}

func parsePtyRequest(payload []byte) *ptyRequest {
	if len(payload) < 4 {
		return nil
	}

	termLen := int(payload[3])
	if len(payload) < 4+termLen+8 {
		return nil
	}

	term := string(payload[4 : 4+termLen])
	rest := payload[4+termLen:]

	if len(rest) < 8 {
		return nil
	}

	width := uint32(rest[0])<<24 | uint32(rest[1])<<16 | uint32(rest[2])<<8 | uint32(rest[3])
	height := uint32(rest[4])<<24 | uint32(rest[5])<<16 | uint32(rest[6])<<8 | uint32(rest[7])

	return &ptyRequest{
		Term:   term,
		Width:  width,
		Height: height,
	}
}

func joinGroups(groups []string) string {
	if len(groups) == 0 {
		return ""
	}
	result := groups[0]
	for i := 1; i < len(groups); i++ {
		result += "," + groups[i]
	}
	return result
}

func splitGroups(s string) []string {
	if s == "" {
		return nil
	}
	var groups []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			groups = append(groups, s[start:i])
			start = i + 1
		}
	}
	groups = append(groups, s[start:])
	return groups
}

// isAdmin checks if user is in the admin group.
func (s *Server) isAdmin(username string, groups []string) bool {
	if username == "admin" {
		return true
	}
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

// runAdminConsole provides an interactive admin interface via SSH.
func (s *Server) runAdminConsole(channel ssh.Channel, username string) {
	_, _ = io.WriteString(channel, "\r\n=== VC Jump Admin Console ===\r\n")
	_, _ = io.WriteString(channel, fmt.Sprintf("Logged in as: %s\r\n\r\n", username))

	for {
		_, _ = io.WriteString(channel, "\r\nAdmin Menu:\r\n")
		_, _ = io.WriteString(channel, "  [1] List Hosts\r\n")
		_, _ = io.WriteString(channel, "  [2] Add Host\r\n")
		_, _ = io.WriteString(channel, "  [3] Delete Host\r\n")
		_, _ = io.WriteString(channel, "  [4] List Users\r\n")
		_, _ = io.WriteString(channel, "  [5] List SSH Keys\r\n")
		_, _ = io.WriteString(channel, "  [Q] Exit\r\n")
		_, _ = io.WriteString(channel, "\r\nSelect option: ")

		choice, err := readLine(channel)
		if err != nil {
			return
		}

		switch choice {
		case "1":
			s.adminListHosts(channel)
		case "2":
			s.adminAddHost(channel)
		case "3":
			s.adminDeleteHost(channel)
		case "4":
			s.adminListUsers(channel)
		case "5":
			s.adminListKeys(channel)
		case "q", "Q":
			_, _ = io.WriteString(channel, "\r\nGoodbye!\r\n")
			return
		default:
			_, _ = io.WriteString(channel, "\r\nInvalid option.\r\n")
		}
	}
}

func (s *Server) adminListHosts(channel ssh.Channel) {
	if s.sqliteStore == nil {
		_, _ = io.WriteString(channel, "\r\nDatabase not available.\r\n")
		return
	}

	hosts, err := s.sqliteStore.ListHosts(s.ctx)
	if err != nil {
		_, _ = io.WriteString(channel, fmt.Sprintf("\r\nError: %v\r\n", err))
		return
	}

	_, _ = io.WriteString(channel, "\r\n--- Hosts ---\r\n")
	if len(hosts) == 0 {
		_, _ = io.WriteString(channel, "No hosts configured.\r\n")
		return
	}

	for i, h := range hosts {
		keyInfo := ""
		if h.KeyID != "" {
			key, err := s.sqliteStore.GetSSHKey(s.ctx, h.KeyID)
			if err == nil {
				keyInfo = fmt.Sprintf(" [Key: %s]", key.Name)
			}
		}
		_, _ = io.WriteString(channel, fmt.Sprintf("  %d. %s - %s@%s:%d%s\r\n", i+1, h.Name, h.User, h.Addr, h.Port, keyInfo))
	}
}

func (s *Server) adminAddHost(channel ssh.Channel) {
	if s.sqliteStore == nil {
		_, _ = io.WriteString(channel, "\r\nDatabase not available.\r\n")
		return
	}

	_, _ = io.WriteString(channel, "\r\n--- Add Host ---\r\n")

	name, addr, ok := s.promptHostBasicInfo(channel)
	if !ok {
		return
	}

	port := s.promptPort(channel)
	user := s.promptUser(channel)
	keyID := s.promptSSHKey(channel)

	host := &storage.Host{
		Name:  name,
		Addr:  addr,
		Port:  port,
		User:  user,
		KeyID: keyID,
	}

	if err := s.sqliteStore.CreateHost(s.ctx, host); err != nil {
		_, _ = io.WriteString(channel, fmt.Sprintf("\r\nError: %v\r\n", err))
		return
	}

	_, _ = io.WriteString(channel, fmt.Sprintf("\r\nHost '%s' created successfully!\r\n", name))
}

func (s *Server) promptHostBasicInfo(channel ssh.Channel) (name, addr string, ok bool) {
	_, _ = io.WriteString(channel, "Name: ")
	name, err := readLine(channel)
	if err != nil || name == "" {
		_, _ = io.WriteString(channel, "\r\nCancelled.\r\n")
		return "", "", false
	}

	_, _ = io.WriteString(channel, "Address: ")
	addr, err = readLine(channel)
	if err != nil || addr == "" {
		_, _ = io.WriteString(channel, "\r\nCancelled.\r\n")
		return "", "", false
	}

	return name, addr, true
}

func (s *Server) promptPort(channel ssh.Channel) int {
	_, _ = io.WriteString(channel, "Port [22]: ")
	portStr, _ := readLine(channel)
	if portStr == "" {
		return 22
	}
	if p, err := strconv.Atoi(portStr); err == nil && p > 0 {
		return p
	}
	return 22
}

func (s *Server) promptUser(channel ssh.Channel) string {
	_, _ = io.WriteString(channel, "SSH User [root]: ")
	user, _ := readLine(channel)
	if user == "" {
		return "root"
	}
	return user
}

func (s *Server) promptSSHKey(channel ssh.Channel) string {
	keys, _ := s.sqliteStore.ListSSHKeys(s.ctx)
	if len(keys) == 0 {
		return ""
	}

	_, _ = io.WriteString(channel, "\r\nAvailable SSH Keys:\r\n")
	for i, k := range keys {
		_, _ = io.WriteString(channel, fmt.Sprintf("  [%d] %s (%s)\r\n", i+1, k.Name, k.KeyType))
	}
	_, _ = io.WriteString(channel, "  [0] None\r\n")
	_, _ = io.WriteString(channel, "\r\nSelect key [0]: ")

	keyChoice, _ := readLine(channel)
	if n, err := strconv.Atoi(keyChoice); err == nil && n >= 1 && n <= len(keys) {
		return keys[n-1].ID
	}
	return ""
}

func (s *Server) adminDeleteHost(channel ssh.Channel) {
	if s.sqliteStore == nil {
		_, _ = io.WriteString(channel, "\r\nDatabase not available.\r\n")
		return
	}

	hosts, err := s.sqliteStore.ListHosts(s.ctx)
	if err != nil {
		_, _ = io.WriteString(channel, fmt.Sprintf("\r\nError: %v\r\n", err))
		return
	}

	if len(hosts) == 0 {
		_, _ = io.WriteString(channel, "\r\nNo hosts to delete.\r\n")
		return
	}

	_, _ = io.WriteString(channel, "\r\n--- Delete Host ---\r\n")
	for i, h := range hosts {
		_, _ = io.WriteString(channel, fmt.Sprintf("  [%d] %s (%s:%d)\r\n", i+1, h.Name, h.Addr, h.Port))
	}
	_, _ = io.WriteString(channel, "\r\nSelect host to delete (0 to cancel): ")

	choice, err := readLine(channel)
	if err != nil {
		return
	}

	n, err := strconv.Atoi(choice)
	if err != nil || n < 1 || n > len(hosts) {
		_, _ = io.WriteString(channel, "\r\nCancelled.\r\n")
		return
	}

	hostToDelete := hosts[n-1]
	_, _ = io.WriteString(channel, fmt.Sprintf("\r\nAre you sure you want to delete '%s'? (y/N): ", hostToDelete.Name))
	confirm, _ := readLine(channel)
	if confirm != "y" && confirm != "Y" {
		_, _ = io.WriteString(channel, "\r\nCancelled.\r\n")
		return
	}

	if err := s.sqliteStore.DeleteHost(s.ctx, hostToDelete.ID); err != nil {
		_, _ = io.WriteString(channel, fmt.Sprintf("\r\nError: %v\r\n", err))
		return
	}

	_, _ = io.WriteString(channel, fmt.Sprintf("\r\nHost '%s' deleted successfully!\r\n", hostToDelete.Name))
}

func (s *Server) adminListUsers(channel ssh.Channel) {
	if s.sqliteStore == nil {
		_, _ = io.WriteString(channel, "\r\nDatabase not available.\r\n")
		return
	}

	users, err := s.sqliteStore.ListUsers(s.ctx)
	if err != nil {
		_, _ = io.WriteString(channel, fmt.Sprintf("\r\nError: %v\r\n", err))
		return
	}

	_, _ = io.WriteString(channel, "\r\n--- Users ---\r\n")
	if len(users) == 0 {
		_, _ = io.WriteString(channel, "No users configured.\r\n")
		return
	}

	for i, u := range users {
		status := "inactive"
		if u.IsActive {
			status = "active"
		}
		source := string(u.Source)
		if source == "" {
			source = "local"
		}
		_, _ = io.WriteString(channel, fmt.Sprintf("  %d. %s [%s] (%s)\r\n", i+1, u.Username, source, status))
	}
}

func (s *Server) adminListKeys(channel ssh.Channel) {
	if s.sqliteStore == nil {
		_, _ = io.WriteString(channel, "\r\nDatabase not available.\r\n")
		return
	}

	keys, err := s.sqliteStore.ListSSHKeys(s.ctx)
	if err != nil {
		_, _ = io.WriteString(channel, fmt.Sprintf("\r\nError: %v\r\n", err))
		return
	}

	_, _ = io.WriteString(channel, "\r\n--- SSH Keys ---\r\n")
	if len(keys) == 0 {
		_, _ = io.WriteString(channel, "No SSH keys configured.\r\n")
		return
	}

	for i, k := range keys {
		_, _ = io.WriteString(channel, fmt.Sprintf("  %d. %s (%s) - %s\r\n", i+1, k.Name, k.KeyType, k.Fingerprint))
	}
}

// readLine reads a line from the SSH channel.
func readLine(r io.Reader) (string, error) {
	var line []byte
	buf := make([]byte, 1)

	for {
		n, err := r.Read(buf)
		if err != nil {
			return "", err
		}
		if n == 0 {
			continue
		}

		b := buf[0]
		switch b {
		case '\r', '\n':
			return string(line), nil
		case 127, 8: // Backspace.
			if len(line) > 0 {
				line = line[:len(line)-1]
			}
		case 3: // Ctrl+C
			return "", errors.New("interrupted")
		default:
			if b >= 32 && b < 127 {
				line = append(line, b)
			}
		}
	}
}
