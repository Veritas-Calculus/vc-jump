// Package proxy provides SSH proxy functionality for connecting to target hosts.
package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/Veritas-Calculus/vc-jump/internal/config"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// Proxy handles SSH connections to target hosts.
type Proxy struct{}

// New creates a new Proxy instance.
func New() *Proxy {
	return &Proxy{}
}

// PTYRequest contains PTY request parameters.
type PTYRequest struct {
	Term   string
	Width  uint32
	Height uint32
}

// ConnectOptions contains options for the Connect method.
type ConnectOptions struct {
	PrivateKeyData string // Private key data from database.
	TargetUser     string // User to connect as on target host.
}

// Connect establishes an SSH connection to the target host and proxies I/O.
func (p *Proxy) Connect(ctx context.Context, channel io.ReadWriteCloser, host config.HostConfig, ptyReq *PTYRequest) error {
	return p.ConnectWithOptions(ctx, channel, host, ptyReq, nil)
}

// ConnectWithOptions establishes an SSH connection with additional options.
func (p *Proxy) ConnectWithOptions(ctx context.Context, channel io.ReadWriteCloser, host config.HostConfig, ptyReq *PTYRequest, opts *ConnectOptions) error {
	if host.Addr == "" {
		return errors.New("host address cannot be empty")
	}
	if host.Port <= 0 || host.Port > 65535 {
		return errors.New("invalid host port")
	}

	// Load private key for target host.
	var key ssh.Signer
	var err error

	switch {
	case opts != nil && opts.PrivateKeyData != "":
		// Use provided private key data.
		key, err = ssh.ParsePrivateKey([]byte(opts.PrivateKeyData))
		if err != nil {
			return fmt.Errorf("failed to parse private key: %w", err)
		}
	case host.KeyPath != "":
		// Load from file path.
		key, err = loadPrivateKey(host.KeyPath)
		if err != nil {
			return fmt.Errorf("failed to load private key: %w", err)
		}
	default:
		return errors.New("no SSH key configured for target host")
	}

	// Determine target user.
	targetUser := getUserForHost(host)
	if opts != nil && opts.TargetUser != "" {
		targetUser = opts.TargetUser
	}

	// Create host key callback.
	hostKeyCallback, err := createHostKeyCallback(host.KnownHostsPath, host.InsecureIgnoreHostKey)
	if err != nil {
		return fmt.Errorf("failed to create host key callback: %w", err)
	}

	// Create SSH client config.
	clientConfig := &ssh.ClientConfig{
		User: targetUser,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(key),
		},
		HostKeyCallback: hostKeyCallback,
		Timeout:         30 * time.Second,
	}

	// Connect to target host.
	addr := fmt.Sprintf("%s:%d", host.Addr, host.Port)
	client, err := ssh.Dial("tcp", addr, clientConfig)
	if err != nil {
		return fmt.Errorf("failed to connect to target: %w", err)
	}
	defer func() { _ = client.Close() }()

	// Create session.
	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}
	defer func() { _ = session.Close() }()

	// Request PTY if needed.
	if ptyReq != nil {
		modes := ssh.TerminalModes{
			ssh.ECHO:          1,
			ssh.TTY_OP_ISPEED: 14400,
			ssh.TTY_OP_OSPEED: 14400,
		}

		term := ptyReq.Term
		if term == "" {
			term = "xterm-256color"
		}

		if err := session.RequestPty(term, int(ptyReq.Height), int(ptyReq.Width), modes); err != nil {
			return fmt.Errorf("failed to request pty: %w", err)
		}
	}

	// Connect stdin/stdout/stderr.
	stdin, err := session.StdinPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdin pipe: %w", err)
	}

	stdout, err := session.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	stderr, err := session.StderrPipe()
	if err != nil {
		return fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	// Start shell.
	if err := session.Shell(); err != nil {
		return fmt.Errorf("failed to start shell: %w", err)
	}

	// Proxy I/O.
	done := make(chan error, 3)

	// Channel -> remote stdin.
	go func() {
		_, err := io.Copy(stdin, channel)
		_ = stdin.Close()
		done <- err
	}()

	// Remote stdout -> channel.
	go func() {
		_, err := io.Copy(channel, stdout)
		done <- err
	}()

	// Remote stderr -> channel.
	go func() {
		_, err := io.Copy(channel, stderr)
		done <- err
	}()

	// Wait for session to end or context cancellation.
	select {
	case <-ctx.Done():
		_ = session.Close()
		return ctx.Err()
	case err := <-done:
		// Wait for session to finish.
		_ = session.Wait()
		if err != nil && !errors.Is(err, io.EOF) && !isClosedError(err) {
			return err
		}
		return nil
	}
}

func loadPrivateKey(keyPath string) (ssh.Signer, error) {
	if keyPath == "" {
		// Try default SSH key locations.
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return nil, errors.New("key path not specified and cannot find home directory")
		}
		keyPath = homeDir + "/.ssh/id_rsa"
	}

	// Validate keyPath to prevent directory traversal.
	cleanPath := filepath.Clean(keyPath)
	if !filepath.IsAbs(cleanPath) {
		return nil, errors.New("key path must be an absolute path")
	}

	keyData, err := os.ReadFile(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	signer, err := ssh.ParsePrivateKey(keyData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return signer, nil
}

// createHostKeyCallback creates a host key callback function.
// If insecureIgnore is true, it returns a callback that accepts any host key (use only for trusted networks).
// If knownHostsPath is empty, it uses the default ~/.ssh/known_hosts file.
func createHostKeyCallback(knownHostsPath string, insecureIgnore bool) (ssh.HostKeyCallback, error) {
	// If insecure mode is explicitly enabled, skip host key verification.
	// This should only be used for trusted internal networks.
	if insecureIgnore {
		//nolint:gosec // InsecureIgnoreHostKey is intentionally allowed when explicitly configured.
		return ssh.InsecureIgnoreHostKey(), nil
	}

	if knownHostsPath == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("cannot find home directory: %w", err)
		}
		knownHostsPath = filepath.Join(homeDir, ".ssh", "known_hosts")
	}

	// Validate and clean the path.
	cleanPath := filepath.Clean(knownHostsPath)
	if !filepath.IsAbs(cleanPath) {
		return nil, errors.New("known_hosts path must be an absolute path")
	}

	// Check if file exists.
	if _, err := os.Stat(cleanPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("known_hosts file does not exist: %s", cleanPath)
	}

	callback, err := knownhosts.New(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse known_hosts file: %w", err)
	}

	return callback, nil
}

func getUserForHost(host config.HostConfig) string {
	if len(host.Users) > 0 {
		return host.Users[0]
	}
	return "root"
}

func isClosedError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, net.ErrClosed) {
		return true
	}
	// Check for common closed connection errors.
	errStr := err.Error()
	return errStr == "use of closed network connection" ||
		errStr == "connection reset by peer"
}
