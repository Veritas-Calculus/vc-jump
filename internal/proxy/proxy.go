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
	if err := validateHost(host); err != nil {
		return err
	}

	// Load private key for target host.
	key, err := p.loadSSHKey(host, opts)
	if err != nil {
		return err
	}

	// Determine target user.
	targetUser := p.getTargetUser(host, opts)

	// Create SSH client config.
	clientConfig, err := p.createClientConfig(host, targetUser, key)
	if err != nil {
		return err
	}

	// Connect to target host.
	addr := fmt.Sprintf("%s:%d", host.Addr, host.Port)
	client, err := ssh.Dial("tcp", addr, clientConfig)
	if err != nil {
		return fmt.Errorf("failed to connect to target: %w", err)
	}
	defer func() { _ = client.Close() }()

	// Create and run session.
	return p.runSession(ctx, client, channel, ptyReq)
}

func validateHost(host config.HostConfig) error {
	if host.Addr == "" {
		return errors.New("host address cannot be empty")
	}
	if host.Port <= 0 || host.Port > 65535 {
		return errors.New("invalid host port")
	}
	return nil
}

func (p *Proxy) loadSSHKey(host config.HostConfig, opts *ConnectOptions) (ssh.Signer, error) {
	switch {
	case opts != nil && opts.PrivateKeyData != "":
		key, err := ssh.ParsePrivateKey([]byte(opts.PrivateKeyData))
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
		return key, nil
	case host.KeyPath != "":
		key, err := loadPrivateKey(host.KeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load private key: %w", err)
		}
		return key, nil
	default:
		return nil, errors.New("no SSH key configured for target host")
	}
}

func (p *Proxy) getTargetUser(host config.HostConfig, opts *ConnectOptions) string {
	if opts != nil && opts.TargetUser != "" {
		return opts.TargetUser
	}
	return getUserForHost(host)
}

func (p *Proxy) createClientConfig(host config.HostConfig, user string, key ssh.Signer) (*ssh.ClientConfig, error) {
	hostKeyCallback, err := createHostKeyCallback(host.KnownHostsPath, host.InsecureIgnoreHostKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create host key callback: %w", err)
	}

	return &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(key),
		},
		HostKeyCallback: hostKeyCallback,
		Timeout:         30 * time.Second,
	}, nil
}

func (p *Proxy) runSession(ctx context.Context, client *ssh.Client, channel io.ReadWriteCloser, ptyReq *PTYRequest) error {
	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}
	defer func() { _ = session.Close() }()

	if err := p.setupPTY(session, ptyReq); err != nil {
		return err
	}

	return p.proxyIO(ctx, session, channel)
}

func (p *Proxy) setupPTY(session *ssh.Session, ptyReq *PTYRequest) error {
	if ptyReq == nil {
		return nil
	}

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
	return nil
}

func (p *Proxy) proxyIO(ctx context.Context, session *ssh.Session, channel io.ReadWriteCloser) error {
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

	if err := session.Shell(); err != nil {
		return fmt.Errorf("failed to start shell: %w", err)
	}

	done := make(chan error, 3)

	go func() {
		_, err := io.Copy(stdin, channel)
		_ = stdin.Close()
		done <- err
	}()

	go func() {
		_, err := io.Copy(channel, stdout)
		done <- err
	}()

	go func() {
		_, err := io.Copy(channel, stderr)
		done <- err
	}()

	select {
	case <-ctx.Done():
		_ = session.Close()
		return ctx.Err()
	case err := <-done:
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
	// This should only be used for trusted internal networks where the admin
	// has explicitly configured insecure_ignore_host_key: true in the host config.
	// This is a deliberate security trade-off for environments where known_hosts
	// management is impractical (e.g., dynamic cloud environments).
	if insecureIgnore {
		return ssh.InsecureIgnoreHostKey(), nil // #nosec G106 -- intentionally allowed when explicitly configured by admin
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
	if host.User != "" {
		return host.User
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
