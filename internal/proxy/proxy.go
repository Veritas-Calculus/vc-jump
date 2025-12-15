// Package proxy provides SSH proxy functionality for connecting to target hosts.
package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/Veritas-Calculus/vc-jump/internal/config"
	"golang.org/x/crypto/ssh"
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

	if opts != nil && opts.PrivateKeyData != "" {
		// Use provided private key data.
		key, err = ssh.ParsePrivateKey([]byte(opts.PrivateKeyData))
		if err != nil {
			return fmt.Errorf("failed to parse private key: %w", err)
		}
	} else if host.KeyPath != "" {
		// Load from file path.
		key, err = loadPrivateKey(host.KeyPath)
		if err != nil {
			return fmt.Errorf("failed to load private key: %w", err)
		}
	} else {
		return errors.New("no SSH key configured for target host")
	}

	// Determine target user.
	targetUser := getUserForHost(host)
	if opts != nil && opts.TargetUser != "" {
		targetUser = opts.TargetUser
	}

	// Create SSH client config.
	clientConfig := &ssh.ClientConfig{
		User: targetUser,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(key),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // TODO: Implement proper host key verification.
		Timeout:         30 * time.Second,
	}

	// Connect to target host.
	addr := fmt.Sprintf("%s:%d", host.Addr, host.Port)
	client, err := ssh.Dial("tcp", addr, clientConfig)
	if err != nil {
		return fmt.Errorf("failed to connect to target: %w", err)
	}
	defer client.Close()

	// Create session.
	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

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
		stdin.Close()
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
		session.Close()
		return ctx.Err()
	case err := <-done:
		// Wait for session to finish.
		session.Wait()
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

	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	signer, err := ssh.ParsePrivateKey(keyData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return signer, nil
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
