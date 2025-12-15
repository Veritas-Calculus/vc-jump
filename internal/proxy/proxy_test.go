package proxy

import (
	"testing"

	"github.com/Veritas-Calculus/vc-jump/internal/config"
)

func TestNewProxy(t *testing.T) {
	p := New()
	if p == nil {
		t.Fatal("proxy is nil")
	}
}

func TestGetUserForHostWithUsers(t *testing.T) {
	host := config.HostConfig{
		Name:  "test",
		Addr:  "10.0.0.1",
		Port:  22,
		Users: []string{"admin", "root"},
	}

	user := getUserForHost(host)
	if user != "admin" {
		t.Errorf("expected admin, got %s", user)
	}
}

func TestGetUserForHostNoUsers(t *testing.T) {
	host := config.HostConfig{
		Name: "test",
		Addr: "10.0.0.1",
		Port: 22,
	}

	user := getUserForHost(host)
	if user != "root" {
		t.Errorf("expected root (default), got %s", user)
	}
}

func TestIsClosedErrorNil(t *testing.T) {
	if isClosedError(nil) {
		t.Error("expected false for nil error")
	}
}

func TestPTYRequestStruct(t *testing.T) {
	pty := PTYRequest{
		Term:   "xterm",
		Width:  80,
		Height: 24,
	}

	if pty.Term != "xterm" {
		t.Errorf("expected xterm, got %s", pty.Term)
	}
	if pty.Width != 80 {
		t.Errorf("expected width 80, got %d", pty.Width)
	}
	if pty.Height != 24 {
		t.Errorf("expected height 24, got %d", pty.Height)
	}
}
