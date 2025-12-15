// Package selector provides host selection functionality for vc-jump.
package selector

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"

	"github.com/Veritas-Calculus/vc-jump/internal/config"
	"github.com/Veritas-Calculus/vc-jump/internal/storage"
)

// Selector handles host selection for users.
type Selector struct {
	hosts []config.HostConfig
	store *storage.SQLiteStore
}

// New creates a new Selector with the given host configurations.
func New(hosts []config.HostConfig) *Selector {
	return &Selector{
		hosts: hosts,
	}
}

// NewWithStore creates a new Selector that uses database storage.
func NewWithStore(store *storage.SQLiteStore) *Selector {
	return &Selector{
		store: store,
	}
}

// GetAccessibleHosts returns a list of hosts that the user can access.
// If allowedHosts is non-empty, only hosts in that list are returned.
func (s *Selector) GetAccessibleHosts(username string, groups []string, allowedHosts []string) []config.HostConfig {
	hosts := s.getAllHosts()
	if len(hosts) == 0 {
		return nil
	}

	var accessible []config.HostConfig
	for _, host := range hosts {
		if s.canAccess(host, username, groups, allowedHosts) {
			accessible = append(accessible, host)
		}
	}
	return accessible
}

func (s *Selector) getAllHosts() []config.HostConfig {
	// Try database first.
	if s.store != nil {
		ctx := context.Background()
		dbHosts, err := s.store.ListHosts(ctx)
		if err == nil && len(dbHosts) > 0 {
			var hosts []config.HostConfig
			for _, h := range dbHosts {
				hosts = append(hosts, config.HostConfig{
					Name:    h.Name,
					Addr:    h.Addr,
					Port:    h.Port,
					Users:   h.Users,
					Groups:  h.Groups,
					KeyPath: h.KeyPath,
				})
			}
			return hosts
		}
	}
	// Fallback to config file hosts.
	return s.hosts
}

func (s *Selector) canAccess(host config.HostConfig, username string, groups []string, allowedHosts []string) bool {
	// If user has allowed_hosts restriction, check it first.
	if len(allowedHosts) > 0 {
		allowed := false
		for _, h := range allowedHosts {
			if h == host.Name || h == "*" {
				allowed = true
				break
			}
		}
		if !allowed {
			return false
		}
	}

	// If no users or groups are specified, allow access to all.
	if len(host.Users) == 0 && len(host.Groups) == 0 {
		return true
	}

	// Check if user is in the allowed users list.
	for _, u := range host.Users {
		if u == username {
			return true
		}
	}

	// Check if user is in any allowed group.
	for _, allowedGroup := range host.Groups {
		for _, userGroup := range groups {
			if allowedGroup == userGroup {
				return true
			}
		}
	}

	return false
}

// SelectHost displays a menu and returns the selected host.
func (s *Selector) SelectHost(rw io.ReadWriter, hosts []config.HostConfig) (config.HostConfig, error) {
	return s.SelectHostWithAdmin(rw, hosts, false)
}

// SelectHostWithAdmin displays a menu with optional admin option.
// Returns a special "admin" host if admin option is selected.
func (s *Selector) SelectHostWithAdmin(rw io.ReadWriter, hosts []config.HostConfig, isAdmin bool) (config.HostConfig, error) {
	if len(hosts) == 0 && !isAdmin {
		return config.HostConfig{}, errors.New("no hosts available")
	}

	// Display menu.
	_, _ = io.WriteString(rw, "\r\n=== VC Jump - Host Selection ===\r\n\r\n")
	for i, host := range hosts {
		_, _ = fmt.Fprintf(rw, "  [%d] %s (%s:%d)\r\n", i+1, host.Name, host.Addr, host.Port)
	}
	if isAdmin {
		_, _ = io.WriteString(rw, "\r\n  [A] Admin Console\r\n")
	}
	_, _ = io.WriteString(rw, "\r\nSelect host (number): ")

	// Read selection.
	selection, err := readLine(rw)
	if err != nil {
		return config.HostConfig{}, fmt.Errorf("failed to read selection: %w", err)
	}

	// Check for admin selection.
	if isAdmin && (selection == "a" || selection == "A") {
		return config.HostConfig{Name: "__admin__"}, nil
	}

	num, err := strconv.Atoi(selection)
	if err != nil {
		return config.HostConfig{}, errors.New("invalid selection: not a number")
	}

	if num < 1 || num > len(hosts) {
		return config.HostConfig{}, fmt.Errorf("invalid selection: must be between 1 and %d", len(hosts))
	}

	return hosts[num-1], nil
}

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
		default:
			if b >= 32 && b < 127 {
				line = append(line, b)
			}
		}
	}
}
