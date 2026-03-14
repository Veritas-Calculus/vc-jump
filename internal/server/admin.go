package server

import (
	"fmt"
	"io"
	"strconv"

	"github.com/Veritas-Calculus/vc-jump/internal/storage"
	"golang.org/x/crypto/ssh"
)

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
