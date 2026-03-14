package server

import (
	"bufio"
	"errors"
	"io"
	"strings"

	"golang.org/x/crypto/ssh"
)

// ptyRequest holds parsed PTY request parameters.
type ptyRequest struct {
	Term   string
	Width  uint32
	Height uint32
}

// parsePtyRequest parses a PTY request payload from SSH.
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

// readLine reads a line of text input from an SSH channel.
// It handles Enter, Backspace, and Ctrl+C, echoing typed characters.
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

// readLineMasked reads a line from an SSH channel, echoing asterisks (for OTP input).
func readLineMasked(channel ssh.Channel) (string, error) {
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
		// Echo asterisk for masked input.
		_, _ = channel.Write([]byte("*"))
	}

	return line.String(), nil
}

// joinGroups joins a string slice into a comma-separated string.
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

// splitGroups splits a comma-separated string into a string slice.
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
