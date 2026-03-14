package server

import (
	"bytes"
	"errors"
	"testing"
)

func TestReadLine_BasicInput(t *testing.T) {
	input := bytes.NewBufferString("hello\r")
	got, err := readLine(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "hello" {
		t.Errorf("got %q, want %q", got, "hello")
	}
}

func TestReadLine_NewlineTerminator(t *testing.T) {
	input := bytes.NewBufferString("test\n")
	got, err := readLine(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "test" {
		t.Errorf("got %q, want %q", got, "test")
	}
}

func TestReadLine_Backspace(t *testing.T) {
	// Type "ab", backspace, "c", enter → "ac"
	input := bytes.NewBuffer([]byte{'a', 'b', 127, 'c', '\r'})
	got, err := readLine(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "ac" {
		t.Errorf("got %q, want %q", got, "ac")
	}
}

func TestReadLine_BackspaceOnEmpty(t *testing.T) {
	// Backspace on empty line should not panic.
	input := bytes.NewBuffer([]byte{127, 127, 'a', '\r'})
	got, err := readLine(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "a" {
		t.Errorf("got %q, want %q", got, "a")
	}
}

func TestReadLine_CtrlC(t *testing.T) {
	input := bytes.NewBuffer([]byte{'a', 3}) // Ctrl+C
	_, err := readLine(input)
	if err == nil {
		t.Fatal("expected error for Ctrl+C, got nil")
	}
	if !errors.Is(err, errors.New("interrupted")) && err.Error() != "interrupted" {
		t.Errorf("expected 'interrupted' error, got: %v", err)
	}
}

func TestReadLine_IgnoresControlChars(t *testing.T) {
	input := bytes.NewBuffer([]byte{1, 2, 'h', 'i', '\r'})
	got, err := readLine(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "hi" {
		t.Errorf("got %q, want %q", got, "hi")
	}
}

func TestReadLine_EmptyInput(t *testing.T) {
	input := bytes.NewBufferString("\r")
	got, err := readLine(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "" {
		t.Errorf("got %q, want empty string", got)
	}
}

func TestParsePtyRequest_Valid(t *testing.T) {
	// Build a valid PTY request payload.
	// Format: 4 bytes term length prefix (big-endian uint32), term string, 8 bytes width+height.
	term := "xterm-256color"
	termLen := len(term)
	payload := make([]byte, 0, 4+termLen+8)
	// Term string length as big-endian uint32.
	payload = append(payload, 0, 0, 0, byte(termLen))
	payload = append(payload, []byte(term)...)
	// Width = 80 (big-endian uint32).
	payload = append(payload, 0, 0, 0, 80)
	// Height = 24 (big-endian uint32).
	payload = append(payload, 0, 0, 0, 24)

	result := parsePtyRequest(payload)
	if result == nil {
		t.Fatal("parsePtyRequest returned nil for valid payload")
	}
	if result.Term != term {
		t.Errorf("Term = %q, want %q", result.Term, term)
	}
	if result.Width != 80 {
		t.Errorf("Width = %d, want 80", result.Width)
	}
	if result.Height != 24 {
		t.Errorf("Height = %d, want 24", result.Height)
	}
}

func TestParsePtyRequest_TooShort(t *testing.T) {
	result := parsePtyRequest([]byte{0, 0})
	if result != nil {
		t.Error("expected nil for short payload")
	}
}

func TestParsePtyRequest_Nil(t *testing.T) {
	result := parsePtyRequest(nil)
	if result != nil {
		t.Error("expected nil for nil payload")
	}
}

func TestJoinGroups(t *testing.T) {
	tests := []struct {
		input []string
		want  string
	}{
		{nil, ""},
		{[]string{}, ""},
		{[]string{"admin"}, "admin"},
		{[]string{"admin", "users"}, "admin,users"},
		{[]string{"a", "b", "c"}, "a,b,c"},
	}

	for _, tt := range tests {
		got := joinGroups(tt.input)
		if got != tt.want {
			t.Errorf("joinGroups(%v) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestSplitGroups(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		{"", nil},
		{"admin", []string{"admin"}},
		{"admin,users", []string{"admin", "users"}},
		{"a,b,c", []string{"a", "b", "c"}},
	}

	for _, tt := range tests {
		got := splitGroups(tt.input)
		if len(got) != len(tt.want) {
			t.Errorf("splitGroups(%q) = %v, want %v", tt.input, got, tt.want)
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("splitGroups(%q)[%d] = %q, want %q", tt.input, i, got[i], tt.want[i])
			}
		}
	}
}

func TestJoinSplitRoundtrip(t *testing.T) {
	groups := []string{"admin", "users", "devops"}
	joined := joinGroups(groups)
	split := splitGroups(joined)

	if len(split) != len(groups) {
		t.Fatalf("len mismatch: got %d, want %d", len(split), len(groups))
	}
	for i := range groups {
		if split[i] != groups[i] {
			t.Errorf("roundtrip[%d] = %q, want %q", i, split[i], groups[i])
		}
	}
}
