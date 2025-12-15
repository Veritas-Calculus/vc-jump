package selector

import (
	"bytes"
	"testing"

	"github.com/Veritas-Calculus/vc-jump/internal/config"
)

func TestNewSelector(t *testing.T) {
	hosts := []config.HostConfig{
		{Name: "host1", Addr: "10.0.0.1", Port: 22},
	}
	s := New(hosts)
	if s == nil {
		t.Fatal("selector is nil")
	}
}

func TestGetAccessibleHostsNoHosts(t *testing.T) {
	s := New(nil)
	hosts := s.GetAccessibleHosts("user", []string{"group"}, nil)
	if len(hosts) != 0 {
		t.Errorf("expected 0 hosts, got %d", len(hosts))
	}
}

func TestGetAccessibleHostsAllAccessible(t *testing.T) {
	hosts := []config.HostConfig{
		{Name: "host1", Addr: "10.0.0.1", Port: 22},
		{Name: "host2", Addr: "10.0.0.2", Port: 22},
	}
	s := New(hosts)

	accessible := s.GetAccessibleHosts("anyuser", []string{}, nil)
	if len(accessible) != 2 {
		t.Errorf("expected 2 accessible hosts, got %d", len(accessible))
	}
}

func TestGetAccessibleHostsByUser(t *testing.T) {
	hosts := []config.HostConfig{
		{Name: "host1", Addr: "10.0.0.1", Port: 22, Users: []string{"alice"}},
		{Name: "host2", Addr: "10.0.0.2", Port: 22, Users: []string{"bob"}},
	}
	s := New(hosts)

	aliceHosts := s.GetAccessibleHosts("alice", nil, nil)
	if len(aliceHosts) != 1 {
		t.Errorf("expected 1 host for alice, got %d", len(aliceHosts))
	}
	if aliceHosts[0].Name != "host1" {
		t.Errorf("expected host1 for alice, got %s", aliceHosts[0].Name)
	}

	bobHosts := s.GetAccessibleHosts("bob", nil, nil)
	if len(bobHosts) != 1 {
		t.Errorf("expected 1 host for bob, got %d", len(bobHosts))
	}
	if bobHosts[0].Name != "host2" {
		t.Errorf("expected host2 for bob, got %s", bobHosts[0].Name)
	}
}

func TestGetAccessibleHostsByGroup(t *testing.T) {
	hosts := []config.HostConfig{
		{Name: "dev-host", Addr: "10.0.0.1", Port: 22, Groups: []string{"developers"}},
		{Name: "ops-host", Addr: "10.0.0.2", Port: 22, Groups: []string{"ops"}},
	}
	s := New(hosts)

	devHosts := s.GetAccessibleHosts("anyuser", []string{"developers"}, nil)
	if len(devHosts) != 1 {
		t.Errorf("expected 1 host for developers, got %d", len(devHosts))
	}
	if devHosts[0].Name != "dev-host" {
		t.Errorf("expected dev-host, got %s", devHosts[0].Name)
	}
}

func TestGetAccessibleHostsMultipleGroups(t *testing.T) {
	hosts := []config.HostConfig{
		{Name: "host1", Addr: "10.0.0.1", Port: 22, Groups: []string{"dev"}},
		{Name: "host2", Addr: "10.0.0.2", Port: 22, Groups: []string{"ops"}},
		{Name: "host3", Addr: "10.0.0.3", Port: 22, Groups: []string{"admin"}},
	}
	s := New(hosts)

	multiGroupHosts := s.GetAccessibleHosts("user", []string{"dev", "ops"}, nil)
	if len(multiGroupHosts) != 2 {
		t.Errorf("expected 2 hosts, got %d", len(multiGroupHosts))
	}
}

func TestGetAccessibleHostsWithAllowedHosts(t *testing.T) {
	hosts := []config.HostConfig{
		{Name: "host1", Addr: "10.0.0.1", Port: 22},
		{Name: "host2", Addr: "10.0.0.2", Port: 22},
		{Name: "host3", Addr: "10.0.0.3", Port: 22},
	}
	s := New(hosts)

	// User allowed only host1 and host2.
	allowedHosts := []string{"host1", "host2"}
	accessible := s.GetAccessibleHosts("user", nil, allowedHosts)
	if len(accessible) != 2 {
		t.Errorf("expected 2 accessible hosts, got %d", len(accessible))
	}

	// Verify host3 is not included.
	for _, h := range accessible {
		if h.Name == "host3" {
			t.Error("host3 should not be accessible")
		}
	}
}

func TestGetAccessibleHostsWildcard(t *testing.T) {
	hosts := []config.HostConfig{
		{Name: "host1", Addr: "10.0.0.1", Port: 22},
		{Name: "host2", Addr: "10.0.0.2", Port: 22},
	}
	s := New(hosts)

	// Wildcard allows all hosts.
	allowedHosts := []string{"*"}
	accessible := s.GetAccessibleHosts("user", nil, allowedHosts)
	if len(accessible) != 2 {
		t.Errorf("expected 2 accessible hosts with wildcard, got %d", len(accessible))
	}
}

func TestCanAccessNoRestrictions(t *testing.T) {
	s := New(nil)
	host := config.HostConfig{Name: "host", Addr: "10.0.0.1", Port: 22}

	if !s.canAccess(host, "anyuser", nil, nil) {
		t.Error("expected access with no restrictions")
	}
}

func TestCanAccessUserRestricted(t *testing.T) {
	s := New(nil)
	host := config.HostConfig{
		Name:  "host",
		Addr:  "10.0.0.1",
		Port:  22,
		Users: []string{"allowed"},
	}

	if !s.canAccess(host, "allowed", nil, nil) {
		t.Error("expected access for allowed user")
	}
	if s.canAccess(host, "denied", nil, nil) {
		t.Error("expected no access for denied user")
	}
}

func TestCanAccessWithAllowedHostsRestriction(t *testing.T) {
	s := New(nil)
	host := config.HostConfig{Name: "host1", Addr: "10.0.0.1", Port: 22}

	// User allowed to access host1.
	if !s.canAccess(host, "user", nil, []string{"host1"}) {
		t.Error("expected access for allowed host")
	}

	// User not allowed to access host1.
	if s.canAccess(host, "user", nil, []string{"host2"}) {
		t.Error("expected no access for restricted host")
	}

	// Wildcard allows all.
	if !s.canAccess(host, "user", nil, []string{"*"}) {
		t.Error("expected access with wildcard")
	}

	// Empty allowed hosts means no restriction.
	if !s.canAccess(host, "user", nil, nil) {
		t.Error("expected access with empty allowed hosts")
	}
}

func TestSelectHostNoHosts(t *testing.T) {
	s := New(nil)
	buf := &bytes.Buffer{}

	_, err := s.SelectHost(buf, nil)
	if err == nil {
		t.Error("expected error for empty hosts")
	}
}

type mockReadWriter struct {
	readData  []byte
	writeData *bytes.Buffer
	readPos   int
}

func (m *mockReadWriter) Read(p []byte) (int, error) {
	if m.readPos >= len(m.readData) {
		return 0, nil
	}
	n := copy(p, m.readData[m.readPos:])
	m.readPos += n
	return n, nil
}

func (m *mockReadWriter) Write(p []byte) (int, error) {
	return m.writeData.Write(p)
}

func TestSelectHostValidSelection(t *testing.T) {
	hosts := []config.HostConfig{
		{Name: "host1", Addr: "10.0.0.1", Port: 22},
		{Name: "host2", Addr: "10.0.0.2", Port: 22},
	}
	s := New(hosts)

	rw := &mockReadWriter{
		readData:  []byte("1\n"),
		writeData: &bytes.Buffer{},
	}

	selected, err := s.SelectHost(rw, hosts)
	if err != nil {
		t.Fatalf("selection failed: %v", err)
	}
	if selected.Name != "host1" {
		t.Errorf("expected host1, got %s", selected.Name)
	}
}

func TestSelectHostSecondOption(t *testing.T) {
	hosts := []config.HostConfig{
		{Name: "host1", Addr: "10.0.0.1", Port: 22},
		{Name: "host2", Addr: "10.0.0.2", Port: 22},
	}
	s := New(hosts)

	rw := &mockReadWriter{
		readData:  []byte("2\n"),
		writeData: &bytes.Buffer{},
	}

	selected, err := s.SelectHost(rw, hosts)
	if err != nil {
		t.Fatalf("selection failed: %v", err)
	}
	if selected.Name != "host2" {
		t.Errorf("expected host2, got %s", selected.Name)
	}
}

func TestSelectHostInvalidNumber(t *testing.T) {
	hosts := []config.HostConfig{
		{Name: "host1", Addr: "10.0.0.1", Port: 22},
	}
	s := New(hosts)

	rw := &mockReadWriter{
		readData:  []byte("abc\n"),
		writeData: &bytes.Buffer{},
	}

	_, err := s.SelectHost(rw, hosts)
	if err == nil {
		t.Error("expected error for invalid selection")
	}
}

func TestSelectHostOutOfRange(t *testing.T) {
	hosts := []config.HostConfig{
		{Name: "host1", Addr: "10.0.0.1", Port: 22},
	}
	s := New(hosts)

	rw := &mockReadWriter{
		readData:  []byte("5\n"),
		writeData: &bytes.Buffer{},
	}

	_, err := s.SelectHost(rw, hosts)
	if err == nil {
		t.Error("expected error for out of range selection")
	}
}
