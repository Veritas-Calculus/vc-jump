package dashboard

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestParseAuditQueryParams(t *testing.T) {
	tests := []struct {
		name      string
		query     string
		wantLimit int
		wantUser  string
		wantType  string
	}{
		{
			name:      "default values",
			query:     "",
			wantLimit: 100,
			wantUser:  "",
			wantType:  "",
		},
		{
			name:      "with username filter",
			query:     "username=admin",
			wantLimit: 100,
			wantUser:  "admin",
			wantType:  "",
		},
		{
			name:      "with event type filter",
			query:     "event_type=login",
			wantLimit: 100,
			wantUser:  "",
			wantType:  "login",
		},
		{
			name:      "custom limit",
			query:     "limit=50",
			wantLimit: 50,
			wantUser:  "",
			wantType:  "",
		},
		{
			name:      "limit too high",
			query:     "limit=2000",
			wantLimit: 100, // Should use default
			wantUser:  "",
			wantType:  "",
		},
		{
			name:      "invalid limit",
			query:     "limit=invalid",
			wantLimit: 100,
			wantUser:  "",
			wantType:  "",
		},
		{
			name:      "all filters",
			query:     "username=testuser&event_type=connect&limit=25&offset=10",
			wantLimit: 25,
			wantUser:  "testuser",
			wantType:  "connect",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/audit?"+tt.query, nil)
			params := parseAuditQueryParams(req)

			if params.limit != tt.wantLimit {
				t.Errorf("limit = %d, want %d", params.limit, tt.wantLimit)
			}
			if params.username != tt.wantUser {
				t.Errorf("username = %q, want %q", params.username, tt.wantUser)
			}
			if params.eventType != tt.wantType {
				t.Errorf("eventType = %q, want %q", params.eventType, tt.wantType)
			}
		})
	}
}

func TestParseAuditQueryParamsTime(t *testing.T) {
	startTimeStr := "2024-01-15T10:00:00Z"
	endTimeStr := "2024-01-15T18:00:00Z"

	req := httptest.NewRequest(http.MethodGet, "/api/audit?start_time="+startTimeStr+"&end_time="+endTimeStr, nil)
	params := parseAuditQueryParams(req)

	expectedStart, _ := time.Parse(time.RFC3339, startTimeStr)
	expectedEnd, _ := time.Parse(time.RFC3339, endTimeStr)

	if !params.startTime.Equal(expectedStart) {
		t.Errorf("startTime = %v, want %v", params.startTime, expectedStart)
	}
	if !params.endTime.Equal(expectedEnd) {
		t.Errorf("endTime = %v, want %v", params.endTime, expectedEnd)
	}
}

func TestParseAuditQueryParamsInvalidTime(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/audit?start_time=invalid&end_time=also-invalid", nil)
	params := parseAuditQueryParams(req)

	if !params.startTime.IsZero() {
		t.Errorf("startTime should be zero for invalid input, got %v", params.startTime)
	}
	if !params.endTime.IsZero() {
		t.Errorf("endTime should be zero for invalid input, got %v", params.endTime)
	}
}
