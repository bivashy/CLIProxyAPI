package management

import (
	"net/http"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

func TestAuthenticateManagementKey_AllowedIPs(t *testing.T) {
	tests := []struct {
		name        string
		allowRemote bool
		allowedIPs  []string
		clientIP    string
		local       bool
		wantAllowed bool
		wantStatus  int
		wantMsg     string
	}{
		{name: "empty list allows remote", allowRemote: true, clientIP: "203.0.113.9", wantAllowed: true},
		{name: "exact ip", allowRemote: true, allowedIPs: []string{"203.0.113.10"}, clientIP: "203.0.113.10", wantAllowed: true},
		{name: "cidr", allowRemote: true, allowedIPs: []string{"10.0.0.0/24"}, clientIP: "10.0.0.77", wantAllowed: true},
		{name: "ipv6", allowRemote: true, allowedIPs: []string{"2001:db8::/32"}, clientIP: "2001:db8::1", wantAllowed: true},
		{name: "ipv4 mapped ipv6", allowRemote: true, allowedIPs: []string{"203.0.113.10"}, clientIP: "::ffff:203.0.113.10", wantAllowed: true},
		{name: "not listed", allowRemote: true, allowedIPs: []string{"10.0.0.0/24"}, clientIP: "203.0.113.9", wantStatus: http.StatusForbidden, wantMsg: "management access denied for this IP"},
		{name: "loopback bypasses list", allowRemote: false, allowedIPs: []string{"10.0.0.0/24"}, clientIP: "127.0.0.1", local: true, wantAllowed: true},
		{name: "allow-remote false still rejects", allowRemote: false, allowedIPs: []string{"203.0.113.10"}, clientIP: "203.0.113.10", wantStatus: http.StatusForbidden, wantMsg: "remote management disabled"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := &Handler{
				cfg: &config.Config{RemoteManagement: config.RemoteManagement{
					AllowRemote: tc.allowRemote,
					AllowedIPs:  tc.allowedIPs,
				}},
				failedAttempts: make(map[string]*attemptInfo),
				envSecret:      "test-secret",
			}
			allowed, status, msg := h.AuthenticateManagementKey(tc.clientIP, tc.local, "test-secret")
			if allowed != tc.wantAllowed || status != tc.wantStatus || msg != tc.wantMsg {
				t.Fatalf("got (%v, %d, %q), want (%v, %d, %q)", allowed, status, msg, tc.wantAllowed, tc.wantStatus, tc.wantMsg)
			}
		})
	}
}

func TestAuthenticateManagementKey_AllowedIPsRejectionDoesNotCountTowardBan(t *testing.T) {
	h := &Handler{
		cfg: &config.Config{RemoteManagement: config.RemoteManagement{
			AllowRemote: true,
			AllowedIPs:  []string{"10.0.0.0/24"},
		}},
		failedAttempts: make(map[string]*attemptInfo),
		envSecret:      "test-secret",
	}
	for i := 0; i < 10; i++ {
		if allowed, status, _ := h.AuthenticateManagementKey("203.0.113.9", false, "wrong"); allowed || status != http.StatusForbidden {
			t.Fatalf("attempt %d: allowed=%v status=%d", i, allowed, status)
		}
	}
	if len(h.failedAttempts) != 0 {
		t.Fatalf("failedAttempts = %d entries, want 0", len(h.failedAttempts))
	}
}
