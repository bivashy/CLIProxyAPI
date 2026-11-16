package config

import (
	"reflect"
	"testing"
)

func TestParseConfigBytesManagementAllowedIPs(t *testing.T) {
	cfg, errParse := ParseConfigBytes([]byte("remote-management:\n  allowed-ips: [\"203.0.113.10\", \"10.0.0.0/24\"]\n"))
	if errParse != nil {
		t.Fatalf("ParseConfigBytes() error = %v", errParse)
	}
	if want := []string{"203.0.113.10", "10.0.0.0/24"}; !reflect.DeepEqual(cfg.RemoteManagement.AllowedIPs, want) {
		t.Fatalf("AllowedIPs = %v, want %v", cfg.RemoteManagement.AllowedIPs, want)
	}
	for _, bad := range []string{"not-an-ip", "\"\"", "\" 10.0.0.1\""} {
		if _, errParse := ParseConfigBytes([]byte("remote-management:\n  allowed-ips: [" + bad + "]\n")); errParse == nil {
			t.Fatalf("ParseConfigBytes() accepted allowed-ips entry %s", bad)
		}
	}
}

func TestParseConfigBytesTrustedProxies(t *testing.T) {
	cfg, errParse := ParseConfigBytes([]byte(`trusted-proxies:
  - 192.0.2.0/24
  - 2001:db8::1
`))
	if errParse != nil {
		t.Fatalf("ParseConfigBytes() error = %v", errParse)
	}

	want := []string{"192.0.2.0/24", "2001:db8::1"}
	if !reflect.DeepEqual(cfg.TrustedProxies, want) {
		t.Fatalf("TrustedProxies = %v, want %v", cfg.TrustedProxies, want)
	}
}

func TestParseConfigBytesRejectsInvalidTrustedProxy(t *testing.T) {
	if _, errParse := ParseConfigBytes([]byte("trusted-proxies: [not-an-ip]")); errParse == nil {
		t.Fatal("ParseConfigBytes() error = nil, want invalid trusted proxy error")
	}
}
