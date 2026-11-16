package config

import (
	"fmt"
	"net"
	"strings"
)

func validateTrustedProxies(trustedProxies []string) error {
	for _, trustedProxy := range trustedProxies {
		if trustedProxy == "" || strings.TrimSpace(trustedProxy) != trustedProxy {
			return fmt.Errorf("invalid trusted-proxies entry %q: expected an IP address or CIDR", trustedProxy)
		}
		if net.ParseIP(trustedProxy) != nil {
			continue
		}
		if _, _, errParseCIDR := net.ParseCIDR(trustedProxy); errParseCIDR != nil {
			return fmt.Errorf("invalid trusted-proxies entry %q: %w", trustedProxy, errParseCIDR)
		}
	}
	return nil
}

func validateManagementAllowedIPs(allowedIPs []string) error {
	for _, entry := range allowedIPs {
		if entry == "" || strings.TrimSpace(entry) != entry {
			return fmt.Errorf("invalid management allowed-ips entry %q: expected an IP address or CIDR", entry)
		}
		if net.ParseIP(entry) != nil {
			continue
		}
		if _, _, errParseCIDR := net.ParseCIDR(entry); errParseCIDR != nil {
			return fmt.Errorf("invalid management allowed-ips entry %q: %w", entry, errParseCIDR)
		}
	}
	return nil
}
