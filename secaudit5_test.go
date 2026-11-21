// SPDX-License-Identifier: BSD-3-Clause

package saml

import (
	"net/http"
	"net/url"
	"testing"
)

// What is loopback, and what is a routable address that must not be.
func TestLoopbackIsLoopbackIPsAndLocalhost(t *testing.T) {
	for _, h := range []string{"localhost", "127.0.0.1", "127.255.0.9", "::1"} {
		if !loopback(h) {
			t.Errorf("loopback(%q) = false", h)
		}
	}
	for _, h := range []string{"", "8.8.8.8", "192.168.1.1", "2001:db8::1", "::", "0.0.0.0", "localhost.evil.example"} {
		if loopback(h) {
			t.Errorf("loopback(%q) = true", h)
		}
	}
}

// Security audit 2026-11-21: "127." as a string prefix is true of DNS names.
func TestSecAudit5LoopbackIsNotAStringPrefix(t *testing.T) {
	for _, h := range []string{"127.evil.example", "127.0.0.1.evil.example", "127.example"} {
		if loopback(h) {
			t.Errorf("loopback(%q) = true: a public DNS name is treated as this host", h)
		}
		u, _ := url.Parse("http://" + h + "/metadata.xml")
		if err := stayHTTPS(&http.Request{URL: u}, nil); err == nil {
			t.Errorf("stayHTTPS allows an https -> cleartext redirect to %s", u)
		}
	}
}
