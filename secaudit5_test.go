// SPDX-License-Identifier: BSD-3-Clause

package saml

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/go-authn/harden/redirect"
)

// Security audit 2026-11-21: "127." as a string prefix is true of DNS names, so
// a metadata redirect to one must not be followed (the rule is harden's).
func TestSecAudit5LoopbackIsNotAStringPrefix(t *testing.T) {
	for _, h := range []string{"127.evil.example", "127.0.0.1.evil.example", "127.example"} {
		u, _ := url.Parse("http://" + h + "/metadata.xml")
		if err := redirect.CheckRedirect(&http.Request{URL: u}, nil); err == nil {
			t.Errorf("a redirect from https to cleartext %s was allowed", u)
		}
	}
}
