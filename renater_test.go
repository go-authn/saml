// SPDX-License-Identifier: BSD-3-Clause

package saml

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

// RENATER's metadata, as RENATER signed it, fetched on 2026-09-29.
//
// This is the one signature in the suite that nobody here produced: pyFF and
// xmlsec at RENATER signed it, and the certificate is checked below against
// the fingerprint RENATER publishes, not against itself.
const (
	renaterFingerprint = "682f2058419ed079ebfe3c27d6a4a409396fae3f105f22ea040f04f3782d5cc0"
	// Inside the document's validity: it was signed on 2026-09-29 and is
	// valid for nine days.
	renaterNow = "2026-09-30T12:00:00Z"
)

func renater(t *testing.T) ([]byte, *x509.Certificate) {
	t.Helper()
	f, err := os.Open("testdata/fer-idps.xml.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(z)
	if err != nil {
		t.Fatal(err)
	}
	p, err := os.ReadFile("testdata/metadata-signature-2026.pem")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := pem.Decode(p)
	sum := sha256.Sum256(b.Bytes)
	if hex.EncodeToString(sum[:]) != renaterFingerprint {
		t.Fatalf("the committed certificate is not the one RENATER publishes the fingerprint of")
	}
	cert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return data, cert
}

func at(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

func TestRENATERMetadata(t *testing.T) {
	data, cert := renater(t)
	md, err := ParseMetadata(data, cert, at(renaterNow))
	if err != nil {
		t.Fatal(err)
	}
	// 343 IdPs are in the file, every one of them with SAML 2.0 alongside
	// whatever SAML 1.1 it still speaks.
	t.Logf("%d SAML 2.0 IdPs, valid until %s, cache %s", len(md.IdPs), md.ValidUntil, md.CacheDuration)
	if len(md.IdPs) < 250 {
		t.Fatalf("only %d IdPs read", len(md.IdPs))
	}
	if md.CacheDuration != time.Hour {
		t.Errorf("cacheDuration = %s, want PT1H", md.CacheDuration)
	}
	noScope, noKey := 0, 0
	for _, i := range md.IdPs {
		if len(i.Scopes) == 0 {
			noScope++
		}
		if len(i.Keys) == 0 {
			noKey++
		}
	}
	t.Logf("%d without a scope, %d without a signing key", noScope, noKey)
	if noKey != 0 {
		t.Errorf("%d IdPs have no signing key", noKey)
	}
}

func TestRENATERMetadataTampered(t *testing.T) {
	data, cert := renater(t)
	// One IdP's SSO location, moved somewhere else.
	i := bytes.Index(data, []byte(`Location="https://`))
	bad := append([]byte{}, data...)
	copy(bad[i+len(`Location="https://`):], "evil")
	if _, err := ParseMetadata(bad, cert, at(renaterNow)); err == nil {
		t.Fatal("a tampered aggregate was ACCEPTED")
	} else if !strings.Contains(err.Error(), "signature") {
		t.Fatalf("refused, but not for the signature: %v", err)
	}
}
