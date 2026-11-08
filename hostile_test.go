// SPDX-License-Identifier: BSD-3-Clause

package saml

import (
	"encoding/base64"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
)

// hostile runs f under a soft memory limit and requires that it REFUSES, and
// that the refusal costs a bounded amount: TotalAlloc is exact under load,
// where time is not. A bomb that is "refused" only after it has been expanded
// is not refused.
func hostile(t *testing.T, budget uint64, f func() error) {
	t.Helper()
	old := debug.SetMemoryLimit(256 << 20)
	defer debug.SetMemoryLimit(old)
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	err := f()
	runtime.ReadMemStats(&after)
	if err == nil {
		t.Fatal("ACCEPTED a hostile document; want a refusal")
	}
	if got := after.TotalAlloc - before.TotalAlloc; got > budget {
		t.Fatalf("refused (%v), but only after allocating %d bytes (budget %d)", err, got, budget)
	}
}

// laughs is the billion laughs: ten levels of ten references each, 10^9
// expansions of "lol" if anything expanded them.
func laughs() string {
	var b strings.Builder
	b.WriteString(`<!DOCTYPE lolz [<!ENTITY lol "lol">`)
	prev := "lol"
	for i := 1; i <= 9; i++ {
		name := "lol" + string(rune('0'+i))
		b.WriteString(`<!ENTITY ` + name + ` "` + strings.Repeat("&"+prev+";", 10) + `">`)
		prev = name
	}
	b.WriteString(`]>`)
	return b.String() + `<samlp:Response xmlns:samlp="` + nsProtocol + `">&` + prev + `;</samlp:Response>`
}

func TestHostileInputsAreRefusedCheaply(t *testing.T) {
	w := newFzWorld(t)
	p := Pending{ID: fzReq, IdP: fzIdP, Issued: w.at}
	b64 := base64.StdEncoding.EncodeToString
	accept := func(doc string) func() error {
		return func() error { _, err := w.newSP().Accept(b64([]byte(doc)), p); return err }
	}
	meta := func(doc string) func() error {
		return func() error { _, err := ParseMetadata([]byte(doc), w.fed.Cert, w.at); return err }
	}

	t.Run("entity expansion in a response", func(t *testing.T) { hostile(t, 4<<20, accept(laughs())) })
	t.Run("entity expansion in metadata", func(t *testing.T) { hostile(t, 4<<20, meta(laughs())) })
	t.Run("a DOCTYPE with an external entity", func(t *testing.T) {
		hostile(t, 4<<20, accept(`<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><samlp:Response xmlns:samlp="`+nsProtocol+`">&x;</samlp:Response>`))
	})

	// 100,000 levels fit in the 256 KiB a response may be; a million in a
	// metadata document, which has no size bound of its own.
	t.Run("deep nesting in a response", func(t *testing.T) {
		hostile(t, 4<<20, accept(strings.Repeat("<a>", 80000)+strings.Repeat("</a>", 80000)))
	})
	t.Run("deep nesting in metadata", func(t *testing.T) {
		hostile(t, 8<<20, meta(strings.Repeat("<a>", 1<<20)+strings.Repeat("</a>", 1<<20)))
	})
	t.Run("a flat wide document", func(t *testing.T) {
		hostile(t, 4<<20, accept(`<samlp:Response xmlns:samlp="`+nsProtocol+`">`+strings.Repeat("<a/>", 60000)+`</samlp:Response>`))
	})

	// A CipherValue that fills the response: base64 inside an
	// EncryptedAssertion inside the cap. No key opens it; it must not cost
	// more than its own decoding.
	t.Run("a huge CipherValue", func(t *testing.T) {
		huge := b64(make([]byte, 150<<10))
		doc := `<samlp:Response xmlns:samlp="` + nsProtocol + `" xmlns:saml="` + nsAssertion + `" xmlns:xenc="` + nsXEnc + `" ID="_r" Version="2.0" InResponseTo="` + fzReq + `">` +
			`<saml:EncryptedAssertion><xenc:EncryptedData><xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/>` +
			`<xenc:CipherData><xenc:CipherValue>` + huge + `</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData></saml:EncryptedAssertion></samlp:Response>`
		hostile(t, 4<<20, accept(doc))
	})
	t.Run("a response over the cap, never decoded", func(t *testing.T) {
		hostile(t, 1<<20, func() error {
			_, err := w.newSP().Accept(strings.Repeat("A", maxResponse+1), p)
			return err
		})
	})
	t.Run("base64 that is all whitespace", func(t *testing.T) {
		hostile(t, 4<<20, func() error {
			_, err := w.newSP().Accept(strings.Repeat(" \n", maxResponse/2), p)
			return err
		})
	})
}
