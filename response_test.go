// SPDX-License-Identifier: BSD-3-Clause

package saml

import (
	"crypto/x509"
	"encoding/base64"
	"errors"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

const (
	aes128GCM = "http://www.w3.org/2009/xmlenc11#aes128-gcm"
	aes256GCM = "http://www.w3.org/2009/xmlenc11#aes256-gcm"
	aes128CBC = "http://www.w3.org/2001/04/xmlenc#aes128-cbc"
	aes256CBC = "http://www.w3.org/2001/04/xmlenc#aes256-cbc"
)

// What an IdP in the federation actually sends, in each of the shapes a
// Shibboleth IdP is configured to send it.
func TestAccepted(t *testing.T) {
	for _, c := range []struct {
		name string
		r    response
	}{
		// Shibboleth IdP v5, fresh install: Response signed, assertion
		// encrypted with AES-128-GCM.
		{"signed response, GCM", response{signResponse: true, encrypt: aes128GCM}},
		// Older install: the same with CBC.
		{"signed response, CBC", response{signResponse: true, encrypt: aes128CBC}},
		{"signed response, AES-256-CBC", response{signResponse: true, encrypt: aes256CBC}},
		{"signed response, plain", response{signResponse: true}},
		{"signed assertion, plain", response{signAssertion: true}},
		{"signed assertion, GCM, unsigned response", response{signAssertion: true, encrypt: aes256GCM}},
		{"both signed, GCM", response{signResponse: true, signAssertion: true, encrypt: aes128GCM}},
		{"RSA-OAEP 1.1 with MGF1-SHA256", response{signResponse: true, encrypt: aes128GCM,
			keyTransport: `<xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#rsa-oaep"><ds:DigestMethod xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><xenc11:MGF xmlns:xenc11="http://www.w3.org/2009/xmlenc11#" Algorithm="http://www.w3.org/2009/xmlenc11#mgf1sha256"/></xenc:EncryptionMethod>`}},
	} {
		t.Run(c.name, func(t *testing.T) {
			if strings.Contains(c.r.keyTransport, "xmlenc11#rsa-oaep") && len(laxKeySearch) == 0 {
				// xmlsec1 1.2 -- what Ubuntu ships -- cannot produce RSA-OAEP 1.1
				// (it knows only the 1.0 identifier). The case is judged by 1.3,
				// which has it; a 1.2 lane says so instead of failing on the judge.
				t.Skip("this xmlsec1 cannot encrypt with xmlenc11#rsa-oaep")
			}
			w := newWorld(t)
			a, err := w.newSP().Accept(w.build(defaultAssertion(), c.r), w.pending)
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
			if got, from := a.Subject(); got != "a1b2c3@"+scope || from != SubjectID {
				t.Errorf("Subject() = %q from %q", got, from)
			}
			if a.First(EduPersonPrincipalName) != "alice@"+scope {
				t.Errorf("eppn = %q", a.First(EduPersonPrincipalName))
			}
			// The IdP's scope is univ-example.fr: the affiliation it
			// claimed at another university is dropped, its own is kept.
			if got := a.Attributes[EduPersonScopedAffiliation]; !slices.Equal(got, []string{"member@" + scope}) {
				t.Errorf("scoped affiliation = %q: an out-of-scope value was KEPT", got)
			}
			if a.IdP.EntityID != idpEntity || a.SessionIndex != "_s1" {
				t.Errorf("assertion = %+v", a)
			}
		})
	}
}

// refused runs one response and requires a refusal whose message matches.
func refused(t *testing.T, w *world, sp *SP, a assertion, r response, want string) {
	t.Helper()
	_, err := sp.Accept(w.build(a, r), w.pending)
	if err == nil {
		t.Fatalf("ACCEPTED; want a refusal matching %q", want)
	}
	if !regexp.MustCompile(want).MatchString(err.Error()) {
		t.Fatalf("refused, but for another reason: %v (want %q)", err, want)
	}
}

func TestRefused(t *testing.T) {
	signed := response{signResponse: true, encrypt: aes128GCM}
	for _, c := range []struct {
		name string
		a    func(*assertion)
		r    response
		want string
	}{
		{"nothing signed", nil, response{}, "neither the response nor the assertion is signed"},
		{"nothing signed, encrypted GCM", nil, response{encrypt: aes128GCM}, "neither"},
		// ⛔ The padding oracle: CBC ciphertext nobody signed is not even
		// decrypted.
		{"CBC in an unsigned response", nil, response{signAssertion: true, encrypt: aes128CBC}, "refused before decryption"},
		{"SHA-1 signature", nil, response{signResponse: true, sigMethod: rsaSHA1, digest: dSHA1}, "rsa-sha1.*not accepted"},
		{"SHA-1 digest", nil, response{signResponse: true, digest: dSHA1}, "digest algorithm.*not accepted"},
		{"another audience", func(a *assertion) { a.Audience = "https://other.example.org/sp" }, signed, "another audience"},
		{"another recipient", func(a *assertion) { a.Recipient = "https://other.example.org/acs" }, signed, "no bearer confirmation"},
		{"another request", func(a *assertion) { a.InResponseTo = "_other" }, signed, "no bearer confirmation"},
		{"unsolicited", func(a *assertion) { a.InResponseTo = "" }, response{signResponse: true, inResponseTo: "_x"}, "does not answer this request"},
		{"expired", func(a *assertion) { a.NotOnOrAfter = judgeNow.Add(-10 * time.Minute) }, signed, "no bearer confirmation|expired"},
		{"another issuer", func(a *assertion) { a.Issuer = "https://idp.another-university.fr/idp" }, signed, "issued by"},
		{"a condition nobody understands", func(a *assertion) {
			a.Extra = `<saml:Condition xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="Unknown"/>`
		}, signed, "not understood"},
		{"addressed elsewhere", nil, response{signResponse: true, destination: "https://other.example.org/acs"}, "addressed to"},
		{"an IdP that said no", nil, response{signResponse: true, status: `<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder"><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:NoPassive"/></samlp:StatusCode>`}, "NoPassive"},
		// Changed after signing: the value, then the whole assertion swapped
		// for a second one.
		{"tampered value", nil, response{signResponse: true, tamper: func(s string) string {
			return strings.Replace(s, "Alice Martin", "Mallory", 1)
		}}, "signature"},
		{"a second, unsigned assertion", nil, response{signAssertion: true, tamper: func(s string) string {
			evil := defaultAssertion()
			evil.ID = "_evil"
			evil.Attributes[EduPersonPrincipalName] = []string{"president@" + scope}
			return strings.Replace(s, "</samlp:Response>", evil.xml(false)+"</samlp:Response>", 1)
		}}, "2 assertions"},
	} {
		t.Run(c.name, func(t *testing.T) {
			w := newWorld(t)
			a := defaultAssertion()
			if c.a != nil {
				c.a(&a)
			}
			refused(t, w, w.newSP(), a, c.r, c.want)
		})
	}
}

// ⛔ The signature-wrapping attack, in the shape that works against a
// library that verifies one element and reads another: the signed assertion
// is kept, but moved where nobody reads it, and an unsigned one with the
// SAME ID takes its place. The digest does verify -- over the moved one.
func TestWrapping(t *testing.T) {
	w := newWorld(t)
	resp := w.build(defaultAssertion(), response{signAssertion: true})
	raw := decode(t, resp)
	i := strings.Index(raw, "<saml:Assertion")
	j := strings.Index(raw, "</saml:Assertion>") + len("</saml:Assertion>")
	original := raw[i:j]
	evil := strings.Replace(original, "alice@"+scope, "president@"+scope, 1)
	// The evil one keeps the original's Signature element, whose digest
	// covers the original; the original is tucked into an Extensions.
	wrapped := raw[:i] + `<samlp:Extensions>` + original + `</samlp:Extensions>` + evil + raw[j:]
	a, err := w.newSP().Accept(encode(wrapped), w.pending)
	if err == nil {
		t.Fatalf("a wrapped assertion was ACCEPTED as %q", a.First(EduPersonPrincipalName))
	}
}

func TestReplay(t *testing.T) {
	w := newWorld(t)
	sp := w.newSP()
	resp := w.build(defaultAssertion(), response{signResponse: true, encrypt: aes128GCM})
	if _, err := sp.Accept(resp, w.pending); err != nil {
		t.Fatal(err)
	}
	if _, err := sp.Accept(resp, w.pending); err == nil || !strings.Contains(err.Error(), "already been used") {
		t.Fatalf("the same assertion twice: %v", err)
	}
}

func TestNoPassive(t *testing.T) {
	w := newWorld(t)
	_, err := w.newSP().Accept(w.build(defaultAssertion(), response{signResponse: true,
		status: `<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder"><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:NoPassive"/></samlp:StatusCode><samlp:StatusMessage>no session</samlp:StatusMessage>`}), w.pending)
	var se *StatusError
	if !errors.As(err, &se) || !se.NoPassive() || se.Message != "no session" {
		t.Fatalf("err = %v, want a NoPassive StatusError", err)
	}
}

// A request for MFA that came back with a password is refused: the IdP may
// ignore RequestedAuthnContext, and the caller must not believe it got what
// it asked for.
func TestAuthnContextNotHonoured(t *testing.T) {
	w := newWorld(t)
	w.pending.AuthnContext = []string{"https://refeds.org/profile/mfa"}
	refused(t, w, w.newSP(), defaultAssertion(), response{signResponse: true}, "was not one of those requested")

	a := defaultAssertion()
	a.AuthnContext = "https://refeds.org/profile/mfa"
	w2 := newWorld(t)
	w2.pending.AuthnContext = []string{"https://refeds.org/profile/mfa"}
	got, err := w2.newSP().Accept(w2.build(a, response{signResponse: true}), w2.pending)
	if err != nil || got.AuthnContext != "https://refeds.org/profile/mfa" {
		t.Fatalf("an MFA assertion for an MFA request: %v", err)
	}
}

// Signed by a key the federation does not list for this IdP.
func TestAnotherKey(t *testing.T) {
	w := newWorld(t)
	other := newParty(t, w.dir, "other")
	w.provider.Keys = []*x509.Certificate{other.cert}
	refused(t, w, w.newSP(), defaultAssertion(), response{signResponse: true}, "does not verify with any key")
}

func decode(t *testing.T, s string) string {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func encode(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// ⛔ The element that was verified is the one that is read.
//
// A comment inserted AFTER signing does not break the signature: exclusive
// canonicalisation without comments drops it before the digest. But a
// reader that walks the document as it arrived sees two text nodes where the
// signer wrote one, and etree's Text() returns the first -- so
// "Alice<!---->Martin" reads as "Alice". This is the 2018 truncation attack
// on half a dozen SAML libraries, where "admin@evil.example<!---->.good.example"
// signed as one address and was read as another.
//
// ⛔ This does NOT witness the rule that only verify's result is read, and
// was checked not to: with that rule sabotaged the test stays green, because
// etree 1.8 itself skips comments in Text(). Both close the attack; this
// test keeps the attack closed if either one changes. No witness for the rule
// itself could be built -- every difference between what arrived and what was
// signed is either caught by the digest or normalised by etree the same way
// canonicalisation normalises it -- so the rule stands as defence in depth,
// said here rather than implied by a test that cannot see it.
func TestCommentInjectedAfterSigning(t *testing.T) {
	for _, r := range []response{
		{signResponse: true},
		{signAssertion: true},
		{signResponse: true, signAssertion: true},
	} {
		w := newWorld(t)
		r.tamper = func(s string) string {
			return strings.Replace(s, "Alice Martin", "Alice <!---->Martin", 1)
		}
		a, err := w.newSP().Accept(w.build(defaultAssertion(), r), w.pending)
		if err != nil {
			t.Fatalf("%+v: a comment outside the signature's view was refused: %v", r, err)
		}
		if got := a.First(DisplayName); got != "Alice Martin" {
			t.Fatalf("%+v: displayName read as %q -- the UNVERIFIED document was read", r, got)
		}
	}
}

// ⛔ An unsigned response with many EncryptedKeys: each is an RSA private-key
// operation before any signature is checked. A few are tried -- an IdP sends
// one per encryption key of the SP, two across a rollover -- and a response
// carrying more is refused at once rather than after hundreds of them.
func TestEncryptedKeysAreCapped(t *testing.T) {
	ekRe := regexp.MustCompile(`(?s)<xenc:EncryptedKey.*?</xenc:EncryptedKey>`)
	cvRe := regexp.MustCompile(`(?s)(<xenc:CipherValue>)(.*?)(</xenc:CipherValue>)`)
	// before puts n keys that open nothing ahead of the real one.
	before := func(n int) func(string) string {
		return func(s string) string {
			real := ekRe.FindString(s)
			if real == "" {
				t.Fatal("no EncryptedKey to copy")
			}
			bogus := cvRe.ReplaceAllStringFunc(real, func(m string) string {
				p := cvRe.FindStringSubmatch(m)
				return p[1] + strings.Repeat("A", len(p[2])) + p[3]
			})
			return strings.Replace(s, real, strings.Repeat(bogus, n)+real, 1)
		}
	}
	r := response{signAssertion: true, encrypt: aes256GCM}

	// A rollover's worth, and the real one: accepted.
	w := newWorld(t)
	r.tamper = before(maxKeyUnwraps - 1)
	if _, err := w.newSP().Accept(w.build(defaultAssertion(), r), w.pending); err != nil {
		t.Fatalf("%d keys that open nothing, then the real one: %v", maxKeyUnwraps-1, err)
	}

	// A hundred -- under the size limit: refused, and quickly.
	w = newWorld(t)
	r.tamper = before(100)
	start := time.Now()
	_, err := w.newSP().Accept(w.build(defaultAssertion(), r), w.pending)
	took := time.Since(start)
	if err == nil || !strings.Contains(err.Error(), "keys for this SP") {
		t.Fatalf("100 keys: %v", err)
	}
	// Four RSA operations at most; 100 take a tenth of a second or more.
	if took > 50*time.Millisecond {
		t.Errorf("100 keys took %s to refuse", took)
	}
}
