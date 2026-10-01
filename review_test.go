// SPDX-License-Identifier: BSD-3-Clause

package saml

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// What an adversarial review of v0.1.1 proved, each held here.

// signedFeed signs a metadata document with the test federation key.
func signedFeed(w *world, body string) []byte {
	doc := `<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="_md" ` + body
	in := w.file("md.xml", strings.Replace(doc, "<!--SIG-->", sprintf(sigTemplate, rsaSHA256, "_md", dSHA256), 1))
	return w.run("--sign", "--privkey-pem", w.idp.keyFile+","+w.idp.certFile,
		"--id-attr:ID", "urn:oasis:names:tc:SAML:2.0:metadata:EntitiesDescriptor", "--output", "/dev/stdout", in)
}

func feedEntity(id, cert string) string {
	return `<md:EntityDescriptor entityID="` + id + `"><md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">` +
		`<md:KeyDescriptor><ds:KeyInfo><ds:X509Data><ds:X509Certificate>` + cert + `</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>` +
		`<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://` + id + `/r"/></md:IDPSSODescriptor></md:EntityDescriptor>`
}

// ⛔ An older, validly signed document is not taken back: it may be the one
// with the key since revoked, replayed by whoever stands on the path. And a
// failed document does not leave its ETag behind to make the next refresh a
// silent 304.
func TestFederationRollbackAndETag(t *testing.T) {
	w := newWorld(t)
	compromised := newParty(t, w.dir, "compromised")
	old := signedFeed(w, `validUntil="2026-10-09T00:00:00Z"><!--SIG-->`+feedEntity("a.fr", b64(compromised.cert.Raw))+`</md:EntitiesDescriptor>`)
	newer := signedFeed(w, `validUntil="2026-10-12T00:00:00Z"><!--SIG-->`+feedEntity("a.fr", b64(w.sp.cert.Raw))+`</md:EntitiesDescriptor>`)
	var serve, etag atomic.Value
	serve.Store(newer)
	etag.Store(`"new"`)
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == etag.Load().(string) {
			rw.WriteHeader(http.StatusNotModified)
			return
		}
		rw.Header().Set("ETag", etag.Load().(string))
		rw.Write(serve.Load().([]byte))
	}))
	defer srv.Close()
	f := &Federation{URL: srv.URL, Cert: w.idp.cert, Now: func() time.Time { return judgeNow }}
	ctx := context.Background()
	if err := f.Refresh(ctx); err != nil {
		t.Fatal(err)
	}

	serve.Store(old)
	etag.Store(`"old"`)
	if err := f.Refresh(ctx); err == nil || !strings.Contains(err.Error(), "rollback") {
		t.Errorf("an older document: %v", err)
	}
	if !f.Metadata().IdPs["a.fr"].Keys[0].Equal(w.sp.cert) {
		t.Fatal("the federation went back to the older document and its revoked key")
	}

	bad := []byte(strings.Replace(string(newer), "a.fr/r", "b.fr/r", 1)) // breaks the signature
	serve.Store(bad)
	etag.Store(`"v2"`)
	if err := f.Refresh(ctx); err == nil {
		t.Fatal("a document that does not verify was taken")
	}
	if err := f.Refresh(ctx); err == nil {
		t.Error("the same failing document, asked again, was reported as success: its ETag was kept")
	}
}

// A document valid for years is one a replay keeps alive for years.
func TestFederationMaxValidity(t *testing.T) {
	w := newWorld(t)
	far := signedFeed(w, `validUntil="2027-09-29T00:00:00Z"><!--SIG-->`+feedEntity("a.fr", b64(w.sp.cert.Raw))+`</md:EntitiesDescriptor>`)
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) { rw.Write(far) }))
	defer srv.Close()
	f := &Federation{URL: srv.URL, Cert: w.idp.cert, Now: func() time.Time { return judgeNow }}
	if err := f.Refresh(context.Background()); err == nil || !strings.Contains(err.Error(), "more than") {
		t.Errorf("valid for a year: %v", err)
	}
	f.MaxValidity = -1
	if err := f.Refresh(context.Background()); err != nil {
		t.Errorf("with no bound: %v", err)
	}
}

// Run refreshes at once, not after its first wait.
func TestFederationRunRefreshesAtOnce(t *testing.T) {
	w := newWorld(t)
	doc := signedFeed(w, `validUntil="2026-10-12T00:00:00Z"><!--SIG-->`+feedEntity("a.fr", b64(w.sp.cert.Raw))+`</md:EntitiesDescriptor>`)
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) { rw.Write(doc) }))
	defer srv.Close()
	f := &Federation{URL: srv.URL, Cert: w.idp.cert, Now: func() time.Time { return judgeNow }}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go f.Run(ctx, nil)
	for i := 0; f.Metadata() == nil; i++ {
		if i == 100 {
			t.Fatal("Run did not refresh at once")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// ⛔ A response answers a request: none, and every check that ties it to one
// compares two empty strings -- an IdP-initiated response, accepted.
func TestUnsolicitedRefused(t *testing.T) {
	w := newWorld(t)
	a := defaultAssertion()
	a.InResponseTo = ""
	b := w.build(a, response{signAssertion: true, tamper: func(s string) string {
		return strings.Replace(s, ` InResponseTo="_req0123456789"`, "", 1)
	}})
	if _, err := w.newSP().Accept(b, Pending{IdP: idpEntity}); err == nil || !strings.Contains(err.Error(), "unsolicited") {
		t.Errorf("an unsolicited response: %v", err)
	}
	// And a request left open past maxPendingAge.
	p := w.pending
	p.Issued = judgeNow.Add(-maxPendingAge - time.Minute)
	if _, err := w.newSP().Accept(w.build(defaultAssertion(), response{signResponse: true}), p); err == nil {
		t.Error("a request two hours old was answered")
	}
}

// ForceAuthn asked: an authentication from before the request is refused,
// not believed.
func TestForceAuthnHeld(t *testing.T) {
	for _, force := range []bool{true, false} {
		w := newWorld(t)
		p := w.pending
		p.ForceAuthn = force
		p.Issued = judgeNow.Add(10 * time.Minute) // after the assertion's AuthnInstant, past the skew
		_, err := w.newSP().Accept(w.build(defaultAssertion(), response{signResponse: true}), p)
		if force && (err == nil || !strings.Contains(err.Error(), "forced")) {
			t.Errorf("forced, and an older authentication: %v", err)
		}
		if !force && err != nil {
			t.Errorf("the control, not forced: %v", err)
		}
	}
}

// subject-id and pairwise-id have a grammar; a value outside it is not one.
func TestSubjectIDSyntax(t *testing.T) {
	w := newWorld(t)
	a := defaultAssertion()
	a.Attributes[SubjectID] = []string{"a b@" + scope}
	got, err := w.newSP().Accept(w.build(a, response{signResponse: true}), w.pending)
	if err != nil {
		t.Fatal(err)
	}
	if _, from := got.Subject(); from == SubjectID {
		t.Errorf("a subject-id with a space in it was taken: %v", got.Attributes[SubjectID])
	}
}
