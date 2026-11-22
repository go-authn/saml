// SPDX-License-Identifier: BSD-3-Clause

// Tests of the 2026-11-21 audit's suspicions (see the CHANGELOG).

package saml

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/go-authn/saml/samltest"
)

// signedResponse builds a Response that carries the signature of method over
// itself. With nested false the signature is where the schema puts it, a
// direct child. With nested true it is moved under an <Extensions> element,
// and a decoy direct <ds:Signature> that names only allow-listed algorithms
// stands where the real one was: what the allow-list inspects is the decoy,
// what goxmldsig verifies is the first signature in document order that
// references the response, the nested one. The enveloped-signature transform
// removes the signature it found wherever it is, so the digest still holds.
func signedResponse(t *testing.T, p *samltest.Party, method string, nested bool) *etree.Element {
	t.Helper()
	resp := etree.NewElement("samlp:Response")
	resp.CreateAttr("xmlns:samlp", nsProtocol)
	resp.CreateAttr("ID", "_r1")
	ext := resp.CreateElement("samlp:Extensions")
	if nested {
		decoy := resp.CreateElement("ds:Signature")
		decoy.CreateAttr("xmlns:ds", nsDSig)
		si := decoy.CreateElement("ds:SignedInfo")
		si.CreateElement("ds:SignatureMethod").CreateAttr("Algorithm", dsig.RSASHA256SignatureMethod)
		ref := si.CreateElement("ds:Reference")
		ref.CreateAttr("URI", "#_r1")
		ref.CreateElement("ds:DigestMethod").CreateAttr("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256")
	}
	ctx, err := dsig.NewSigningContext(p.Key, [][]byte{p.Cert.Raw})
	if err != nil {
		t.Fatal(err)
	}
	if err := ctx.SetSignatureMethod(method); err != nil {
		t.Fatal(err)
	}
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	ctx.IdAttribute = "ID"
	sig, err := ctx.ConstructSignature(resp, true)
	if err != nil {
		t.Fatal(err)
	}
	if nested {
		ext.AddChild(sig)
	} else {
		resp.InsertChildAt(0, sig)
	}
	return resp
}

// goxmldsig v1.6.1 findSignature walks every descendant and takes the first
// signature that references the root; verify inspected the algorithms of the
// direct children only. A response whose signature is a SHA-1 one, nested,
// passed the allow-list that exists to refuse SHA-1.
func TestANestedSHA1SignatureDoesNotSlipPastTheAllowList(t *testing.T) {
	p, err := samltest.NewParty("idp")
	if err != nil {
		t.Fatal(err)
	}
	keys := []*x509.Certificate{p.Cert}

	// Controls: the honest shapes behave as before.
	if _, err := verify(signedResponse(t, p, dsig.RSASHA256SignatureMethod, false), keys); err != nil {
		t.Fatalf("an honest SHA-256 signature was refused: %v", err)
	}
	if _, err := verify(signedResponse(t, p, dsig.RSASHA1SignatureMethod, false), keys); err == nil {
		t.Fatal("a direct SHA-1 signature was accepted")
	}

	// The suspicion.
	if _, err := verify(signedResponse(t, p, dsig.RSASHA1SignatureMethod, true), keys); err == nil {
		t.Error("a nested SHA-1 signature, with an allow-listed decoy beside it, was accepted")
	}
	// A nested signature of an allowed algorithm is just as much a second
	// signature over the response: refused for the shape, not the algorithm.
	if _, err := verify(signedResponse(t, p, dsig.RSASHA256SignatureMethod, true), keys); err == nil {
		t.Error("a nested signature next to a direct decoy was accepted")
	}
}

// replayAt accepts the same response at two instants, with the SP's clock and
// the replay cache's clock moved together, and returns the second verdict.
func replayAt(t *testing.T, a assertion, first, second time.Time) error {
	t.Helper()
	w := newWorld(t)
	clock := first
	sp := w.newSP()
	sp.Now = func() time.Time { return clock }
	replay := NewMemoryReplay()
	replay.now = func() time.Time { return clock }
	sp.Replay = replay
	body := w.build(a, response{signResponse: true})
	if _, err := sp.Accept(body, w.pending); err != nil {
		t.Fatalf("the first delivery was refused: %v", err)
	}
	clock = second
	_, err := sp.Accept(body, w.pending)
	return err
}

// The replay entry lived until the FIRST bearer confirmation's NotOnOrAfter,
// but the response is acceptable until the first one that still holds: a
// second confirmation with a later NotOnOrAfter kept it deliverable after the
// entry was evicted (saml-profiles 4.1.4.5: remember the ID "for the length
// of time for which the assertion would be considered valid").
func TestASecondConfirmationDoesNotOutliveTheReplayEntry(t *testing.T) {
	a := defaultAssertion()
	a.ConfirmUntil = judgeNow.Add(5 * time.Minute)
	a.NotOnOrAfter = judgeNow.Add(30 * time.Minute)
	a.MoreConfirmations = `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData Recipient="` +
		acsURL + `" InResponseTo="_req0123456789" NotOnOrAfter="` + judgeNow.Add(20*time.Minute).Format(time.RFC3339) + `"/></saml:SubjectConfirmation>`
	// Past the first confirmation and its skew, inside the second.
	if err := replayAt(t, a, judgeNow, judgeNow.Add(10*time.Minute)); err == nil {
		t.Error("the response was delivered a second time after its replay entry was evicted")
	}
}

// Control: with one confirmation the entry already covers the skew window
// (NotOnOrAfter plus the clock skew), which is what the response is accepted
// for.
func TestTheReplayEntryCoversTheSkewWindow(t *testing.T) {
	a := defaultAssertion() // NotOnOrAfter judgeNow+5m, the default skew is 3m
	if err := replayAt(t, a, judgeNow, judgeNow.Add(6*time.Minute)); err == nil {
		t.Error("the response was delivered a second time inside the skew window")
	}
	// Control: after the skew window it is refused for being expired.
	if err := replayAt(t, a, judgeNow, judgeNow.Add(9*time.Minute)); err == nil {
		t.Error("an expired response was accepted")
	}
}

// Many IdPs (ADFS, Okta, Shibboleth by option) sign BOTH the Response and the
// Assertion inside it: a ds:Signature at Response/Signature and another at
// Response/Assertion/Signature. The assertion's signature references the
// assertion, not the response, so the nested-signature refusal must not touch
// it: the layout stays accepted with SHA-256, and a SHA-1 signature at either
// level is still refused.
func TestASignatureOnBothTheResponseAndTheAssertionStaysAccepted(t *testing.T) {
	w := newWorld(t)
	got, err := w.newSP().Accept(w.build(defaultAssertion(), response{signResponse: true, signAssertion: true}), w.pending)
	if err != nil {
		t.Fatalf("a Response and an Assertion both signed with RSA-SHA256 was refused: %v", err)
	}
	if got == nil {
		t.Fatal("no result")
	}
	w2 := newWorld(t)
	if _, err := w2.newSP().Accept(w2.build(defaultAssertion(), response{signResponse: true, signAssertion: true,
		sigMethod: rsaSHA1, digest: dSHA1}), w2.pending); err == nil {
		t.Error("both signed with SHA-1 was accepted")
	}
}
