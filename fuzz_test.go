// SPDX-License-Identifier: BSD-3-Clause

package saml

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/base64"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"

	"github.com/go-authn/saml/samltest"
)

// The fuzzers hold one property each: whatever the input, nothing that was
// not signed (or sealed) comes out as if it had been. Each is seeded with the
// genuine article from samltest, so the property is tested at the boundary
// between accepted and refused, not only in the refused desert. The corpus
// (testdata/fuzz) is replayed by every `go test`; `go test -fuzz FuzzAccept`
// grows it.

const (
	fzIdP    = "https://idp.univ-ex.example/idp/shibboleth"
	fzScope  = "univ-ex.example"
	fzSP     = "https://sp.example/saml"
	fzACS    = "https://sp.example/saml/acs"
	fzReq    = "_0123456789abcdef0123456789abcdef01234567"
	fzSigned = "mallory@" + fzScope // what the IdP signed
	fzEvil   = "victim@" + fzScope  // what the fuzzer wants it to say
)

type fzWorld struct {
	md     *Metadata
	sp     *samltest.Party
	fed    *samltest.Party
	at     time.Time
	clear  []byte // a Response around an assertion signed in the clear
	sealed []byte // a signed Response around an encrypted (GCM) assertion
	mdXML  []byte
}

func newFzWorld(tb testing.TB) *fzWorld {
	tb.Helper()
	party := func(name string) *samltest.Party {
		p, err := samltest.NewParty(name)
		if err != nil {
			tb.Fatal(err)
		}
		return p
	}
	w := &fzWorld{sp: party("sp"), fed: party("federation"), at: time.Now()}
	idp := &samltest.IdP{EntityID: fzIdP, Scope: fzScope, SSO: "https://" + fzScope + "/SSO", Signer: party("idp")}
	var err error
	if w.mdXML, err = (&samltest.Federation{Signer: w.fed, IdPs: []*samltest.IdP{idp}}).Metadata(24 * time.Hour); err != nil {
		tb.Fatal(err)
	}
	if w.md, err = ParseMetadata(w.mdXML, w.fed.Cert, w.at); err != nil {
		tb.Fatal(err)
	}
	a := samltest.Assertion{InResponseTo: fzReq, SP: fzSP, ACS: fzACS, Now: w.at, Lifetime: time.Hour,
		Attributes: []samltest.Attribute{{Name: samltest.EPPN, Values: []string{fzSigned}}}}
	decode := func(s string, err error) []byte {
		if err != nil {
			tb.Fatal(err)
		}
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			tb.Fatal(err)
		}
		return b
	}
	w.clear = decode(idp.Response(a))
	a.EncryptTo = w.sp.Cert
	w.sealed = decode(idp.Response(a))
	return w
}

// newSP is a fresh SP, so that the replay cache does not make the same input
// refused the second time.
func (w *fzWorld) newSP() *SP {
	return &SP{EntityID: fzSP, ACS: fzACS, Key: w.sp.Key, Cert: w.sp.Cert, Federation: w.md,
		Now: func() time.Time { return w.at.Add(time.Second) }}
}

func (w *fzWorld) accept(doc []byte) (*Assertion, error) {
	p := Pending{ID: fzReq, IdP: fzIdP, Issued: w.at}
	return w.newSP().Accept(base64.StdEncoding.EncodeToString(doc), p)
}

// FuzzAccept: a response the fuzzer rearranged is refused, or says exactly
// what the IdP signed -- mallory, from this IdP, and nothing else. Seeded with
// both shapes an IdP sends and with the signature-wrapping layouts XSW1-8.
func FuzzAccept(f *testing.F) {
	w := newFzWorld(f)
	for _, doc := range [][]byte{w.clear, w.sealed} {
		if _, err := w.accept(doc); err != nil {
			f.Fatalf("a genuine response is refused: %v", err)
		}
		f.Add(doc)
	}
	for _, doc := range xsw(f, string(w.clear)) {
		f.Add([]byte(doc))
	}
	f.Add([]byte(`<!DOCTYPE r [<!ENTITY a "a">]>` + string(w.clear)))
	f.Fuzz(func(t *testing.T, doc []byte) {
		a, err := w.accept(doc)
		if err != nil {
			return
		}
		if a.IdP.EntityID != fzIdP {
			t.Fatalf("accepted from %q", a.IdP.EntityID)
		}
		if got := a.Attributes[EduPersonPrincipalName]; !reflect.DeepEqual(got, []string{fzSigned}) {
			t.Fatalf("accepted, saying eppn=%q, which nobody signed", got)
		}
		for name, vals := range a.Attributes {
			if name != EduPersonPrincipalName {
				t.Fatalf("accepted, with an attribute %q=%q nobody signed", name, vals)
			}
		}
	})
}

// xsw builds the eight signature-wrapping layouts (Somorovsky et al., "On
// Breaking SAML", 2012; XSW1-8) around the signed assertion of a genuine
// response, each carrying an evil copy that says fzEvil. They are seeds: the
// property is that none is accepted as saying fzEvil.
func xsw(tb testing.TB, resp string) []string {
	tb.Helper()
	i := strings.Index(resp, "<saml:Assertion")
	end := "</saml:Assertion>"
	j := strings.LastIndex(resp, end) + len(end)
	if i < 0 || j < len(end) {
		tb.Fatal("the seed has no saml:Assertion")
	}
	orig := resp[i:j]
	evil := strings.Replace(orig, fzSigned, fzEvil, 1)
	evilID := strings.Replace(evil, `ID="`, `ID="_evil`, 1)
	// The evil assertion with its signature removed.
	k, l := strings.Index(evil, "<ds:Signature"), strings.Index(evil, "</ds:Signature>")
	unsigned := evil
	if k >= 0 && l > k {
		unsigned = evil[:k] + evil[l+len("</ds:Signature>"):]
	}
	return []string{
		resp[:i] + evil + orig + resp[j:],                                                  // evil first
		resp[:i] + orig + evil + resp[j:],                                                  // evil last (XSW1/XSW5 flavour)
		resp[:i] + unsigned + orig + resp[j:],                                              // XSW3: unsigned evil before
		resp[:i] + "<samlp:Extensions>" + orig + "</samlp:Extensions>" + evilID + resp[j:], // XSW4/6
		resp[:i] + "<saml:Advice>" + orig + "</saml:Advice>" + evilID + resp[j:],           // XSW7/8
		resp[:i] + strings.Replace(evilID, "</saml:Subject>", "</saml:Subject><saml:Advice>"+orig+"</saml:Advice>", 1) + resp[j:],
		strings.Replace(resp, fzSigned, fzEvil, 1), // tampered after signing
		resp[:i] + "<samlp:Extensions>" + evil + "</samlp:Extensions>" + orig + resp[j:],
	}
}

// FuzzParseMetadata: metadata the fuzzer rearranged is refused, or names
// exactly the IdP the federation signed, with its key, scope and SSO.
func FuzzParseMetadata(f *testing.F) {
	w := newFzWorld(f)
	want := w.md.IdPs[fzIdP]
	f.Add(w.mdXML)
	f.Add([]byte(strings.Replace(string(w.mdXML), fzScope+"<", "evil.example<", 1)))
	f.Add([]byte(`<!DOCTYPE r [<!ENTITY a "a">]>` + string(w.mdXML)))
	f.Fuzz(func(t *testing.T, doc []byte) {
		md, err := ParseMetadata(doc, w.fed.Cert, w.at)
		if err != nil {
			return
		}
		if len(md.IdPs) != 1 {
			t.Fatalf("accepted with %d IdPs", len(md.IdPs))
		}
		got, ok := md.IdPs[fzIdP]
		if !ok {
			t.Fatalf("accepted, naming an IdP nobody signed: %v", md.IdPs)
		}
		if !slices.Equal(got.Scopes, want.Scopes) || len(got.Keys) != len(want.Keys) || !got.Keys[0].Equal(want.Keys[0]) || got.SSO != want.SSO {
			t.Fatalf("accepted, with scopes %q keys %d sso %q, not what was signed", got.Scopes, len(got.Keys), got.SSO)
		}
	})
}

// cbcAssertion encrypts plain to the SP's key the way an older IdP does:
// AES-128-CBC, the key wrapped with RSA-OAEP (MGF1-SHA1).
func cbcAssertion(tb testing.TB, plain []byte, pub *rsa.PublicKey) []byte {
	tb.Helper()
	key, iv := make([]byte, 16), make([]byte, 16)
	rand.Read(key)
	rand.Read(iv)
	block, _ := aes.NewCipher(key)
	n := 16 - len(plain)%16
	padded := append(bytes.Clone(plain), bytes.Repeat([]byte{byte(n)}, n)...)
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)
	wrapped, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, pub, key, nil)
	if err != nil {
		tb.Fatal(err)
	}
	b64 := base64.StdEncoding.EncodeToString
	return []byte(`<saml:EncryptedAssertion xmlns:saml="` + nsAssertion + `" xmlns:xenc="` + nsXEnc + `" xmlns:ds="` + nsDSig + `">` +
		`<xenc:EncryptedData Type="http://www.w3.org/2001/04/xmlenc#Element">` +
		`<xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"/>` +
		`<ds:KeyInfo><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="` + oaepMGF1P + `"/>` +
		`<xenc:CipherData><xenc:CipherValue>` + b64(wrapped) + `</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo>` +
		`<xenc:CipherData><xenc:CipherValue>` + b64(append(iv, ct...)) + `</xenc:CipherValue></xenc:CipherData>` +
		`</xenc:EncryptedData></saml:EncryptedAssertion>`)
}

// FuzzDecrypt: decrypt on its own. The input is an EncryptedAssertion and one
// byte (whether a verified signature covered it). Properties: it never
// panics; CBC is never opened when nothing authenticated it (the padding
// oracle); and what it opens is, byte for byte, an assertion somebody sealed
// -- GCM authenticates, so a rearranged ciphertext cannot yield another.
// Seeded with GCM (samltest, keys inside EncryptedData's KeyInfo), CBC, and
// the EncryptedKey beside EncryptedData.
func FuzzDecrypt(f *testing.F) {
	w := newFzWorld(f)
	sp := w.newSP()
	root, err := parse(w.sealed, responseLimits)
	if err != nil {
		f.Fatal(err)
	}
	gcm := children(root, nsAssertion, "EncryptedAssertion")[0]
	plainRoot, err := sp.decrypt(gcm, true)
	if err != nil {
		f.Fatalf("a genuine encrypted assertion does not open: %v", err)
	}
	doc := etree.NewDocument()
	doc.SetRoot(plainRoot.Copy())
	plain, _ := doc.WriteToBytes()
	sealed := map[string]bool{string(plain): true}

	gcmXML := etree.NewDocument()
	gcmXML.SetRoot(detach(gcm))
	gcmBytes, _ := gcmXML.WriteToBytes()
	cbc := cbcAssertion(f, plain, &w.sp.Key.PublicKey)
	if _, err := sp.decrypt(mustEA(f, cbc), true); err != nil {
		f.Fatalf("the CBC seed does not open: %v", err)
	}
	// The EncryptedKey beside EncryptedData rather than inside its KeyInfo.
	beside := strings.Replace(string(cbc), "<ds:KeyInfo>", "<ds:KeyInfo/>", 1)
	if m, n := strings.Index(string(cbc), "<xenc:EncryptedKey>"), strings.Index(string(cbc), "</xenc:EncryptedKey>"); m > 0 && n > m {
		key := string(cbc)[m : n+len("</xenc:EncryptedKey>")]
		beside = strings.Replace(string(cbc), key, "", 1)
		beside = strings.Replace(beside, "</xenc:EncryptedData>", "</xenc:EncryptedData>"+key, 1)
	}
	for _, s := range [][]byte{gcmBytes, cbc, []byte(beside)} {
		f.Add(s, true)
		f.Add(s, false)
	}
	f.Fuzz(func(t *testing.T, in []byte, authenticated bool) {
		root, err := parse(in, responseLimits)
		if err != nil || !is(root, nsAssertion, "EncryptedAssertion") {
			return
		}
		got, err := sp.decrypt(root, authenticated)
		if err != nil {
			return
		}
		// decrypt read exactly one EncryptedData; which cipher it named
		// decides the property.
		ed, _ := child(root, nsXEnc, "EncryptedData")
		em, _ := child(ed, nsXEnc, "EncryptionMethod")
		isCBC := strings.HasSuffix(em.SelectAttrValue("Algorithm", ""), "-cbc")
		if isCBC && !authenticated {
			t.Fatalf("opened AES-CBC nobody authenticated")
		}
		if isCBC {
			// CBC has no integrity: a signature the caller checks afterwards
			// is what covers it, so only the refusal above is asserted.
			return
		}
		out := etree.NewDocument()
		out.SetRoot(got.Copy())
		b, _ := out.WriteToBytes()
		if !sealed[string(b)] {
			t.Fatalf("opened an assertion nobody sealed: %q", b)
		}
	})
}

func mustEA(tb testing.TB, b []byte) *etree.Element {
	tb.Helper()
	root, err := parse(b, responseLimits)
	if err != nil {
		tb.Fatal(err)
	}
	return root
}

// FuzzLimits: limits.check and parse agree on what is refused, and check
// stays linear. Whatever parse accepts is, measured again by walking the tree,
// inside the limits; and check allocates in proportion to its input, not to
// the shape of it.
func FuzzLimits(f *testing.F) {
	w := newFzWorld(f)
	for _, s := range [][]byte{w.clear, w.sealed, w.mdXML,
		[]byte(strings.Repeat("<a>", 40) + strings.Repeat("</a>", 40)),
		[]byte("<a " + strings.Repeat(`x:y="1" `, 70) + "/>"),
		[]byte("<r>" + strings.Repeat("<e/>", 4100) + "</r>"),
		[]byte("<r " + strings.Repeat(`xmlns:p="u" `, 70) + "/>"),
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, lim := range []limits{responseLimits, metadataLimits} {
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			cerr := lim.check(data)
			runtime.ReadMemStats(&after)
			// Linear: a few words per open element is the stack; 64 bytes per
			// input byte plus a fixed slack is far above any honest cost and
			// far below a quadratic one.
			if grown := after.TotalAlloc - before.TotalAlloc; grown > uint64(64*len(data))+(1<<20) {
				t.Fatalf("check allocated %d bytes for %d bytes of input", grown, len(data))
			}
			root, perr := parse(data, lim)
			if cerr != nil && perr == nil {
				t.Fatalf("check refuses (%v) what parse accepts", cerr)
			}
			if perr != nil {
				continue
			}
			n, depth := 0, 0
			var walk func(e *etree.Element, d int, inScope int)
			walk = func(e *etree.Element, d, inScope int) {
				n++
				depth = max(depth, d)
				attrs, decls := 0, 0
				for _, a := range e.Attr {
					attrs++
					if a.Space == "xmlns" || (a.Space == "" && a.Key == "xmlns") {
						decls++
					}
				}
				if attrs > lim.attributes {
					t.Fatalf("accepted an element with %d attributes", attrs)
				}
				if inScope+decls > lim.inScopeNamespaces {
					t.Fatalf("accepted %d namespace declarations in scope", inScope+decls)
				}
				for _, c := range e.ChildElements() {
					walk(c, d+1, inScope+decls)
				}
			}
			walk(root, 1, 0)
			if depth > lim.depth || (lim.elements > 0 && n > lim.elements) {
				t.Fatalf("accepted depth %d, %d elements", depth, n)
			}
		}
	})
}
