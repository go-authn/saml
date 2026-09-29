// SPDX-License-Identifier: BSD-3-Clause

package saml

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/beevik/etree"
	xrv "github.com/mattermost/xml-roundtrip-validator"
	dsig "github.com/russellhaering/goxmldsig"
)

// The namespaces this package reads. An element is identified by its
// namespace URI and local name, never by its prefix: the prefix is whatever
// the sender chose, and "saml:Assertion" in one document is "ns2:Assertion"
// in another.
const (
	nsAssertion = "urn:oasis:names:tc:SAML:2.0:assertion"
	nsProtocol  = "urn:oasis:names:tc:SAML:2.0:protocol"
	nsMetadata  = "urn:oasis:names:tc:SAML:2.0:metadata"
	nsDSig      = "http://www.w3.org/2000/09/xmldsig#"
	nsXEnc      = "http://www.w3.org/2001/04/xmlenc#"
	nsXEnc11    = "http://www.w3.org/2009/xmlenc11#"
	nsShibMD    = "urn:mace:shibboleth:metadata:1.0"
	nsMDUI      = "urn:oasis:names:tc:SAML:metadata:ui"
	nsMDAttr    = "urn:oasis:names:tc:SAML:metadata:attribute"
	nsIdPDisco  = "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol"
	nsXSI       = "http://www.w3.org/2001/XMLSchema-instance"

	protocolSAML2 = "urn:oasis:names:tc:SAML:2.0:protocol"

	bindingRedirect = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
	bindingPOST     = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"

	statusSuccess = "urn:oasis:names:tc:SAML:2.0:status:Success"
	cmBearer      = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
	formatEntity  = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
)

// parse reads a document that somebody else wrote, and refuses the ones whose
// meaning changes between reading and writing.
//
// ⛔ encoding/xml -- which etree and goxmldsig both sit on -- had three bugs
// (CVE-2020-29509/29510/29511) in which a document did not survive a round
// trip: the element or attribute a signature covered was not the one the
// application read. xml-roundtrip-validator exists to refuse exactly those
// documents, and it is cheap next to what it guards.
func parse(data []byte) (*etree.Element, error) {
	if err := xrv.Validate(bytes.NewReader(data)); err != nil {
		return nil, fmt.Errorf("the document does not survive a round trip: %w", err)
	}
	doc := etree.NewDocument()
	// No entities: a DOCTYPE with an internal subset is how a document asks
	// its reader to expand things, and nothing in SAML needs one.
	doc.ReadSettings.Entity = nil
	if err := doc.ReadFromBytes(data); err != nil {
		return nil, err
	}
	for _, t := range doc.Child {
		if _, ok := t.(*etree.Directive); ok {
			return nil, errors.New("a document with a DOCTYPE is refused")
		}
	}
	root := doc.Root()
	if root == nil {
		return nil, errors.New("the document is empty")
	}
	return root, nil
}

// is says whether el is the element {ns}tag.
func is(el *etree.Element, ns, tag string) bool {
	return el != nil && el.Tag == tag && el.NamespaceURI() == ns
}

// children are el's child elements named {ns}tag, in order.
func children(el *etree.Element, ns, tag string) []*etree.Element {
	var out []*etree.Element
	for _, c := range el.ChildElements() {
		if is(c, ns, tag) {
			out = append(out, c)
		}
	}
	return out
}

// child is el's only child named {ns}tag. More than one is an error, not a
// choice: a reader that takes the first where a signer meant the last is how
// a document says two things at once.
func child(el *etree.Element, ns, tag string) (*etree.Element, error) {
	c := children(el, ns, tag)
	switch len(c) {
	case 0:
		return nil, fmt.Errorf("no <%s> in <%s>", tag, el.Tag)
	case 1:
		return c[0], nil
	}
	return nil, fmt.Errorf("%d <%s> in <%s>, where one is allowed", len(c), tag, el.Tag)
}

// optional is el's child named {ns}tag, nil when there is none, and an error
// when there are several.
func optional(el *etree.Element, ns, tag string) (*etree.Element, error) {
	c := children(el, ns, tag)
	if len(c) > 1 {
		return nil, fmt.Errorf("%d <%s> in <%s>, where at most one is allowed", len(c), tag, el.Tag)
	}
	if len(c) == 0 {
		return nil, nil
	}
	return c[0], nil
}

// descendants are every element under el named {ns}tag, el excluded.
func descendants(el *etree.Element, ns, tag string) []*etree.Element {
	var out []*etree.Element
	for _, c := range el.ChildElements() {
		if is(c, ns, tag) {
			out = append(out, c)
		}
		out = append(out, descendants(c, ns, tag)...)
	}
	return out
}

func text(el *etree.Element) string { return strings.TrimSpace(el.Text()) }

// detach copies el out of its document, carrying along the namespace
// declarations it inherited: an Assertion inside a Response usually writes
// "saml:" with the declaration on the Response, and a copy that lost it could
// neither resolve its own names nor be canonicalised. Exclusive
// canonicalisation only emits the declarations an element visibly uses, so
// adding the inherited ones does not change what the signature covers.
func detach(el *etree.Element) *etree.Element {
	c := el.Copy()
	declared := map[string]bool{}
	for _, a := range c.Attr {
		if a.Space == "xmlns" || (a.Space == "" && a.Key == "xmlns") {
			declared[a.FullKey()] = true
		}
	}
	for p := el.Parent(); p != nil; p = p.Parent() {
		for _, a := range p.Attr {
			if !(a.Space == "xmlns" || (a.Space == "" && a.Key == "xmlns")) || declared[a.FullKey()] {
				continue
			}
			declared[a.FullKey()] = true
			c.CreateAttr(a.FullKey(), a.Value)
		}
	}
	return c
}

// instant reads an xs:dateTime. SAML requires UTC (saml-core 1.3.3), and a
// time without a zone is refused rather than guessed.
func instant(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("%q is not a SAML time: %w", s, err)
	}
	return t, nil
}

// The signature and digest algorithms a signature may use, as an allowlist.
// SHA-1 is not here: a signature over a SHA-1 digest is a signature over a
// value somebody else can collide with, and neither RENATER's metadata nor a
// Shibboleth IdP's default configuration uses it.
var (
	signatureMethods = map[string]bool{
		"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256":   true,
		"http://www.w3.org/2001/04/xmldsig-more#rsa-sha384":   true,
		"http://www.w3.org/2001/04/xmldsig-more#rsa-sha512":   true,
		"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256": true,
		"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384": true,
		"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512": true,
	}
	digestMethods = map[string]bool{
		"http://www.w3.org/2001/04/xmlenc#sha256":       true,
		"http://www.w3.org/2001/04/xmldsig-more#sha384": true,
		"http://www.w3.org/2001/04/xmlenc#sha512":       true,
	}
)

// verify checks the enveloped signature on el against the keys, and returns
// the element the signature covers.
//
// ⛔ The RETURNED element is the only one that may be read afterwards. It is
// rebuilt from the bytes the digest was computed over, so nothing that was
// not signed can be in it; the element that was passed in is the document as
// it arrived, and a document can carry a signed element and an unsigned one
// with the same name side by side. Reading the second after checking the
// first is XML signature wrapping, the attack most SAML libraries have had at
// least once.
//
// The keys are trusted because the metadata names them, which is how SAML
// federations work: a self-signed certificate is the usual way to carry a
// key, and its validity dates say nothing a federation relies on. So each key
// is tried with the clock set inside its own validity period, which is the
// only way to make goxmldsig ignore dates it would otherwise enforce.
func verify(el *etree.Element, keys []*x509.Certificate) (*etree.Element, error) {
	if len(keys) == 0 {
		return nil, errors.New("no signing key is known for the signer")
	}
	id := el.SelectAttrValue("ID", "")
	if id == "" {
		return nil, fmt.Errorf("<%s> has no ID, so no signature can cover it", el.Tag)
	}
	sigs := 0
	for _, s := range children(el, nsDSig, "Signature") {
		sigs++
		if err := algorithms(s); err != nil {
			return nil, err
		}
	}
	if sigs != 1 {
		return nil, fmt.Errorf("<%s> carries %d signatures, where exactly one is required", el.Tag, sigs)
	}
	var last error
	for _, k := range keys {
		ctx := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{k}})
		ctx.IdAttribute = "ID"
		ctx.Clock = dsig.NewFakeClockAt(k.NotBefore.Add(time.Second))
		got, err := ctx.Validate(el)
		if err == nil {
			// The signature covered SOME element with this ID. It has to be
			// this one: same name, same ID.
			if got.Tag != el.Tag || got.NamespaceURI() != el.NamespaceURI() || got.SelectAttrValue("ID", "") != id {
				return nil, errors.New("the signature covers a different element")
			}
			return got, nil
		}
		last = err
	}
	return nil, fmt.Errorf("the signature does not verify with any key the signer published: %w", last)
}

// algorithms refuses a signature whose algorithms are not on the allowlist,
// before any cryptography runs.
func algorithms(sig *etree.Element) error {
	si, err := child(sig, nsDSig, "SignedInfo")
	if err != nil {
		return err
	}
	sm, err := child(si, nsDSig, "SignatureMethod")
	if err != nil {
		return err
	}
	if a := sm.SelectAttrValue("Algorithm", ""); !signatureMethods[a] {
		return fmt.Errorf("signature algorithm %q is not accepted", a)
	}
	refs := children(si, nsDSig, "Reference")
	if len(refs) != 1 {
		return fmt.Errorf("a signature with %d references, where one is required", len(refs))
	}
	dm, err := child(refs[0], nsDSig, "DigestMethod")
	if err != nil {
		return err
	}
	if a := dm.SelectAttrValue("Algorithm", ""); !digestMethods[a] {
		return fmt.Errorf("digest algorithm %q is not accepted", a)
	}
	return nil
}
