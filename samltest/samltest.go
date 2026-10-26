// SPDX-License-Identifier: BSD-3-Clause

// Package samltest is a SAML federation and identity provider for tests of
// the programs built on github.com/go-authn/saml -- an OpenID provider in
// front of a federation, a service behind one -- in pure Go.
//
// A [Federation] publishes signed metadata for its [IdP]s. An IdP answers
// an AuthnRequest (HTTP-Redirect binding) with a Response over the
// HTTP-POST binding: the Response signed (RSA-SHA256, exclusive
// canonicalisation, enveloped), and the assertion encrypted to the SP's
// certificate (AES-128-GCM, RSA-OAEP with MGF1-SHA1), which are a
// Shibboleth IdP v5's defaults. [IdP.Handler] serves a login form and posts
// the answer back, so a test drives a whole login with an HTTP client.
//
// What it produces is judged by two parties that did not write it:
// xmlsec1 verifies the signatures and decrypts the assertions, and this
// module's SP accepts them (samltest_test.go). It is a test helper: the
// keys are generated, the passwords are whatever the test says, and
// nothing here belongs in production.
package samltest

import (
	"bytes"
	"compress/flate"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"html"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// Attribute names, as a Shibboleth IdP releases them (urn:oid, the
// MACE-Dir names).
const (
	EPPN        = "urn:oid:1.3.6.1.4.1.5923.1.1.1.6"
	Entitlement = "urn:oid:1.3.6.1.4.1.5923.1.1.1.7"
	SubjectID   = "urn:oasis:names:tc:SAML:attribute:subject-id"
	Mail        = "urn:oid:0.9.2342.19200300.100.1.3"
	DisplayName = "urn:oid:2.16.840.1.113730.3.1.241"
)

const (
	nsMetadata  = "urn:oasis:names:tc:SAML:2.0:metadata"
	nsAssertion = "urn:oasis:names:tc:SAML:2.0:assertion"
	nsProtocol  = "urn:oasis:names:tc:SAML:2.0:protocol"
	nsDSig      = "http://www.w3.org/2000/09/xmldsig#"
	nsXEnc      = "http://www.w3.org/2001/04/xmlenc#"
	nsShibMD    = "urn:mace:shibboleth:metadata:1.0"
	nsMDUI      = "urn:oasis:names:tc:SAML:metadata:ui"

	algAES128GCM = "http://www.w3.org/2009/xmlenc11#aes128-gcm"
	algOAEP      = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
	ppt          = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
)

// A Party is a key and its self-signed certificate: a federation's
// metadata signer, an IdP, an SP.
type Party struct {
	Key  *rsa.PrivateKey
	Cert *x509.Certificate
}

// NewParty makes a 2048-bit RSA key and a certificate for it, valid from an
// hour ago for a day.
func NewParty(name string) (*Party, error) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		return nil, err
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &Party{Key: k, Cert: c}, nil
}

// WriteFiles writes the key (PKCS #1, mode 0600) and the certificate as PEM
// into dir, as name.key and name.crt, for programs configured with files.
func (p *Party) WriteFiles(dir, name string) (keyFile, certFile string, err error) {
	keyFile, certFile = filepath.Join(dir, name+".key"), filepath.Join(dir, name+".crt")
	if err = os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(p.Key)}), 0o600); err != nil {
		return "", "", err
	}
	err = os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.Cert.Raw}), 0o644)
	return keyFile, certFile, err
}

// Fingerprint is the certificate's SHA-256 fingerprint, upper-case hex
// pairs separated by colons, as federations publish it.
func (p *Party) Fingerprint() string {
	s := sha256.Sum256(p.Cert.Raw)
	h := strings.ToUpper(hex.EncodeToString(s[:]))
	var parts []string
	for i := 0; i < len(h); i += 2 {
		parts = append(parts, h[i:i+2])
	}
	return strings.Join(parts, ":")
}

// An IdP is one identity provider of the federation.
type IdP struct {
	EntityID string
	// Scope is its shibmd:Scope: the domain its identifiers and groups may
	// be in.
	Scope string
	// SSO is where AuthnRequests go (HTTP-Redirect), as the metadata says.
	SSO string
	// Name is its display name (mdui:DisplayName, French and English).
	Name   string
	Signer *Party
}

// Federation signs metadata listing its IdPs.
type Federation struct {
	Signer *Party
	IdPs   []*IdP
}

// Metadata is the federation's EntitiesDescriptor, signed by f.Signer and
// valid for validFor.
func (f *Federation) Metadata(validFor time.Duration) ([]byte, error) {
	doc := etree.NewDocument()
	root := doc.CreateElement("md:EntitiesDescriptor")
	root.CreateAttr("xmlns:md", nsMetadata)
	root.CreateAttr("xmlns:shibmd", nsShibMD)
	root.CreateAttr("xmlns:mdui", nsMDUI)
	root.CreateAttr("xmlns:ds", nsDSig)
	root.CreateAttr("ID", newID("_fed"))
	root.CreateAttr("validUntil", time.Now().Add(validFor).UTC().Format(time.RFC3339))
	for _, idp := range f.IdPs {
		ed := root.CreateElement("md:EntityDescriptor")
		ed.CreateAttr("entityID", idp.EntityID)
		d := ed.CreateElement("md:IDPSSODescriptor")
		d.CreateAttr("protocolSupportEnumeration", nsProtocol)
		ext := d.CreateElement("md:Extensions")
		if idp.Scope != "" {
			s := ext.CreateElement("shibmd:Scope")
			s.CreateAttr("regexp", "false")
			s.SetText(idp.Scope)
		}
		name := idp.Name
		if name == "" {
			name = idp.EntityID
		}
		ui := ext.CreateElement("mdui:UIInfo")
		for _, lang := range []string{"fr", "en"} {
			n := ui.CreateElement("mdui:DisplayName")
			n.CreateAttr("xml:lang", lang)
			n.SetText(name)
		}
		kd := d.CreateElement("md:KeyDescriptor")
		kd.CreateAttr("use", "signing")
		kd.CreateElement("ds:KeyInfo").CreateElement("ds:X509Data").CreateElement("ds:X509Certificate").
			SetText(base64.StdEncoding.EncodeToString(idp.Signer.Cert.Raw))
		sso := d.CreateElement("md:SingleSignOnService")
		sso.CreateAttr("Binding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect")
		sso.CreateAttr("Location", idp.SSO)
	}
	if err := sign(root, f.Signer, nil); err != nil {
		return nil, err
	}
	return doc.WriteToBytes()
}

// Attribute is one SAML attribute with its values, in order.
type Attribute struct {
	Name   string
	Values []string
}

// Assertion is what the IdP says, and to whom.
type Assertion struct {
	// InResponseTo is the AuthnRequest's ID ([RequestID] reads it).
	InResponseTo string
	// SP is the service provider's entity ID (the Audience), ACS where the
	// response goes (Destination and Recipient).
	SP, ACS string
	// NameID is a transient NameID when empty.
	NameID     string
	Attributes []Attribute
	// AuthnContext is PasswordProtectedTransport when empty.
	AuthnContext string
	// Now is when the IdP answers (time.Now when zero); the assertion is
	// valid for Lifetime after it (five minutes when zero).
	Now      time.Time
	Lifetime time.Duration
	// EncryptTo is the SP's certificate. Nil sends the assertion in the
	// clear, signed itself.
	EncryptTo *x509.Certificate
}

// Response is the IdP's signed Response, base64 as the SAMLResponse form
// field carries it.
func (idp *IdP) Response(a Assertion) (string, error) {
	now := a.Now
	if now.IsZero() {
		now = time.Now()
	}
	if a.Lifetime == 0 {
		a.Lifetime = 5 * time.Minute
	}
	if a.AuthnContext == "" {
		a.AuthnContext = ppt
	}
	if a.NameID == "" {
		a.NameID = newID("t")
	}
	ts := now.Add(-time.Second).UTC().Format(time.RFC3339)
	later := now.Add(a.Lifetime).UTC().Format(time.RFC3339)

	adoc := etree.NewDocument()
	as := adoc.CreateElement("saml:Assertion")
	as.CreateAttr("xmlns:saml", nsAssertion)
	as.CreateAttr("ID", newID("_a"))
	as.CreateAttr("Version", "2.0")
	as.CreateAttr("IssueInstant", ts)
	as.CreateElement("saml:Issuer").SetText(idp.EntityID)
	subj := as.CreateElement("saml:Subject")
	n := subj.CreateElement("saml:NameID")
	n.CreateAttr("Format", "urn:oasis:names:tc:SAML:2.0:nameid-format:transient")
	n.SetText(a.NameID)
	sc := subj.CreateElement("saml:SubjectConfirmation")
	sc.CreateAttr("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer")
	scd := sc.CreateElement("saml:SubjectConfirmationData")
	scd.CreateAttr("Recipient", a.ACS)
	scd.CreateAttr("InResponseTo", a.InResponseTo)
	scd.CreateAttr("NotOnOrAfter", later)
	cond := as.CreateElement("saml:Conditions")
	cond.CreateAttr("NotBefore", ts)
	cond.CreateAttr("NotOnOrAfter", later)
	cond.CreateElement("saml:AudienceRestriction").CreateElement("saml:Audience").SetText(a.SP)
	st := as.CreateElement("saml:AuthnStatement")
	st.CreateAttr("AuthnInstant", ts)
	st.CreateAttr("SessionIndex", newID("_s"))
	st.CreateElement("saml:AuthnContext").CreateElement("saml:AuthnContextClassRef").SetText(a.AuthnContext)
	if len(a.Attributes) > 0 {
		stmt := as.CreateElement("saml:AttributeStatement")
		for _, at := range a.Attributes {
			e := stmt.CreateElement("saml:Attribute")
			e.CreateAttr("Name", at.Name)
			e.CreateAttr("NameFormat", "urn:oasis:names:tc:SAML:2.0:attrname-format:uri")
			for _, v := range at.Values {
				e.CreateElement("saml:AttributeValue").SetText(v)
			}
		}
	}

	doc := etree.NewDocument()
	resp := doc.CreateElement("samlp:Response")
	resp.CreateAttr("xmlns:samlp", nsProtocol)
	resp.CreateAttr("xmlns:saml", nsAssertion)
	resp.CreateAttr("ID", newID("_r"))
	resp.CreateAttr("Version", "2.0")
	resp.CreateAttr("IssueInstant", ts)
	resp.CreateAttr("Destination", a.ACS)
	resp.CreateAttr("InResponseTo", a.InResponseTo)
	resp.CreateElement("saml:Issuer").SetText(idp.EntityID)
	resp.CreateElement("samlp:Status").CreateElement("samlp:StatusCode").CreateAttr("Value", "urn:oasis:names:tc:SAML:2.0:status:Success")

	if a.EncryptTo != nil {
		plain, err := adoc.WriteToBytes()
		if err != nil {
			return "", err
		}
		ea, err := encrypt(plain, a.EncryptTo)
		if err != nil {
			return "", err
		}
		resp.AddChild(ea)
	} else {
		// In the clear the assertion carries its own signature.
		if err := sign(as, idp.Signer, as.SelectElement("Issuer")); err != nil {
			return "", err
		}
		resp.AddChild(as.Copy())
	}
	if err := sign(resp, idp.Signer, resp.SelectElement("Issuer")); err != nil {
		return "", err
	}
	out, err := doc.WriteToBytes()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(out), nil
}

// sign puts an enveloped signature of el, by p, after the element "after"
// (the Issuer, where the SAML schema puts it), or first when after is nil.
func sign(el *etree.Element, p *Party, after *etree.Element) error {
	ctx, err := dsig.NewSigningContext(p.Key, [][]byte{p.Cert.Raw})
	if err != nil {
		return err
	}
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	ctx.IdAttribute = "ID"
	sig, err := ctx.ConstructSignature(el, true)
	if err != nil {
		return err
	}
	at := 0
	if after != nil {
		at = after.Index() + 1
	}
	el.InsertChildAt(at, sig)
	return nil
}

// encrypt wraps an assertion in an EncryptedAssertion: AES-128-GCM over the
// serialised element (XML Encryption 1.1 §5.2.4: 96-bit IV first, tag
// last), the key under RSA-OAEP with MGF1-SHA1 (§5.5.2) in the
// EncryptedData's KeyInfo.
func encrypt(plain []byte, to *x509.Certificate) (*etree.Element, error) {
	pub, ok := to.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("samltest: the SP's certificate holds no RSA key")
	}
	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	block, _ := aes.NewCipher(key)
	g, _ := cipher.NewGCM(block)
	iv := make([]byte, g.NonceSize())
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	ct := g.Seal(iv, iv, plain, nil)
	wrapped, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, pub, key, nil)
	if err != nil {
		return nil, err
	}
	ea := etree.NewElement("saml:EncryptedAssertion")
	ed := ea.CreateElement("xenc:EncryptedData")
	ed.CreateAttr("xmlns:xenc", nsXEnc)
	ed.CreateAttr("Type", nsXEnc+"Element")
	ed.CreateElement("xenc:EncryptionMethod").CreateAttr("Algorithm", algAES128GCM)
	ki := ed.CreateElement("ds:KeyInfo")
	ki.CreateAttr("xmlns:ds", nsDSig)
	ek := ki.CreateElement("xenc:EncryptedKey")
	ek.CreateElement("xenc:EncryptionMethod").CreateAttr("Algorithm", algOAEP)
	ek.CreateElement("xenc:CipherData").CreateElement("xenc:CipherValue").SetText(base64.StdEncoding.EncodeToString(wrapped))
	ed.CreateElement("xenc:CipherData").CreateElement("xenc:CipherValue").SetText(base64.StdEncoding.EncodeToString(ct))
	return ea, nil
}

// RequestID reads the ID of an AuthnRequest sent over the HTTP-Redirect
// binding: the SAMLRequest query parameter, DEFLATE then base64.
func RequestID(samlRequest string) (string, error) {
	z, err := base64.StdEncoding.DecodeString(samlRequest)
	if err != nil {
		return "", fmt.Errorf("samltest: SAMLRequest is not base64: %w", err)
	}
	raw, err := io.ReadAll(io.LimitReader(flate.NewReader(bytes.NewReader(z)), 1<<20))
	if err != nil {
		return "", fmt.Errorf("samltest: SAMLRequest does not inflate: %w", err)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil {
		return "", fmt.Errorf("samltest: SAMLRequest is not XML: %w", err)
	}
	r := doc.Root()
	if r == nil || r.Tag != "AuthnRequest" || r.NamespaceURI() != nsProtocol {
		return "", errors.New("samltest: SAMLRequest is not an AuthnRequest")
	}
	id := r.SelectAttrValue("ID", "")
	if id == "" {
		return "", errors.New("samltest: the AuthnRequest has no ID")
	}
	return id, nil
}

// Login decides who logs in: the attributes released for user, and whether
// the password is right.
type Login func(user, password string) ([]Attribute, bool)

// Handler serves the IdP's SSO endpoint. GET (the HTTP-Redirect binding)
// shows a form with "username" and "password"; POST checks them with login
// and answers with a form that posts SAMLResponse and RelayState to acs --
// what a browser submits by script, and a test client submits as a form.
// The assertion is addressed to sp and encrypted to spCert (nil: signed in
// the clear).
func (idp *IdP) Handler(sp, acs string, spCert *x509.Certificate, login Login) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		req, relay := r.Form.Get("SAMLRequest"), r.Form.Get("RelayState")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if r.Method == http.MethodGet {
			fmt.Fprintf(w, `<!doctype html><html><body><form method="post" action="%s"><input type="hidden" name="SAMLRequest" value="%s"><input type="hidden" name="RelayState" value="%s"><input name="username"><input type="password" name="password"><button type="submit">Log in</button></form></body></html>`,
				html.EscapeString(r.URL.Path), html.EscapeString(req), html.EscapeString(relay))
			return
		}
		attrs, ok := login(r.Form.Get("username"), r.Form.Get("password"))
		if !ok {
			http.Error(w, "wrong user or password", http.StatusUnauthorized)
			return
		}
		id, err := RequestID(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		resp, err := idp.Response(Assertion{InResponseTo: id, SP: sp, ACS: acs, Attributes: attrs, EncryptTo: spCert})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		fmt.Fprintf(w, `<!doctype html><html><body><form method="post" action="%s"><input type="hidden" name="SAMLResponse" value="%s"><input type="hidden" name="RelayState" value="%s"><noscript><button type="submit">Continue</button></noscript></form></body></html>`,
			html.EscapeString(acs), resp, html.EscapeString(relay))
	})
}

func newID(prefix string) string {
	b := make([]byte, 16)
	rand.Read(b)
	return prefix + hex.EncodeToString(b)
}
