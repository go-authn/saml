// SPDX-License-Identifier: BSD-3-Clause

package saml

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The IdP in these tests is xmlsec1 -- the C library Shibboleth's own SP
// and SimpleSAMLphp's ancestors were tested against -- driven from
// templates. It signs and encrypts; this package only verifies and
// decrypts. A response this repository both produced and accepted would
// prove only that its two halves agree with each other.
//
// SAML_REQUIRE_JUDGE=1 turns a missing xmlsec1 from a skip into a failure,
// in the CI lanes that install it.

const (
	idpEntity = "https://idp.univ-example.fr/idp/shibboleth"
	spEntity  = "https://bridge.example.org/saml"
	acsURL    = "https://bridge.example.org/saml/acs"
	scope     = "univ-example.fr"
)

var judgeNow = time.Date(2026, 9, 29, 10, 0, 0, 0, time.UTC)

func xmlsec(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("xmlsec1")
	if err != nil {
		if os.Getenv("SAML_REQUIRE_JUDGE") != "" {
			t.Fatal("xmlsec1 is required here and is not installed")
		}
		t.Skip("xmlsec1 is not installed")
	}
	return p
}

// party is a key and its self-signed certificate, written where xmlsec1 can
// read them.
type party struct {
	key      *rsa.PrivateKey
	cert     *x509.Certificate
	keyFile  string
	certFile string
}

func newParty(t *testing.T, dir, name string) *party {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		// Expired on purpose: federation keys are trusted because metadata
		// names them, and a self-signed certificate's dates mean nothing
		// there. A verifier that enforced them would refuse this IdP.
		NotBefore: time.Date(2015, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:  time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	p := &party{key: k, cert: c, keyFile: filepath.Join(dir, name+".key"), certFile: filepath.Join(dir, name+".crt")}
	os.WriteFile(p.keyFile, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}), 0o600)
	os.WriteFile(p.certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
	return p
}

// world is one IdP, one SP, and a federation containing the IdP.
type world struct {
	t        *testing.T
	dir      string
	xmlsec   string
	idp, sp  *party
	fed      *Metadata
	provider *IdP
	pending  Pending
}

func newWorld(t *testing.T) *world {
	w := &world{t: t, dir: judgeDir(t), xmlsec: xmlsec(t)}
	w.idp = newParty(t, w.dir, "idp")
	w.sp = newParty(t, w.dir, "sp")
	w.provider = &IdP{
		EntityID: idpEntity,
		SSO:      "https://idp.univ-example.fr/idp/profile/SAML2/Redirect/SSO",
		Keys:     []*x509.Certificate{w.idp.cert},
		Scopes:   []string{scope},
		Names:    map[string]string{"fr": "Université Exemple"},
	}
	w.fed = &Metadata{IdPs: map[string]*IdP{idpEntity: w.provider}, ValidUntil: judgeNow.Add(time.Hour)}
	w.pending = Pending{ID: "_req0123456789", IdP: idpEntity, Issued: judgeNow}
	return w
}

func (w *world) newSP() *SP {
	return &SP{
		EntityID:   spEntity,
		ACS:        acsURL,
		Key:        w.sp.key,
		Cert:       w.sp.cert,
		Federation: w.fed,
		Now:        func() time.Time { return judgeNow },
	}
}

// assertion is the fields a test may change.
type assertion struct {
	ID, Issuer, Audience, Recipient, InResponseTo string
	NotOnOrAfter                                  time.Time
	AuthnContext                                  string
	Attributes                                    map[string][]string
	Extra                                         string // raw XML appended to Conditions
}

func defaultAssertion() assertion {
	return assertion{
		ID:           "_a0123456789",
		Issuer:       idpEntity,
		Audience:     spEntity,
		Recipient:    acsURL,
		InResponseTo: "_req0123456789",
		NotOnOrAfter: judgeNow.Add(5 * time.Minute),
		AuthnContext: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
		Attributes: map[string][]string{
			EduPersonPrincipalName:     {"alice@" + scope},
			SubjectID:                  {"A1B2C3@" + scope},
			EduPersonScopedAffiliation: {"member@" + scope, "staff@another-university.fr"},
			Mail:                       {"alice@univ-example.fr"},
			DisplayName:                {"Alice Martin"},
		},
	}
}

const sigTemplate = `<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="%s"/><ds:Reference URI="#%s"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="%s"/><ds:DigestValue/></ds:Reference></ds:SignedInfo><ds:SignatureValue/><ds:KeyInfo><ds:X509Data/></ds:KeyInfo></ds:Signature>`

const (
	rsaSHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	rsaSHA1   = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
	dSHA256   = "http://www.w3.org/2001/04/xmlenc#sha256"
	dSHA1     = "http://www.w3.org/2000/09/xmldsig#sha1"
)

func (a assertion) xml(signed bool) string {
	var attrs strings.Builder
	for name, vals := range a.Attributes {
		fmt.Fprintf(&attrs, `<saml:Attribute Name="%s" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">`, name)
		for _, v := range vals {
			fmt.Fprintf(&attrs, `<saml:AttributeValue>%s</saml:AttributeValue>`, v)
		}
		attrs.WriteString(`</saml:Attribute>`)
	}
	sig := ""
	if signed {
		sig = fmt.Sprintf(sigTemplate, rsaSHA256, a.ID, dSHA256)
	}
	ts := judgeNow.Add(-time.Second).Format(time.RFC3339)
	return fmt.Sprintf(`<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="%s" Version="2.0" IssueInstant="%s">`+
		`<saml:Issuer>%s</saml:Issuer>%s`+
		`<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">AAdzZWNyZXQx</saml:NameID>`+
		`<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData Recipient="%s" InResponseTo="%s" NotOnOrAfter="%s"/></saml:SubjectConfirmation></saml:Subject>`+
		`<saml:Conditions NotBefore="%s" NotOnOrAfter="%s"><saml:AudienceRestriction><saml:Audience>%s</saml:Audience></saml:AudienceRestriction>%s</saml:Conditions>`+
		`<saml:AuthnStatement AuthnInstant="%s" SessionIndex="_s1"><saml:AuthnContext><saml:AuthnContextClassRef>%s</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>`+
		`<saml:AttributeStatement>%s</saml:AttributeStatement></saml:Assertion>`,
		a.ID, ts, a.Issuer, sig, a.Recipient, a.InResponseTo, a.NotOnOrAfter.Format(time.RFC3339),
		ts, a.NotOnOrAfter.Format(time.RFC3339), a.Audience, a.Extra, ts, a.AuthnContext, attrs.String())
}

// response describes how the IdP wraps the assertion.
type response struct {
	signResponse, signAssertion bool
	// encrypt is "", or a content algorithm URI.
	encrypt string
	// keyTransport is the EncryptionMethod of the EncryptedKey, with any
	// children, as raw XML.
	keyTransport string
	status       string // raw StatusCode XML; Success when empty
	sigMethod    string
	digest       string
	destination  string
	inResponseTo string
	// tamper edits the final bytes, after every signature.
	tamper func(string) string
}

const oaepMGF1PTransport = `<xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"><ds:DigestMethod xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/></xenc:EncryptionMethod>`

func (w *world) run(args ...string) []byte {
	w.t.Helper()
	out, err := exec.Command(w.xmlsec, args...).CombinedOutput()
	if err != nil {
		w.t.Fatalf("xmlsec1 %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

func (w *world) file(name, content string) string {
	p := filepath.Join(w.dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		w.t.Fatal(err)
	}
	return p
}

// build has xmlsec1 produce the response, and returns it base64-encoded as
// the ACS receives it.
func (w *world) build(a assertion, r response) string {
	w.t.Helper()
	if r.sigMethod == "" {
		r.sigMethod = rsaSHA256
	}
	if r.digest == "" {
		r.digest = dSHA256
	}
	if r.destination == "" {
		r.destination = acsURL
	}
	if r.inResponseTo == "" {
		r.inResponseTo = w.pending.ID
	}
	if r.status == "" {
		r.status = `<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>`
	}

	// 1. The assertion, signed by itself if asked.
	ax := a.xml(r.signAssertion)
	if r.signAssertion {
		in := w.file("assertion.xml", ax)
		ax = string(w.run("--sign", "--lax-key-search", "--privkey-pem", w.idp.keyFile+","+w.idp.certFile,
			"--id-attr:ID", "urn:oasis:names:tc:SAML:2.0:assertion:Assertion", "--output", "/dev/stdout", in))
		ax = stripDecl(ax)
	}

	// 2. Wrapped, and encrypted to the SP if asked.
	body := ax
	if r.encrypt != "" {
		kt := r.keyTransport
		if kt == "" {
			kt = oaepMGF1PTransport
		}
		tmpl := w.file("enc-template.xml", fmt.Sprintf(
			`<xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" Type="http://www.w3.org/2001/04/xmlenc#Element">`+
				`<xenc:EncryptionMethod Algorithm="%s"/>`+
				`<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><xenc:EncryptedKey>%s<xenc:CipherData><xenc:CipherValue/></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo>`+
				`<xenc:CipherData><xenc:CipherValue/></xenc:CipherData></xenc:EncryptedData>`, r.encrypt, kt))
		size := map[string]string{
			"http://www.w3.org/2001/04/xmlenc#aes128-cbc": "aes-128",
			"http://www.w3.org/2001/04/xmlenc#aes256-cbc": "aes-256",
			"http://www.w3.org/2009/xmlenc11#aes128-gcm":  "aes-128",
			"http://www.w3.org/2009/xmlenc11#aes256-gcm":  "aes-256",
		}[r.encrypt]
		data := w.file("to-encrypt.xml", `<saml:EncryptedAssertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">`+ax+`</saml:EncryptedAssertion>`)
		body = stripDecl(string(w.run("--encrypt", "--lax-key-search", "--pubkey-cert-pem", w.sp.certFile, "--session-key", size,
			"--xml-data", data, "--node-name", "urn:oasis:names:tc:SAML:2.0:assertion:Assertion", "--output", "/dev/stdout", tmpl)))
	}

	// 3. The response, signed if asked.
	sig := ""
	if r.signResponse {
		sig = fmt.Sprintf(sigTemplate, r.sigMethod, "_r0123456789", r.digest)
	}
	resp := fmt.Sprintf(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r0123456789" Version="2.0" IssueInstant="%s" Destination="%s" InResponseTo="%s">`+
		`<saml:Issuer>%s</saml:Issuer>%s<samlp:Status>%s</samlp:Status>%s</samlp:Response>`,
		judgeNow.Format(time.RFC3339), r.destination, r.inResponseTo, a.Issuer, sig, r.status, body)
	if r.signResponse {
		in := w.file("response.xml", resp)
		resp = string(w.run("--sign", "--lax-key-search", "--privkey-pem", w.idp.keyFile+","+w.idp.certFile,
			"--id-attr:ID", "urn:oasis:names:tc:SAML:2.0:protocol:Response", "--output", "/dev/stdout", in))
	}
	if r.tamper != nil {
		resp = r.tamper(resp)
	}
	return base64.StdEncoding.EncodeToString([]byte(resp))
}

func stripDecl(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "<?xml") {
		s = s[strings.Index(s, "?>")+2:]
	}
	return strings.TrimSpace(s)
}

// judgeDir is a temporary directory whose path xmlsec1 can take: its
// "--privkey-pem key,cert" splits on commas, and a subtest's name has them.
func judgeDir(t *testing.T) string {
	d, err := os.MkdirTemp("", "saml-judge")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

func sprintf(f string, a ...any) string { return fmt.Sprintf(f, a...) }

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
