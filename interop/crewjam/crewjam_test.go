// SPDX-License-Identifier: BSD-3-Clause

// Package crewjam holds crewjam/saml's identity provider to go-authn/saml's
// service provider: a response written by code nobody here wrote, through
// the same AuthnRequest, metadata and HTTP-POST form a browser carries.
//
// It is a module of its own so that crewjam/saml and what it pulls in never
// become requirements of the library.
package crewjam

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/xml"
	"html"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	cj "github.com/crewjam/saml"
	"github.com/go-authn/saml"
	dsig "github.com/russellhaering/goxmldsig"
)

const scope = "univ-example.fr"

func party(t *testing.T, cn string) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return key, cert
}

type world struct {
	idp *cj.IdentityProvider
	sp  *saml.SP
	srv *httptest.Server
	// edit, when set, changes the response on its way to the SP.
	edit func(*testing.T, string) string
}

type sps map[string]*cj.EntityDescriptor

func (m sps) GetServiceProvider(_ *http.Request, id string) (*cj.EntityDescriptor, error) {
	if ed, ok := m[id]; ok {
		return ed, nil
	}
	return nil, io.EOF
}

type session cj.Session

func (s *session) GetSession(http.ResponseWriter, *http.Request, *cj.IdpAuthnRequest) *cj.Session {
	cs := cj.Session(*s)
	return &cs
}

// newWorld is an IdP run by crewjam/saml and an SP by this repository, each
// knowing the other only from its metadata. The IdP's reaches the SP the way
// a federation's does: with a shibmd:Scope added and signed by the
// federation's key.
func newWorld(t *testing.T, method string) *world {
	idpKey, idpCert := party(t, "idp")
	spKey, spCert := party(t, "sp")
	fedKey, fedCert := party(t, "federation")

	w := &world{}
	mux := http.NewServeMux()
	w.srv = httptest.NewServer(mux)
	t.Cleanup(w.srv.Close)
	base, _ := url.Parse(w.srv.URL)

	w.sp = &saml.SP{
		EntityID: "https://sp.example.org/sp",
		ACS:      "https://sp.example.org/acs",
		Key:      spKey,
		Cert:     spCert,
	}
	spMD, err := w.sp.Metadata(saml.Description{Names: map[string]string{"en": "sp"}, Technical: "ops@example.org"})
	if err != nil {
		t.Fatal(err)
	}
	var spED cj.EntityDescriptor
	if err := xml.Unmarshal(spMD, &spED); err != nil {
		t.Fatalf("crewjam cannot read our SP metadata: %v", err)
	}

	w.idp = &cj.IdentityProvider{
		Key:                     idpKey,
		Certificate:             idpCert,
		MetadataURL:             *base.JoinPath("metadata"),
		SSOURL:                  *base.JoinPath("sso"),
		ServiceProviderProvider: sps{w.sp.EntityID: &spED},
		SessionProvider: &session{
			ID:                     "s1",
			NameID:                 "alice",
			UserName:               "alice",
			UserEmail:              "alice@" + scope,
			EduPersonPrincipalName: "alice@" + scope,
			UserGivenName:          "Alice",
			UserSurname:            "Liddell",
		},
		SignatureMethod: method,
	}
	mux.HandleFunc("/sso", w.idp.ServeSSO)

	md, err := xml.Marshal(w.idp.Metadata())
	if err != nil {
		t.Fatal(err)
	}
	federation := federate(t, md, fedKey, fedCert)
	m, err := saml.ParseMetadata(federation, fedCert, time.Now())
	if err != nil {
		t.Fatalf("crewjam's IdP metadata, scoped and signed: %v", err)
	}
	if len(m.Skipped) != 0 {
		t.Fatalf("crewjam's IdP was skipped: %v", m.Skipped)
	}
	w.sp.Federation = m
	return w
}

// federate does what a federation registry does to an IdP's metadata: adds
// its scope, puts it in an EntitiesDescriptor with a validUntil, and signs.
func federate(t *testing.T, entity []byte, key *rsa.PrivateKey, cert *x509.Certificate) []byte {
	t.Helper()
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(entity); err != nil {
		t.Fatal(err)
	}
	ed := doc.Root()
	role := ed.FindElement("./IDPSSODescriptor")
	if role == nil {
		t.Fatalf("no IDPSSODescriptor in %s", entity)
	}
	ext := etree.NewElement("Extensions")
	sc := ext.CreateElement("shibmd:Scope")
	sc.CreateAttr("xmlns:shibmd", "urn:mace:shibboleth:metadata:1.0")
	sc.CreateAttr("regexp", "false")
	sc.SetText(scope)
	role.InsertChildAt(0, ext)

	root := etree.NewElement("EntitiesDescriptor")
	root.CreateAttr("xmlns", "urn:oasis:names:tc:SAML:2.0:metadata")
	root.CreateAttr("ID", "_federation")
	root.CreateAttr("validUntil", time.Now().Add(7*24*time.Hour).UTC().Format(time.RFC3339))
	root.AddChild(ed)

	ctx := dsig.NewDefaultSigningContext(dsig.TLSCertKeyStore(tls.Certificate{
		Certificate: [][]byte{cert.Raw}, PrivateKey: key, Leaf: cert,
	}))
	ctx.Hash = crypto.SHA256
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	signed, err := ctx.SignEnveloped(root)
	if err != nil {
		t.Fatal(err)
	}
	// The schema puts the Signature first; the enveloped transform removes
	// it wherever it is, so moving it does not change what was signed.
	last := len(signed.Child) - 1
	signed.Child = append([]etree.Token{signed.Child[last]}, signed.Child[:last]...)
	out := etree.NewDocument()
	out.SetRoot(signed)
	b, err := out.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

var formValue = regexp.MustCompile(`name="SAMLResponse" value="([^"]*)"`)

// login sends a browser from the SP to crewjam's IdP and back with the
// form the IdP writes.
func (w *world) login(t *testing.T) (*saml.Assertion, error) {
	t.Helper()
	idp, ok := w.sp.Federation.IdP(w.idp.MetadataURL.String())
	if !ok {
		t.Fatalf("IdP %s not in the federation", w.idp.MetadataURL.String())
	}
	u, pending, err := w.sp.Request(idp, "state", saml.Options{})
	if err != nil {
		t.Fatal(err)
	}
	res, err := http.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("crewjam refused our AuthnRequest: %d %s", res.StatusCode, body)
	}
	m := formValue.FindSubmatch(body)
	if m == nil {
		t.Fatalf("no SAMLResponse in %s", body)
	}
	resp := html.UnescapeString(string(m[1]))
	if w.edit != nil {
		resp = w.edit(t, resp)
	}
	return w.sp.Accept(resp, pending)
}

// crewjam encrypts with AES-128-CBC whatever the SP's metadata prefers, and
// signs the Response as well as the Assertion: the signature over the
// Response covers the ciphertext, which is what makes CBC acceptable.
func TestCrewjamIdP(t *testing.T) {
	w := newWorld(t, dsig.RSASHA256SignatureMethod)
	a, err := w.login(t)
	if err != nil {
		t.Fatalf("a response from crewjam/saml refused: %v", err)
	}
	if sub, from := a.Subject(); sub != "alice@"+scope {
		t.Errorf("subject %q from %s", sub, from)
	}
	if got := a.First(saml.Mail); got != "alice@"+scope {
		t.Errorf("mail %q", got)
	}
	if got := a.First("urn:oid:2.5.4.42"); got != "Alice" {
		t.Errorf("givenName %q", got)
	}
}

// crewjam signs with RSA-SHA1 unless told otherwise. SHA-1 is refused
// (collisions are practical), and the refusal must say so -- an operator
// meeting it has to know that the IdP's setting is what to change.
func TestCrewjamDefaultSHA1IsRefusedByName(t *testing.T) {
	w := newWorld(t, "")
	_, err := w.login(t)
	if err == nil {
		t.Fatal("a response signed with RSA-SHA1 accepted")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "sha1") && !strings.Contains(strings.ToLower(err.Error()), "sha-1") {
		t.Errorf("refused, without naming SHA-1: %v", err)
	}
	t.Logf("refused: %v", err)
}

// response decodes a SAMLResponse form value.
func response(t *testing.T, b64 string) *etree.Document {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatal(err)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil {
		t.Fatal(err)
	}
	return doc
}

func encode(t *testing.T, doc *etree.Document) string {
	t.Helper()
	raw, err := doc.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

// What TestCrewjamIdP accepted is what it claims: an EncryptedAssertion in
// AES-128-CBC, inside a signed Response. And without the Response's
// signature the same ciphertext is refused -- CBC with nothing over it is
// the padding oracle of Jager and Somorovsky (2011), so the acceptance
// above rests on that signature and nothing else.
func TestCrewjamCBCRestsOnTheResponseSignature(t *testing.T) {
	w := newWorld(t, dsig.RSASHA256SignatureMethod)
	w.edit = func(t *testing.T, s string) string {
		doc := response(t, s)
		em := doc.FindElement("//EncryptedAssertion/EncryptedData/EncryptionMethod")
		if em == nil {
			t.Fatal("crewjam did not encrypt the assertion: the CBC path was not exercised")
		}
		if alg := em.SelectAttrValue("Algorithm", ""); alg != "http://www.w3.org/2001/04/xmlenc#aes128-cbc" {
			t.Fatalf("crewjam encrypted with %s", alg)
		}
		sig := doc.Root().SelectElement("Signature")
		if sig == nil {
			t.Fatal("crewjam did not sign the Response")
		}
		doc.Root().RemoveChild(sig)
		return encode(t, doc)
	}
	_, err := w.login(t)
	if err == nil {
		t.Fatal("an AES-CBC assertion in an unsigned Response accepted")
	}
	if !strings.Contains(err.Error(), "unsigned") {
		t.Errorf("refused, but not for the missing signature: %v", err)
	}
}
