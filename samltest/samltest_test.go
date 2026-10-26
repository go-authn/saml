// SPDX-License-Identifier: BSD-3-Clause

package samltest_test

import (
	"bytes"
	"compress/flate"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"html"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-authn/saml"
	"github.com/go-authn/saml/samltest"
)

const (
	idpEntity = "https://idp.univ-ex.example/idp/shibboleth"
	spEntity  = "https://bridge.example.org/saml"
	acs       = "https://bridge.example.org/saml/acs"
)

type world struct {
	fed, idpKey, spKey *samltest.Party
	idp                *samltest.IdP
	md                 []byte
	sp                 *saml.SP
}

func newWorld(t *testing.T) *world {
	t.Helper()
	w := &world{}
	var err error
	for _, p := range []struct {
		dst  **samltest.Party
		name string
	}{{&w.fed, "federation"}, {&w.idpKey, "idp"}, {&w.spKey, "sp"}} {
		if *p.dst, err = samltest.NewParty(p.name); err != nil {
			t.Fatal(err)
		}
	}
	w.idp = &samltest.IdP{EntityID: idpEntity, Scope: "univ-ex.example", SSO: "https://idp.univ-ex.example/SSO", Name: "Université d'exemple", Signer: w.idpKey}
	f := &samltest.Federation{Signer: w.fed, IdPs: []*samltest.IdP{w.idp}}
	if w.md, err = f.Metadata(24 * time.Hour); err != nil {
		t.Fatal(err)
	}
	md, err := saml.ParseMetadata(w.md, w.fed.Cert, time.Now())
	if err != nil {
		t.Fatalf("this module refuses the federation's metadata: %v", err)
	}
	w.sp = &saml.SP{EntityID: spEntity, ACS: acs, Key: w.spKey.Key, Cert: w.spKey.Cert, Federation: md}
	return w
}

func (w *world) request(t *testing.T) (string, saml.Pending) {
	t.Helper()
	idp, ok := w.sp.Federation.IdP(idpEntity)
	if !ok {
		t.Fatal("the IdP is not in the parsed metadata")
	}
	if idp.SSO != w.idp.SSO || !slices.Contains(idp.Scopes, "univ-ex.example") {
		t.Fatalf("metadata read back as SSO %q scopes %v", idp.SSO, idp.Scopes)
	}
	u, p, err := w.sp.Request(idp, "rs", saml.Options{})
	if err != nil {
		t.Fatal(err)
	}
	q, _ := url.Parse(u)
	return q.Query().Get("SAMLRequest"), p
}

var attrs = []samltest.Attribute{
	{Name: samltest.EPPN, Values: []string{"alice@univ-ex.example"}},
	{Name: samltest.SubjectID, Values: []string{"alice@univ-ex.example"}},
	{Name: samltest.Entitlement, Values: []string{"urn:mace:univ-ex.example:grp-alpha", "urn:mace:univ-ex.example:admins & co <x>"}},
	{Name: samltest.DisplayName, Values: []string{"Alice Martin"}},
}

func check(t *testing.T, a *saml.Assertion) {
	t.Helper()
	if a.First(saml.EduPersonPrincipalName) != "alice@univ-ex.example" {
		t.Errorf("eppn %v", a.Attributes[saml.EduPersonPrincipalName])
	}
	if got := a.Attributes[saml.EduPersonEntitlement]; !slices.Equal(got, attrs[2].Values) {
		t.Errorf("entitlements %q", got)
	}
	if v, from := a.Subject(); v == "" || from == "" {
		t.Errorf("no subject: %q from %q", v, from)
	}
}

// The module's own SP accepts what the helper produces, encrypted or not.
func TestAcceptedByThisModule(t *testing.T) {
	for _, enc := range []bool{true, false} {
		w := newWorld(t)
		req, p := w.request(t)
		id, err := samltest.RequestID(req)
		if err != nil || id != p.ID {
			t.Fatalf("RequestID %q, %v; want %q", id, err, p.ID)
		}
		a := samltest.Assertion{InResponseTo: id, SP: spEntity, ACS: acs, Attributes: attrs}
		if enc {
			a.EncryptTo = w.spKey.Cert
		}
		resp, err := w.idp.Response(a)
		if err != nil {
			t.Fatal(err)
		}
		got, err := w.sp.Accept(resp, p)
		if err != nil {
			t.Fatalf("encrypted=%v: refused: %v", enc, err)
		}
		check(t, got)
		// Replayed: refused, so the helper's IDs are fresh and used once.
		if _, err := w.sp.Accept(resp, p); err == nil {
			t.Errorf("encrypted=%v: the same response accepted twice", enc)
		}
	}
}

// A signature that covers nothing would let anything through: change one
// byte of what was signed and the SP must refuse.
func TestTamperedResponseRefused(t *testing.T) {
	w := newWorld(t)
	req, p := w.request(t)
	id, _ := samltest.RequestID(req)
	resp, err := w.idp.Response(samltest.Assertion{InResponseTo: id, SP: spEntity, ACS: acs, Attributes: attrs})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.StdEncoding.DecodeString(resp)
	bad := bytes.Replace(raw, []byte("Alice Martin"), []byte("Mallory Mar"), 1)
	if bytes.Equal(bad, raw) {
		t.Fatal("nothing to tamper with")
	}
	if _, err := w.sp.Accept(base64.StdEncoding.EncodeToString(bad), p); err == nil {
		t.Fatal("a tampered response was accepted")
	}
	// Signed by a key the federation does not list: refused.
	other, _ := samltest.NewParty("other")
	rogue := *w.idp
	rogue.Signer = other
	resp, _ = rogue.Response(samltest.Assertion{InResponseTo: id, SP: spEntity, ACS: acs, Attributes: attrs, EncryptTo: w.spKey.Cert})
	if _, err := w.sp.Accept(resp, p); err == nil {
		t.Fatal("a response signed by an unlisted key was accepted")
	}
}

var (
	actionRe = regexp.MustCompile(`action="([^"]*)"`)
	inputRe  = regexp.MustCompile(`name="(SAMLRequest|SAMLResponse|RelayState)" value="([^"]*)"`)
)

func TestHandlerLogsSomebodyIn(t *testing.T) {
	w := newWorld(t)
	login := func(u, p string) ([]samltest.Attribute, bool) { return attrs, u == "alice" && p == "secret" }
	srv := httptest.NewServer(w.idp.Handler(spEntity, acs, w.spKey.Cert, login))
	defer srv.Close()
	req, p := w.request(t)
	resp, err := http.Get(srv.URL + "/SSO?" + url.Values{"SAMLRequest": {req}, "RelayState": {"rs"}}.Encode())
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	fields := url.Values{}
	for _, m := range inputRe.FindAllStringSubmatch(string(page), -1) {
		fields.Set(m[1], html.UnescapeString(m[2]))
	}
	if fields.Get("SAMLRequest") != req || fields.Get("RelayState") != "rs" || !strings.Contains(string(page), `name="password"`) {
		t.Fatalf("login page: %s", page)
	}
	fields.Set("username", "alice")
	fields.Set("password", "wrong")
	if r, _ := http.PostForm(srv.URL+"/SSO", fields); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong password: HTTP %d", r.StatusCode)
	}
	fields.Set("password", "secret")
	r, err := http.PostForm(srv.URL+"/SSO", fields)
	if err != nil {
		t.Fatal(err)
	}
	page, _ = io.ReadAll(r.Body)
	r.Body.Close()
	if m := actionRe.FindStringSubmatch(string(page)); m == nil || html.UnescapeString(m[1]) != acs {
		t.Fatalf("answer page posts elsewhere: %s", page)
	}
	out := url.Values{}
	for _, m := range inputRe.FindAllStringSubmatch(string(page), -1) {
		out.Set(m[1], html.UnescapeString(m[2]))
	}
	if out.Get("RelayState") != "rs" {
		t.Fatalf("RelayState %q", out.Get("RelayState"))
	}
	a, err := w.sp.Accept(out.Get("SAMLResponse"), p)
	if err != nil {
		t.Fatal(err)
	}
	check(t, a)
	// A form with no request, or a broken one.
	for _, v := range []url.Values{{"username": {"alice"}, "password": {"secret"}, "SAMLRequest": {"%%"}}} {
		if r, _ := http.PostForm(srv.URL+"/SSO", v); r.StatusCode != http.StatusBadRequest {
			t.Errorf("bad SAMLRequest: HTTP %d", r.StatusCode)
		}
	}
	if r, _ := http.Post(srv.URL+"/SSO?%zz", "application/x-www-form-urlencoded", strings.NewReader("")); r.StatusCode != http.StatusBadRequest {
		t.Errorf("unparsable form: HTTP %d", r.StatusCode)
	}
}

func deflate(s string) string {
	var z bytes.Buffer
	w, _ := flate.NewWriter(&z, flate.BestCompression)
	w.Write([]byte(s))
	w.Close()
	return base64.StdEncoding.EncodeToString(z.Bytes())
}

func TestRequestIDRefusals(t *testing.T) {
	for name, in := range map[string]string{
		"not base64":          "%%%",
		"not deflate":         base64.StdEncoding.EncodeToString([]byte{0xff, 0xff, 0xff}),
		"not XML":             deflate("<<"),
		"not an AuthnRequest": deflate(`<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_x"/>`),
		"no ID":               deflate(`<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>`),
	} {
		if _, err := samltest.RequestID(in); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestPartyFiles(t *testing.T) {
	p, err := samltest.NewParty("x")
	if err != nil {
		t.Fatal(err)
	}
	if fp := p.Fingerprint(); len(fp) != 32*3-1 || strings.ToUpper(fp) != fp || strings.Count(fp, ":") != 31 {
		t.Fatalf("fingerprint %q", fp)
	}
	dir := t.TempDir()
	k, c, err := p.WriteFiles(dir, "x")
	if err != nil {
		t.Fatal(err)
	}
	// Windows has no POSIX permission bits: os.Stat reports 0666 there.
	if st, _ := os.Stat(k); runtime.GOOS != "windows" && st.Mode().Perm() != 0o600 {
		t.Errorf("key file mode %v", st.Mode().Perm())
	}
	if _, err := os.Stat(c); err != nil {
		t.Error(err)
	}
	if _, _, err := p.WriteFiles(filepath.Join(dir, "missing"), "x"); err == nil {
		t.Error("wrote into a directory that does not exist")
	}
}

func TestEncryptToANonRSACertificate(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ec"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	c, _ := x509.ParseCertificate(der)
	w := newWorld(t)
	if _, err := w.idp.Response(samltest.Assertion{InResponseTo: "_x", SP: spEntity, ACS: acs, EncryptTo: c}); err == nil {
		t.Fatal("encrypted to an ECDSA certificate")
	}
}

// xmlsec1 -- which nobody here wrote -- verifies the metadata and the
// response and decrypts the assertion. A response the helper produced and
// this module accepted would prove only that the two agree with each
// other. SAML_REQUIRE_JUDGE=1 makes a missing xmlsec1 a failure.
func TestJudgedByXMLSec1(t *testing.T) {
	x, err := exec.LookPath("xmlsec1")
	if err != nil {
		if os.Getenv("SAML_REQUIRE_JUDGE") != "" {
			t.Fatal("xmlsec1 is required here and is not installed")
		}
		t.Skip("xmlsec1 is not installed: the helper's output is not judged by a third party here")
	}
	lax := []string{}
	if out, _ := exec.Command(x, "--help-verify").CombinedOutput(); strings.Contains(string(out), "--lax-key-search") {
		lax = []string{"--lax-key-search"}
	}
	run := func(args ...string) string {
		t.Helper()
		out, err := exec.Command(x, append(append([]string{args[0]}, lax...), args[1:]...)...).CombinedOutput()
		if err != nil {
			t.Fatalf("xmlsec1 %v: %v\n%s", args, err, out)
		}
		return string(out)
	}
	w := newWorld(t)
	dir := t.TempDir()
	_, fedCert, _ := w.fed.WriteFiles(dir, "fed")
	_, idpCert, _ := w.idpKey.WriteFiles(dir, "idp")
	spKey, _, _ := w.spKey.WriteFiles(dir, "sp")
	md := filepath.Join(dir, "md.xml")
	os.WriteFile(md, w.md, 0o644)
	run("--verify", "--pubkey-cert-pem", fedCert, "--id-attr:ID", "urn:oasis:names:tc:SAML:2.0:metadata:EntitiesDescriptor", md)

	resp, err := w.idp.Response(samltest.Assertion{InResponseTo: "_req", SP: spEntity, ACS: acs, Attributes: attrs, EncryptTo: w.spKey.Cert})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.StdEncoding.DecodeString(resp)
	rf := filepath.Join(dir, "resp.xml")
	os.WriteFile(rf, raw, 0o644)
	run("--verify", "--pubkey-cert-pem", idpCert, "--id-attr:ID", "urn:oasis:names:tc:SAML:2.0:protocol:Response", rf)
	plain := run("--decrypt", "--privkey-pem", spKey, rf)
	if !strings.Contains(plain, "alice@univ-ex.example") || !strings.Contains(plain, "admins &amp; co &lt;x&gt;") {
		t.Fatalf("xmlsec1 decrypted something else:\n%s", plain)
	}

	clear, _ := w.idp.Response(samltest.Assertion{InResponseTo: "_req", SP: spEntity, ACS: acs, Attributes: attrs})
	raw, _ = base64.StdEncoding.DecodeString(clear)
	os.WriteFile(rf, raw, 0o644)
	run("--verify", "--pubkey-cert-pem", idpCert, "--id-attr:ID", "urn:oasis:names:tc:SAML:2.0:protocol:Response", rf)
}
