// SPDX-License-Identifier: BSD-3-Clause

package saml

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testSP(t *testing.T) *SP {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "sp"},
		NotBefore: judgeNow.Add(-time.Hour), NotAfter: judgeNow.Add(24 * 365 * time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	c, _ := x509.ParseCertificate(der)
	return &SP{EntityID: spEntity, ACS: acsURL, Key: k, Cert: c, Now: func() time.Time { return judgeNow }}
}

func TestRequest(t *testing.T) {
	sp := testSP(t)
	idp := &IdP{EntityID: idpEntity, SSO: "https://idp.univ-example.fr/SSO?existing=1"}
	u, p, err := sp.Request(idp, "state-123", Options{ForceAuthn: true, IsPassive: true,
		AuthnContext: []string{"https://refeds.org/profile/mfa"}})
	if err != nil {
		t.Fatal(err)
	}
	if p.IdP != idpEntity || !strings.HasPrefix(p.ID, "_") || len(p.ID) != 41 || !p.Issued.Equal(judgeNow) {
		t.Fatalf("pending = %+v", p)
	}
	parsed, _ := url.Parse(u)
	q := parsed.Query()
	if q.Get("existing") != "1" || q.Get("RelayState") != "state-123" {
		t.Fatalf("query = %v: the SSO URL's own parameters or the RelayState were lost", q)
	}
	z, err := base64.StdEncoding.DecodeString(q.Get("SAMLRequest"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(flate.NewReader(bytes.NewReader(z)))
	if err != nil {
		t.Fatalf("not raw DEFLATE: %v", err)
	}
	r, err := parse(raw, responseLimits)
	if err != nil || !is(r, nsProtocol, "AuthnRequest") {
		t.Fatalf("not an AuthnRequest: %v\n%s", err, raw)
	}
	for attr, want := range map[string]string{
		"ID": p.ID, "Destination": idp.SSO, "AssertionConsumerServiceURL": acsURL,
		"ProtocolBinding": bindingPOST, "ForceAuthn": "true", "IsPassive": "true", "Version": "2.0",
	} {
		if got := r.SelectAttrValue(attr, ""); got != want {
			t.Errorf("%s = %q, want %q", attr, got, want)
		}
	}
	if iss, _ := child(r, nsAssertion, "Issuer"); iss == nil || text(iss) != spEntity {
		t.Error("the request does not name this SP")
	}
	rac, _ := child(r, nsProtocol, "RequestedAuthnContext")
	if rac == nil || text(children(rac, nsAssertion, "AuthnContextClassRef")[0]) != "https://refeds.org/profile/mfa" {
		t.Error("the MFA request is missing")
	}

	if _, _, err := sp.Request(idp, strings.Repeat("x", 81), Options{}); err == nil {
		t.Error("an 81-byte RelayState was accepted")
	}
	if _, _, err := sp.Request(&IdP{SSO: "://bad"}, "", Options{}); err == nil {
		t.Error("an unparseable SSO URL was accepted")
	}
	u2, _, _ := sp.Request(idp, "", Options{})
	if strings.Contains(u2, "RelayState") || strings.Contains(u2, "ForceAuthn") {
		t.Error("an empty RelayState or unset option was sent")
	}
}

func TestSPMetadata(t *testing.T) {
	sp := testSP(t)
	out, err := sp.Metadata(Description{
		Names:            map[string]string{"fr": "Passerelle OIDC", "en": "OIDC bridge"},
		Descriptions:     map[string]string{"fr": "Connexion fédérée"},
		InformationURL:   "https://bridge.example.org/",
		PrivacyStatement: "https://bridge.example.org/privacy",
		Discovery:        "https://bridge.example.org/saml/disco",
		Technical:        "noc@example.org",
		Attributes:       []string{SubjectID, EduPersonPrincipalName},
	})
	if err != nil {
		t.Fatal(err)
	}
	ed, err := parse(out, responseLimits)
	if err != nil {
		t.Fatal(err)
	}
	role, _ := child(ed, nsMetadata, "SPSSODescriptor")
	if role == nil || role.SelectAttrValue("WantAssertionsSigned", "") != "true" {
		t.Fatal("no SPSSODescriptor wanting signed assertions")
	}
	acs, _ := child(role, nsMetadata, "AssertionConsumerService")
	if acs.SelectAttrValue("Location", "") != acsURL || acs.SelectAttrValue("Binding", "") != bindingPOST {
		t.Error("the ACS is not advertised")
	}
	kd, _ := child(role, nsMetadata, "KeyDescriptor")
	if kd.SelectAttrValue("use", "") != "" {
		t.Error("the key is restricted to one use; encryption needs it too")
	}
	ems := children(kd, nsMetadata, "EncryptionMethod")
	if len(ems) == 0 || !strings.HasSuffix(ems[0].SelectAttrValue("Algorithm", ""), "aes128-gcm") {
		t.Error("GCM is not the preferred encryption method")
	}
	certs := descendants(kd, nsDSig, "X509Certificate")
	if len(certs) != 1 || text(certs[0]) != base64.StdEncoding.EncodeToString(sp.Cert.Raw) {
		t.Error("the certificate is not published")
	}
	for _, want := range []string{"mailto:noc@example.org", "Passerelle OIDC", "idpdisc:DiscoveryResponse", SubjectID, "PrivacyStatementURL"} {
		if !bytes.Contains(out, []byte(want)) {
			t.Errorf("%q missing from the metadata", want)
		}
	}

	if _, err := (&SP{}).Metadata(Description{Names: map[string]string{"fr": "x"}}); err == nil {
		t.Error("metadata without a certificate")
	}
	if _, err := sp.Metadata(Description{}); err == nil {
		t.Error("metadata without a name")
	}
	if min, err := sp.Metadata(Description{Names: map[string]string{"en": "x"}}); err != nil || bytes.Contains(min, []byte("ContactPerson")) {
		t.Error("an empty contact was published")
	}
}

func TestDiscovery(t *testing.T) {
	u, err := DiscoveryURL("https://discovery.renater.fr/renater", spEntity, "https://bridge.example.org/saml/disco?s=1")
	if err != nil {
		t.Fatal(err)
	}
	p, _ := url.Parse(u)
	q := p.Query()
	if q.Get("entityID") != spEntity || q.Get("return") != "https://bridge.example.org/saml/disco?s=1" || q.Get("returnIDParam") != "entityID" {
		t.Fatalf("%s", u)
	}
	if _, err := DiscoveryURL("://", "", ""); err == nil {
		t.Error("a bad service URL was accepted")
	}

	fed := &Metadata{IdPs: map[string]*IdP{idpEntity: {EntityID: idpEntity}}}
	if i, err := Chosen(url.Values{"entityID": {idpEntity}}, fed); err != nil || i.EntityID != idpEntity {
		t.Fatalf("Chosen: %v", err)
	}
	if _, err := Chosen(url.Values{}, fed); err == nil {
		t.Error("no choice was accepted")
	}
	if _, err := Chosen(url.Values{"entityID": {"https://evil.example/idp"}}, fed); err == nil {
		t.Error("an IdP outside the federation was accepted")
	}
}

func TestSubjectOrder(t *testing.T) {
	a := &Assertion{Attributes: map[string][]string{}, IdP: &IdP{EntityID: "idp"}}
	if v, from := a.Subject(); v != "" || from != "" {
		t.Fatal("a subject from nothing")
	}
	// A persistent NameID qualified by ANOTHER IdP is not this IdP's to give.
	a.NameID = NameID{Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent", NameQualifier: "other-idp", SPNameQualifier: "sp", Value: "xyz"}
	if v, _ := a.Subject(); v != "" {
		t.Errorf("a persistent NameID qualified by another IdP gave %q", v)
	}
	a.NameID.NameQualifier = "idp"
	if v, _ := a.Subject(); v != "idp!sp!xyz" {
		t.Errorf("persistent NameID: %q", v)
	}
	a.Attributes[EduPersonTargetedID] = []string{"idp!sp!ptid"}
	if v, from := a.Subject(); v != "idp!sp!ptid" || from != EduPersonTargetedID {
		t.Errorf("ePTID: %q", v)
	}
	a.Attributes[Mail] = []string{"alice@x.fr"}
	if _, from := a.Subject(); from == Mail {
		t.Error("mail was used as an identifier")
	}
	a.Attributes[EduPersonPrincipalName] = []string{"Alice@x.fr"}
	if v, _ := a.Subject(); v != "Alice@x.fr" {
		t.Errorf("eppn: %q", v)
	}
	a.Attributes[PairwiseID] = []string{"PW@x.fr"}
	if v, _ := a.Subject(); v != "pw@x.fr" {
		t.Errorf("pairwise-id: %q (compares case-insensitively, so is lower-cased)", v)
	}
	a.Attributes[SubjectID] = []string{"SID@x.fr"}
	if v, from := a.Subject(); v != "sid@x.fr" || from != SubjectID {
		t.Errorf("subject-id: %q", v)
	}
	if a.First("nothing") != "" {
		t.Error("First of a missing attribute")
	}
}

func TestIdPHelpers(t *testing.T) {
	i := &IdP{EntityID: "e", Names: map[string]string{"de": "Uni", "fr": "Université"}, Categories: []string{"https://refeds.org/sirtfi"}}
	if i.Name("fr") != "Université" || i.Name("it") != "Uni" {
		t.Errorf("Name: %q %q", i.Name("fr"), i.Name("it"))
	}
	i.Names["en"] = "University"
	if i.Name("it") != "University" {
		t.Error("English is not the fallback")
	}
	if (&IdP{EntityID: "e"}).Name() != "e" {
		t.Error("no name falls back to the entity ID")
	}
	if !i.Has("https://refeds.org/sirtfi") || i.Has("http://refeds.org/category/research-and-scholarship") {
		t.Error("Has")
	}
	i.Scopes = []string{"x.fr"}
	for v, want := range map[string]bool{"a@x.fr": true, "a@X.fr": false, "a@y.fr": false, "@x.fr": false, "a@": false, "ax.fr": false, "a@b@x.fr": false} {
		if i.inScope(v) != want {
			t.Errorf("inScope(%q) = %v", v, !want)
		}
	}
	md := &Metadata{IdPs: map[string]*IdP{
		"b": {EntityID: "b", Names: map[string]string{"fr": "beta"}},
		"a": {EntityID: "a", Names: map[string]string{"fr": "Alpha"}},
		"c": {EntityID: "c", Names: map[string]string{"fr": "alpha"}},
	}}
	s := md.Sorted("fr")
	if s[0].EntityID != "a" || s[1].EntityID != "c" || s[2].EntityID != "b" {
		t.Errorf("Sorted: %s %s %s", s[0].EntityID, s[1].EntityID, s[2].EntityID)
	}
}

func TestDuration(t *testing.T) {
	for in, want := range map[string]time.Duration{
		"PT1H": time.Hour, "P1D": 24 * time.Hour, "PT30M": 30 * time.Minute,
		"P1DT2H3M4.5S": 26*time.Hour + 3*time.Minute + 4500*time.Millisecond,
	} {
		if got, err := duration(in); err != nil || got != want {
			t.Errorf("duration(%q) = %v, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "P", "1H", "P1Y", "P1M", "PT1D", "PT", "PH", "P1H", "PT1", "PT1.2.3S", "PTT1H"} {
		if _, err := duration(bad); err == nil {
			t.Errorf("duration(%q) was accepted", bad)
		}
	}
}

func TestReplayExpires(t *testing.T) {
	m := NewMemoryReplay()
	now := judgeNow
	m.now = func() time.Time { return now }
	if !m.Use("x", now.Add(time.Minute)) || m.Use("x", now.Add(time.Minute)) {
		t.Fatal("the second use was accepted")
	}
	now = now.Add(2 * time.Minute)
	if !m.Use("x", now.Add(time.Minute)) {
		t.Fatal("an expired entry was kept forever")
	}
}

func TestFederation(t *testing.T) {
	data, cert := renater(t)
	var hits, notModified atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("If-None-Match") == `"v1"` {
			notModified.Add(1)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		w.Write(data)
	}))
	defer srv.Close()
	now := at(renaterNow)
	f := &Federation{URL: srv.URL, Cert: cert, Now: func() time.Time { return now }}
	if f.Metadata() != nil {
		t.Fatal("metadata before any refresh")
	}
	if _, ok := f.IdP("x"); ok {
		t.Fatal("an IdP before any refresh")
	}
	ctx := context.Background()
	if err := f.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if err := f.Refresh(ctx); err != nil || notModified.Load() != 1 {
		t.Fatalf("the second refresh did not ask If-None-Match: %v", err)
	}
	md := f.Metadata()
	if md == nil || len(md.IdPs) != 343 {
		t.Fatal("no metadata")
	}
	var any string
	for k := range md.IdPs {
		any = k
		break
	}
	if _, ok := f.IdP(any); !ok {
		t.Fatal("an IdP in the metadata is not found")
	}
	// Past validUntil, the last good copy is no longer vouched for.
	now = md.ValidUntil
	if f.Metadata() != nil {
		t.Fatal("expired metadata is still served")
	}
}

func TestFederationRefusals(t *testing.T) {
	data, cert := renater(t)
	ctx := context.Background()
	now := func() time.Time { return at(renaterNow) }

	if err := (&Federation{URL: "https://x"}).Refresh(ctx); err == nil {
		t.Error("a federation without a certificate refreshed")
	}
	if err := (&Federation{URL: "http://metadata.example.org/x.xml", Cert: cert}).Refresh(ctx); err == nil {
		t.Error("cleartext http was fetched")
	}
	if err := (&Federation{URL: "ftp://x/y", Cert: cert}).Refresh(ctx); err == nil {
		t.Error("an unknown scheme was fetched")
	}
	if err := (&Federation{URL: "://", Cert: cert}).Refresh(ctx); err == nil {
		t.Error("an unparseable URL was fetched")
	}
	if err := (&Federation{URL: "file:///does/not/exist", Cert: cert}).Refresh(ctx); err == nil {
		t.Error("a missing file was read")
	}
	p := filepath.Join(t.TempDir(), "md.xml")
	os.WriteFile(p, data, 0o644)
	f := &Federation{URL: fileURL(p), Cert: cert, Now: now}
	if err := f.Refresh(ctx); err != nil || f.Metadata() == nil {
		t.Fatalf("file://: %v", err)
	}
	// A bad document does not replace the good one.
	os.WriteFile(p, bytes.Replace(data, []byte(`Location="https://`), []byte(`Location="https://evil.`), 1), 0o644)
	if err := f.Refresh(ctx); err == nil || f.Metadata() == nil {
		t.Fatal("a tampered refresh replaced, or dropped, the good metadata")
	}

	for _, h := range []http.HandlerFunc{
		func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusInternalServerError) },
		func(w http.ResponseWriter, r *http.Request) { w.Write(bytes.Repeat([]byte("x"), 2048)) },
	} {
		srv := httptest.NewServer(h)
		f := &Federation{URL: srv.URL, Cert: cert, MaxSize: 1024, Now: now}
		if err := f.Refresh(ctx); err == nil {
			t.Error("a failed or oversized fetch was accepted")
		}
		srv.Close()
	}
	dead := httptest.NewServer(http.NotFoundHandler())
	dead.Close()
	if err := (&Federation{URL: dead.URL, Cert: cert}).Refresh(ctx); err == nil {
		t.Error("an unreachable server refreshed")
	}
}

func TestFederationRun(t *testing.T) {
	_, cert := renater(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		(&Federation{URL: "https://127.0.0.1:1/x", Cert: cert}).Run(ctx, func(error) {})
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop with its context")
	}
	if !loopback("127.0.0.1") || !loopback("::1") || !loopback("localhost") || loopback("example.org") {
		t.Error("loopback")
	}
}

func fileURL(p string) string {
	s := filepath.ToSlash(p)
	if !strings.HasPrefix(s, "/") {
		s = "/" + s
	}
	return "file://" + s
}
