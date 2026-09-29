// SPDX-License-Identifier: BSD-3-Clause

package saml

import (
	"strings"
	"testing"
	"time"
)

// Inputs refused before any signature is looked at.
func TestAcceptMalformed(t *testing.T) {
	sp := testSP(t)
	sp.Federation = &Metadata{IdPs: map[string]*IdP{idpEntity: {EntityID: idpEntity}}}
	p := Pending{ID: "_r", IdP: idpEntity}
	for name, in := range map[string]string{
		"too large":      strings.Repeat("A", maxResponse+1),
		"not base64":     "!!!",
		"not XML":        encode("<unclosed"),
		"a DOCTYPE":      encode(`<!DOCTYPE x [<!ENTITY e "boom">]><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">&e;</samlp:Response>`),
		"not a Response": encode(`<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>`),
		"empty":          encode(``),
		"wrong version":  encode(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Version="1.1" InResponseTo="_r"/>`),
		"no status":      encode(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Version="2.0" InResponseTo="_r"/>`),
		"issuer format":  encode(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" InResponseTo="_r"><saml:Issuer Format="urn:x">` + idpEntity + `</saml:Issuer></samlp:Response>`),
		"two issuers":    encode(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" InResponseTo="_r"><saml:Issuer>a</saml:Issuer><saml:Issuer>b</saml:Issuer></samlp:Response>`),
		"no assertion":   encode(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Version="2.0" InResponseTo="_r"><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status></samlp:Response>`),
		"no status code": encode(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Version="2.0" InResponseTo="_r"><samlp:Status/></samlp:Response>`),
		"unknown IdP":    "",
	} {
		t.Run(name, func(t *testing.T) {
			pp := p
			if name == "unknown IdP" {
				pp.IdP = "https://unknown.example/idp"
				in = encode(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>`)
			}
			if _, err := sp.Accept(in, pp); err == nil {
				t.Fatal("ACCEPTED")
			}
		})
	}
}

// The assertion checks, on assertions that reach them unsigned: they run
// after the signature, so they are exercised directly here.
func TestAssertionChecks(t *testing.T) {
	sp := testSP(t)
	sp.init()
	idp := &IdP{EntityID: idpEntity, Scopes: []string{scope}}
	p := Pending{ID: "_req0123456789", IdP: idpEntity}
	base := defaultAssertion()
	mk := func(edit func(string) string) string {
		return edit(base.xml(false))
	}
	for name, c := range map[string]struct {
		edit func(string) string
		want string
	}{
		"not an assertion": {func(s string) string { return `<saml:Foo xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/>` }, "not an Assertion"},
		"version":          {func(s string) string { return strings.Replace(s, `Version="2.0"`, `Version="1.0"`, 1) }, "version"},
		"no ID":            {func(s string) string { return strings.Replace(s, `ID="_a0123456789"`, ``, 1) }, "no ID"},
		"no issuer":        {func(s string) string { return strings.Replace(s, "<saml:Issuer>"+idpEntity+"</saml:Issuer>", "", 1) }, "no Issuer"},
		"no subject":       {func(s string) string { return cut(s, "<saml:Subject>", "</saml:Subject>") }, "Subject"},
		"two NameIDs": {func(s string) string {
			return strings.Replace(s, "<saml:Subject>", `<saml:Subject><saml:NameID>x</saml:NameID>`, 1)
		}, "NameID"},
		"not bearer":   {func(s string) string { return strings.Replace(s, "cm:bearer", "cm:holder-of-key", 1) }, "no bearer"},
		"no conf data": {func(s string) string { return cut(s, "<saml:SubjectConfirmationData", "/>") }, "no bearer"},
		"NotBefore on data": {func(s string) string {
			return strings.Replace(s, "<saml:SubjectConfirmationData ", `<saml:SubjectConfirmationData NotBefore="2026-01-01T00:00:00Z" `, 1)
		}, "no bearer"},
		"no conditions":    {func(s string) string { return cut(s, "<saml:Conditions", "</saml:Conditions>") }, "Conditions"},
		"not yet valid":    {func(s string) string { return replaceAttr(s, "Conditions", "NotBefore", "2026-09-29T11:00:00Z") }, "not valid yet"},
		"expired":          {func(s string) string { return replaceAttr(s, "Conditions", "NotOnOrAfter", "2026-09-29T09:00:00Z") }, "expired"},
		"bad NotBefore":    {func(s string) string { return replaceAttr(s, "Conditions", "NotBefore", "yesterday") }, "not a SAML time"},
		"bad NotOnOrAfter": {func(s string) string { return replaceAttr(s, "Conditions", "NotOnOrAfter", "tomorrow") }, "not a SAML time"},
		"no audience":      {func(s string) string { return cut(s, "<saml:AudienceRestriction>", "</saml:AudienceRestriction>") }, "no audience"},
		"two restrictions": {func(s string) string {
			return strings.Replace(s, "</saml:AudienceRestriction>", "</saml:AudienceRestriction><saml:AudienceRestriction><saml:Audience>other</saml:Audience></saml:AudienceRestriction>", 1)
		}, "another audience"},
		"no AuthnStatement": {func(s string) string { return cut(s, "<saml:AuthnStatement", "</saml:AuthnStatement>") }, "no AuthnStatement"},
		"bad AuthnInstant":  {func(s string) string { return replaceAttr(s, "AuthnStatement", "AuthnInstant", "now") }, "not a SAML time"},
		"session ended": {func(s string) string {
			return strings.Replace(s, `SessionIndex="_s1"`, `SessionIndex="_s1" SessionNotOnOrAfter="2026-09-29T09:00:00Z"`, 1)
		}, "session"},
		"bad session end": {func(s string) string {
			return strings.Replace(s, `SessionIndex="_s1"`, `SessionIndex="_s1" SessionNotOnOrAfter="later"`, 1)
		}, "not a SAML time"},
	} {
		t.Run(name, func(t *testing.T) {
			el, err := parse([]byte(mk(c.edit)))
			if err != nil {
				t.Fatal(err)
			}
			_, err = sp.assertion(el, idp, p, judgeNow)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
		})
	}

	// And what is kept: OneTimeUse is understood, ePTID's NameID value is
	// written IdP!SP!value, a later session end is fine.
	s := base.xml(false)
	s = strings.Replace(s, "</saml:AudienceRestriction>", "</saml:AudienceRestriction><saml:OneTimeUse/>", 1)
	s = strings.Replace(s, `SessionIndex="_s1"`, `SessionIndex="_s1" SessionNotOnOrAfter="2026-09-29T18:00:00Z"`, 1)
	s = strings.Replace(s, "</saml:AttributeStatement>", `<saml:Attribute Name="`+EduPersonTargetedID+`"><saml:AttributeValue><saml:NameID NameQualifier="`+idpEntity+`" SPNameQualifier="`+spEntity+`">opaque</saml:NameID></saml:AttributeValue></saml:Attribute><saml:Attribute Name="`+Mail+`"><saml:AttributeValue></saml:AttributeValue></saml:Attribute></saml:AttributeStatement>`, 1)
	el, _ := parse([]byte(s))
	a, err := sp.assertion(el, idp, p, judgeNow)
	if err != nil {
		t.Fatal(err)
	}
	if got := a.First(EduPersonTargetedID); got != idpEntity+"!"+spEntity+"!opaque" {
		t.Errorf("ePTID = %q", got)
	}
	if !a.SessionNotOnOrAfter.Equal(time.Date(2026, 9, 29, 18, 0, 0, 0, time.UTC)) {
		t.Error("SessionNotOnOrAfter not read")
	}
	if len(a.Attributes[Mail]) != 1 {
		t.Errorf("an empty value was kept: %q", a.Attributes[Mail])
	}
}

func cut(s, from, to string) string {
	i := strings.Index(s, from)
	j := strings.Index(s[i:], to) + i + len(to)
	return s[:i] + s[j:]
}

func replaceAttr(s, el, attr, val string) string {
	i := strings.Index(s, "<saml:"+el)
	j := strings.Index(s[i:], attr+`="`) + i + len(attr) + 2
	k := strings.Index(s[j:], `"`) + j
	return s[:j] + val + s[k:]
}

func TestMetadataRefusals(t *testing.T) {
	data, cert := renater(t)
	now := at(renaterNow)
	if _, err := ParseMetadata(data, nil, now); err == nil {
		t.Error("metadata without a certificate to check it")
	}
	if _, err := ParseMetadata(data, cert, now.Add(30*24*time.Hour)); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Errorf("expired metadata: %v", err)
	}
	if _, err := ParseMetadata([]byte(`<x/>`), cert, now); err == nil {
		t.Error("a non-metadata document")
	}
	if _, err := ParseMetadata([]byte(`<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"/>`), cert, now); err == nil {
		t.Error("unsigned metadata")
	}
	if _, err := ParseMetadata([]byte(`<`), cert, now); err == nil {
		t.Error("broken XML")
	}
	// Signed by RENATER's key, but by nobody's certificate here.
	w := newWorld(t)
	if _, err := ParseMetadata(data, w.idp.cert, now); err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Errorf("metadata checked against the wrong certificate: %v", err)
	}
}

// Metadata signed by xmlsec1 exercises what RENATER's file does not: no
// validUntil, a nested group that has expired, a regexp scope, an IdP with
// no SAML 2.0 role, one listed twice.
func TestMetadataShapes(t *testing.T) {
	w := newWorld(t)
	sign := func(body string) []byte {
		doc := `<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:shibmd="urn:mace:shibboleth:metadata:1.0" xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui" xmlns:mdattr="urn:oasis:names:tc:SAML:metadata:attribute" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="_md" ` + body
		in := w.file("md.xml", strings.Replace(doc, "<!--SIG-->", sprintf(sigTemplate, rsaSHA256, "_md", dSHA256), 1))
		return w.run("--sign", "--lax-key-search", "--privkey-pem", w.idp.keyFile+","+w.idp.certFile,
			"--id-attr:ID", "urn:oasis:names:tc:SAML:2.0:metadata:EntitiesDescriptor", "--output", "/dev/stdout", in)
	}
	idp := func(id, extra string) string {
		return `<md:EntityDescriptor entityID="` + id + `"><md:Extensions><mdattr:EntityAttributes><saml:Attribute Name="http://macedir.org/entity-category"><saml:AttributeValue>http://refeds.org/category/research-and-scholarship</saml:AttributeValue></saml:Attribute></mdattr:EntityAttributes></md:Extensions>` +
			`<md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:Extensions><shibmd:Scope regexp="false">ok.fr</shibmd:Scope><shibmd:Scope regexp="true">^.*$</shibmd:Scope><mdui:UIInfo><mdui:DisplayName xml:lang="fr">Nom</mdui:DisplayName></mdui:UIInfo><mdui:DiscoHints><mdui:DomainHint>ok.fr</mdui:DomainHint></mdui:DiscoHints></md:Extensions>` +
			`<md:KeyDescriptor use="encryption"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>` + b64(w.sp.cert.Raw) + `</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>` +
			`<md:KeyDescriptor><ds:KeyInfo><ds:X509Data><ds:X509Certificate>` + b64(w.idp.cert.Raw) + `</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>` +
			`<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://` + id + `/post"/>` +
			`<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://` + id + `/redirect"/></md:IDPSSODescriptor>` + extra + `</md:EntityDescriptor>`
	}
	org := `<md:Organization><md:OrganizationName xml:lang="en">O</md:OrganizationName><md:OrganizationDisplayName xml:lang="en">Org name</md:OrganizationDisplayName><md:OrganizationURL xml:lang="en">https://o</md:OrganizationURL></md:Organization>`

	good := sign(`validUntil="2026-10-01T00:00:00Z"><!--SIG-->` + idp("a.fr", "") +
		`<md:EntitiesDescriptor validUntil="2026-01-01T00:00:00Z">` + idp("expired.fr", "") + `</md:EntitiesDescriptor>` +
		`<md:EntityDescriptor entityID="saml1.fr"><md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:1.1:protocol"/></md:EntityDescriptor>` +
		`<md:EntityDescriptor entityID="nosso.fr"><md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"/></md:EntityDescriptor>` +
		`</md:EntitiesDescriptor>`)
	md, err := ParseMetadata(good, w.idp.cert, judgeNow)
	if err != nil {
		t.Fatal(err)
	}
	if len(md.IdPs) != 1 {
		t.Fatalf("%d IdPs: expired groups, SAML 1.1 and SSO-less IdPs must be left out", len(md.IdPs))
	}
	a := md.IdPs["a.fr"]
	if len(a.Scopes) != 1 || a.Scopes[0] != "ok.fr" {
		t.Errorf("scopes = %q: a regexp scope was honoured", a.Scopes)
	}
	if len(a.Keys) != 1 || !a.Keys[0].Equal(w.idp.cert) {
		t.Error("the encryption-only key was taken for signing, or the unmarked one was not")
	}
	if a.SSO != "https://a.fr/redirect" || a.Name("fr") != "Nom" || !a.Has("http://refeds.org/category/research-and-scholarship") || a.Domains[0] != "ok.fr" {
		t.Errorf("idp = %+v", a)
	}

	withOrg := sign(`validUntil="2026-10-01T00:00:00Z" cacheDuration="PT6H"><!--SIG-->` +
		strings.Replace(idp("o.fr", org), `<mdui:UIInfo><mdui:DisplayName xml:lang="fr">Nom</mdui:DisplayName></mdui:UIInfo>`, "", 1) + `</md:EntitiesDescriptor>`)
	md, err = ParseMetadata(withOrg, w.idp.cert, judgeNow)
	if err != nil || md.IdPs["o.fr"].Name() != "Org name" || md.CacheDuration != 6*time.Hour {
		t.Fatalf("the Organization name was not the fallback: %v", err)
	}

	for name, body := range map[string]string{
		"no validUntil":  `><!--SIG-->` + idp("a.fr", "") + `</md:EntitiesDescriptor>`,
		"twice":          `validUntil="2026-10-01T00:00:00Z"><!--SIG-->` + idp("a.fr", "") + idp("a.fr", "") + `</md:EntitiesDescriptor>`,
		"bad validUntil": `validUntil="soon"><!--SIG-->` + `</md:EntitiesDescriptor>`,
		"bad cache":      `validUntil="2026-10-01T00:00:00Z" cacheDuration="1 hour"><!--SIG--></md:EntitiesDescriptor>`,
		"bad nested":     `validUntil="2026-10-01T00:00:00Z"><!--SIG--><md:EntitiesDescriptor validUntil="x"/></md:EntitiesDescriptor>`,
		"bad cert":       `validUntil="2026-10-01T00:00:00Z"><!--SIG-->` + strings.Replace(idp("a.fr", ""), b64(w.idp.cert.Raw), "AAAA", 1) + `</md:EntitiesDescriptor>`,
		"bad base64":     `validUntil="2026-10-01T00:00:00Z"><!--SIG-->` + strings.Replace(idp("a.fr", ""), b64(w.idp.cert.Raw), "!!!", 1) + `</md:EntitiesDescriptor>`,
	} {
		if _, err := ParseMetadata(sign(body), w.idp.cert, judgeNow); err == nil {
			t.Errorf("%s: ACCEPTED", name)
		}
	}
}
