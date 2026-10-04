package saml

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// Security audit, reproduced before the fix: an IdP of the federation (its own key, its own scope) asserts an
// eduPersonTargetedID qualified by ANOTHER IdP's entity ID. Subject() returns
// exactly the identifier the victim IdP's genuine assertion yields.
func TestAnotherIdPCannotProduceAnIdPsTargetedID(t *testing.T) {
	const evilEntity = "https://idp.evil-univ.fr/idp/shibboleth"
	victimValue := `<saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" NameQualifier="` + idpEntity + `" SPNameQualifier="` + spEntity + `">VICTIM-PTID</saml:NameID>`

	// 1. The genuine assertion from the victim's IdP.
	wv := newWorld(t)
	av := defaultAssertion()
	av.Attributes = map[string][]string{EduPersonTargetedID: {victimValue}}
	gv, err := wv.newSP().Accept(wv.build(av, response{signResponse: true}), wv.pending)
	if err != nil {
		t.Fatal(err)
	}
	vs, vfrom := gv.Subject()
	t.Logf("victim IdP %s -> Subject() = %q from %s", gv.IdP.EntityID, vs, vfrom)

	// 2. A different IdP, own key, own scope, in the same federation.
	for _, form := range []string{victimValue, idpEntity + "!" + spEntity + "!VICTIM-PTID"} {
		w := newWorld(t) // fresh key = the evil IdP's own key
		w.provider.EntityID = evilEntity
		w.provider.Scopes = []string{"evil-univ.fr"}
		w.fed.IdPs = map[string]*IdP{evilEntity: w.provider}
		w.pending.IdP = evilEntity
		a := defaultAssertion()
		a.Issuer = evilEntity
		a.Attributes = map[string][]string{EduPersonTargetedID: {form}}
		got, err := w.newSP().Accept(w.build(a, response{signResponse: true}), w.pending)
		if err != nil {
			t.Fatalf("refused: %v", err)
		}
		s, from := got.Subject()
		t.Logf("evil   IdP %s -> Subject() = %q from %s", got.IdP.EntityID, s, from)
		if s == vs {
			t.Errorf("FORGED: IdP %s produced the victim IdP's identifier %q", evilEntity, s)
		}
	}
}

// Security audit, reproduced before the fix: the same with the Subject's own persistent NameID (assertion.go Subject's last fallback).
func TestAnotherIdPCannotProduceAnIdPsPersistentNameID(t *testing.T) {
	const evilEntity = "https://idp.evil-univ.fr/idp/shibboleth"
	w := newWorld(t)
	w.provider.EntityID = evilEntity
	w.provider.Scopes = []string{"evil-univ.fr"}
	w.fed.IdPs = map[string]*IdP{evilEntity: w.provider}
	w.pending.IdP = evilEntity
	a := defaultAssertion()
	a.Issuer = evilEntity
	a.Attributes = map[string][]string{DisplayName: {"x"}}
	ax := a.xml(false)
	ax = strings.Replace(ax, `<saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">AAdzZWNyZXQx</saml:NameID>`,
		`<saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" NameQualifier="`+idpEntity+`" SPNameQualifier="`+spEntity+`">VICTIM</saml:NameID>`, 1)
	resp := fmt.Sprintf(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r0123456789" Version="2.0" IssueInstant="%s" Destination="%s" InResponseTo="%s"><saml:Issuer>%s</saml:Issuer>%s<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>%s</samlp:Response>`,
		judgeNow.Format(time.RFC3339), acsURL, w.pending.ID, evilEntity, fmt.Sprintf(sigTemplate, rsaSHA256, "_r0123456789", dSHA256), ax)
	in := w.file("response.xml", resp)
	signed := string(w.run("--sign", "--privkey-pem", w.idp.keyFile+","+w.idp.certFile,
		"--id-attr:ID", "urn:oasis:names:tc:SAML:2.0:protocol:Response", "--output", "/dev/stdout", in))
	got, err := w.newSP().Accept(b64([]byte(signed)), w.pending)
	if err != nil {
		t.Fatalf("refused: %v", err)
	}
	s, from := got.Subject()
	t.Logf("evil IdP %s -> Subject() = %q from %s", got.IdP.EntityID, s, from)
	if strings.HasPrefix(s, idpEntity+"!") {
		t.Errorf("FORGED: identifier qualified by %s, asserted by %s", idpEntity, evilEntity)
	}
}

// What is NOT another IdP's is kept, and qualified by the IdP that said it:
// an ePTID NameID with no NameQualifier, and the opaque string form.
func TestAnUnqualifiedTargetedIDIsQualifiedByItsIdP(t *testing.T) {
	for _, tc := range []struct{ value, want string }{
		{`<saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" SPNameQualifier="` + spEntity + `">P1</saml:NameID>`,
			idpEntity + "!" + spEntity + "!P1"},
		{"OPAQUE-P2", idpEntity + "!" + spEntity + "!OPAQUE-P2"},
	} {
		w := newWorld(t)
		a := defaultAssertion()
		a.Attributes = map[string][]string{EduPersonTargetedID: {tc.value}}
		got, err := w.newSP().Accept(w.build(a, response{signResponse: true}), w.pending)
		if err != nil {
			t.Fatal(err)
		}
		if s, _ := got.Subject(); s != tc.want {
			t.Errorf("Subject() = %q, want %q", s, tc.want)
		}
	}
}
