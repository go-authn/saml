// SPDX-License-Identifier: BSD-3-Clause

package saml

import (
	"bytes"
	"compress/flate"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/beevik/etree"
)

// IdPs is where an SP looks identity providers up: a *Metadata, or a
// *Federation that keeps one fresh.
type IdPs interface {
	IdP(entityID string) (*IdP, bool)
}

// An SP is a SAML 2.0 service provider: it sends people to their identity
// provider and reads what comes back.
type SP struct {
	// EntityID is this SP's name in the federation, as registered.
	EntityID string

	// ACS is the AssertionConsumerService URL, where IdPs POST responses.
	// It is compared exactly with the Destination and Recipient the IdP
	// writes, so it must be spelled as it is in the SP's metadata.
	ACS string

	// Key decrypts assertions and Cert is its certificate, which goes in
	// the SP's metadata. A Shibboleth IdP encrypts assertions by default,
	// so an SP without a key cannot read most of a federation.
	Key  *rsa.PrivateKey
	Cert *x509.Certificate

	// Federation is where IdPs are looked up.
	Federation IdPs

	// Replay remembers the assertions already used. The default is in
	// memory, which is right for one process and wrong for several behind
	// a load balancer: each would accept the same assertion once.
	Replay Replay

	// ClockSkew is how far the IdP's clock may be from this one. Three
	// minutes by default.
	ClockSkew time.Duration

	// Now is the clock. time.Now by default.
	Now func() time.Time

	once sync.Once
}

func (sp *SP) init() {
	sp.once.Do(func() {
		if sp.Replay == nil {
			sp.Replay = NewMemoryReplay()
		}
		if sp.ClockSkew == 0 {
			sp.ClockSkew = 3 * time.Minute
		}
		if sp.Now == nil {
			sp.Now = time.Now
		}
	})
}

// Options change what is asked of the IdP.
type Options struct {
	// ForceAuthn asks the IdP to authenticate the person again even if it
	// has a session for them (OIDC prompt=login).
	ForceAuthn bool

	// IsPassive asks the IdP not to interact with the person at all (OIDC
	// prompt=none). An IdP with no session answers NoPassive.
	IsPassive bool

	// AuthnContext lists the authentication context classes that are
	// acceptable, e.g. "https://refeds.org/profile/mfa". When set, a
	// response whose class is not one of them is REFUSED: an IdP may ignore
	// the request, and a caller that asked for a second factor must not be
	// told it got one when it did not.
	AuthnContext []string
}

// Pending is a request sent and not yet answered. The caller keeps it --
// in the session, keyed by the RelayState -- and hands it back to Accept.
type Pending struct {
	ID           string
	IdP          string
	Issued       time.Time
	AuthnContext []string
	// ForceAuthn is whether the request asked the IdP to authenticate the
	// person again rather than reuse its session: then an AuthnInstant
	// from before the request is refused, not believed.
	ForceAuthn bool
}

// Request builds the URL that sends somebody to idp with an AuthnRequest,
// over the HTTP-Redirect binding.
//
// relayState comes back unchanged with the response; SAML bindings (3.4.3)
// limit it to 80 bytes, and it is refused beyond that rather than silently
// truncated by an IdP. Nothing secret belongs in it: it travels through the
// browser in the clear.
func (sp *SP) Request(idp *IdP, relayState string, o Options) (string, Pending, error) {
	sp.init()
	if len(relayState) > 80 {
		return "", Pending{}, errors.New("RelayState is limited to 80 bytes")
	}
	id, err := newID()
	if err != nil {
		return "", Pending{}, err
	}
	now := sp.Now().UTC()
	doc := etree.NewDocument()
	r := doc.CreateElement("samlp:AuthnRequest")
	r.CreateAttr("xmlns:samlp", nsProtocol)
	r.CreateAttr("xmlns:saml", nsAssertion)
	r.CreateAttr("ID", id)
	r.CreateAttr("Version", "2.0")
	r.CreateAttr("IssueInstant", now.Format("2006-01-02T15:04:05Z"))
	r.CreateAttr("Destination", idp.SSO)
	r.CreateAttr("AssertionConsumerServiceURL", sp.ACS)
	r.CreateAttr("ProtocolBinding", bindingPOST)
	if o.ForceAuthn {
		r.CreateAttr("ForceAuthn", "true")
	}
	if o.IsPassive {
		r.CreateAttr("IsPassive", "true")
	}
	r.CreateElement("saml:Issuer").SetText(sp.EntityID)
	if len(o.AuthnContext) > 0 {
		rac := r.CreateElement("samlp:RequestedAuthnContext")
		rac.CreateAttr("Comparison", "exact")
		for _, c := range o.AuthnContext {
			rac.CreateElement("saml:AuthnContextClassRef").SetText(c)
		}
	}
	raw, err := doc.WriteToBytes()
	if err != nil {
		return "", Pending{}, err
	}
	// HTTP-Redirect: raw DEFLATE, then base64, then the query string
	// (saml-bindings 3.4.4.1).
	var z bytes.Buffer
	w, _ := flate.NewWriter(&z, flate.BestCompression)
	w.Write(raw)
	w.Close()

	u, err := url.Parse(idp.SSO)
	if err != nil {
		return "", Pending{}, err
	}
	q := u.Query()
	q.Set("SAMLRequest", base64.StdEncoding.EncodeToString(z.Bytes()))
	if relayState != "" {
		q.Set("RelayState", relayState)
	}
	u.RawQuery = q.Encode()
	return u.String(), Pending{ID: id, IdP: idp.EntityID, Issued: now, AuthnContext: o.AuthnContext, ForceAuthn: o.ForceAuthn}, nil
}

// newID is an xs:ID: it must not start with a digit, so it starts with "_".
func newID() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "_" + hex.EncodeToString(b), nil
}

// A StatusError is an IdP saying no: the person could not be authenticated,
// or would have had to interact when IsPassive forbade it. It is not an
// attack and is worth telling apart from one -- NoPassive is how OIDC's
// prompt=none learns to answer login_required.
type StatusError struct {
	Code, Sub, Message string
}

func (e *StatusError) Error() string {
	s := "the identity provider answered " + e.Code
	if e.Sub != "" {
		s += " / " + e.Sub
	}
	if e.Message != "" {
		s += ": " + e.Message
	}
	return s
}

// NoPassive says whether the IdP refused because IsPassive was set and it
// would have had to ask the person something.
func (e *StatusError) NoPassive() bool {
	return e.Sub == "urn:oasis:names:tc:SAML:2.0:status:NoPassive"
}

// maxResponse bounds what is decoded before anything is checked. A real
// response with a few dozen attributes is a few kilobytes.
const maxResponse = 256 << 10

// Accept reads the SAMLResponse form field an IdP POSTed to the ACS, as the
// answer to p, and returns the assertion in it.
//
// Everything that is refused is one error to the caller; the error text is
// for the server's log, not for the browser.
func (sp *SP) Accept(samlResponse string, p Pending) (*Assertion, error) {
	sp.init()
	// ⛔ A response answers a request. With no request ID, every check that
	// ties it to one (InResponseTo, the bearer confirmation) compares two
	// empty strings and passes: an IdP-initiated response, which this
	// library does not accept -- it is how login CSRF is done.
	if p.ID == "" {
		return nil, errors.New("no request to answer: unsolicited responses are refused")
	}
	if !p.Issued.IsZero() && sp.Now().Sub(p.Issued) > maxPendingAge {
		return nil, fmt.Errorf("the request was made more than %s ago", maxPendingAge)
	}
	if len(samlResponse) > maxResponse {
		return nil, errors.New("the response is too large")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(samlResponse), ""))
	if err != nil {
		return nil, fmt.Errorf("SAMLResponse is not base64: %w", err)
	}
	root, err := parse(raw, responseLimits)
	if err != nil {
		return nil, err
	}
	if !is(root, nsProtocol, "Response") {
		return nil, fmt.Errorf("<%s> is not a Response", root.Tag)
	}
	now := sp.Now()

	// The IdP is the one the request went to, looked up again NOW: keys
	// rotate, and an IdP removed from the federation since the request was
	// sent is not one to believe.
	idp, ok := sp.Federation.IdP(p.IdP)
	if !ok {
		return nil, fmt.Errorf("%s is not in the federation", p.IdP)
	}

	// ââ The response ââââââââââââââââââââââââââââââââââââââââââââââââââ
	resp := root
	signedResponse := len(children(root, nsDSig, "Signature")) > 0
	if signedResponse {
		if resp, err = verify(detach(root), idp.Keys); err != nil {
			return nil, fmt.Errorf("response: %w", err)
		}
	}
	if v := resp.SelectAttrValue("Version", ""); v != "2.0" {
		return nil, fmt.Errorf("response version %q", v)
	}
	// saml-bindings 3.5.5.2: a signed POSTed message MUST carry a
	// Destination, and the receiver MUST check it. An unsigned one is
	// checked when it has one.
	dest := resp.SelectAttrValue("Destination", "")
	if (signedResponse || dest != "") && dest != sp.ACS {
		return nil, fmt.Errorf("the response is addressed to %q, not to this ACS", dest)
	}
	if irt := resp.SelectAttrValue("InResponseTo", ""); irt != p.ID {
		return nil, errors.New("the response does not answer this request")
	}
	if err := issuer(resp, idp, false); err != nil {
		return nil, err
	}
	if err := status(resp); err != nil {
		return nil, err
	}

	// ââ The assertion âââââââââââââââââââââââââââââââââââââââââââââââââ
	// â Exactly one. The profile allows several; accepting several is how
	// a signed assertion and an unsigned one arrive together and the wrong
	// one is read (CVE-2022-41912 in crewjam/saml).
	plain := children(resp, nsAssertion, "Assertion")
	enc := children(resp, nsAssertion, "EncryptedAssertion")
	if len(plain)+len(enc) != 1 {
		return nil, fmt.Errorf("the response carries %d assertions, where exactly one is accepted", len(plain)+len(enc))
	}
	var a *etree.Element
	if len(enc) == 1 {
		if a, err = sp.decrypt(enc[0], signedResponse); err != nil {
			return nil, err
		}
	} else {
		a = detach(plain[0])
	}
	if len(children(a, nsDSig, "Signature")) > 0 {
		if a, err = verify(a, idp.Keys); err != nil {
			return nil, fmt.Errorf("assertion: %w", err)
		}
	} else if !signedResponse {
		// saml-profiles 4.1.4.5: over POST the assertion MUST be signed. A
		// signature on the Response covers it too -- it is what a Shibboleth
		// IdP does by default -- but one of the two there has to be.
		return nil, errors.New("neither the response nor the assertion is signed")
	}
	return sp.assertion(a, idp, p, now)
}

// issuer checks an Issuer element: the IdP's entity ID, in the entity format
// or none (saml-profiles 4.1.4.2). The Response's may be omitted; the
// assertion's may not.
func issuer(el *etree.Element, idp *IdP, required bool) error {
	iss, err := optional(el, nsAssertion, "Issuer")
	if err != nil {
		return err
	}
	if iss == nil {
		if required {
			return errors.New("the assertion has no Issuer")
		}
		return nil
	}
	if f := iss.SelectAttrValue("Format", formatEntity); f != formatEntity {
		return fmt.Errorf("issuer format %q", f)
	}
	if text(iss) != idp.EntityID {
		return fmt.Errorf("issued by %q, but the request went to %q", text(iss), idp.EntityID)
	}
	return nil
}

func status(resp *etree.Element) error {
	st, err := child(resp, nsProtocol, "Status")
	if err != nil {
		return err
	}
	code, err := child(st, nsProtocol, "StatusCode")
	if err != nil {
		return err
	}
	if v := code.SelectAttrValue("Value", ""); v != statusSuccess {
		e := &StatusError{Code: v}
		if sub, _ := optional(code, nsProtocol, "StatusCode"); sub != nil {
			e.Sub = sub.SelectAttrValue("Value", "")
		}
		if m, _ := optional(st, nsProtocol, "StatusMessage"); m != nil {
			e.Message = text(m)
		}
		return e
	}
	return nil
}

// assertion checks a verified assertion and reads it.
func (sp *SP) assertion(a *etree.Element, idp *IdP, p Pending, now time.Time) (*Assertion, error) {
	if !is(a, nsAssertion, "Assertion") {
		return nil, fmt.Errorf("<%s> is not an Assertion", a.Tag)
	}
	if v := a.SelectAttrValue("Version", ""); v != "2.0" {
		return nil, fmt.Errorf("assertion version %q", v)
	}
	out := &Assertion{IdP: idp, ID: a.SelectAttrValue("ID", ""), Attributes: map[string][]string{}}
	if out.ID == "" {
		return nil, errors.New("the assertion has no ID")
	}
	if err := issuer(a, idp, true); err != nil {
		return nil, err
	}
	skew := sp.ClockSkew

	// ââ Subject: a bearer confirmation for this ACS, this request, now ââ
	subj, err := child(a, nsAssertion, "Subject")
	if err != nil {
		return nil, err
	}
	if n, err := optional(subj, nsAssertion, "NameID"); err != nil {
		return nil, err
	} else if n != nil {
		out.NameID = nameID(n)
		// ⛔ A persistent NameID is unscoped: only its NameQualifier says
		// whose it is, and the IdP writes that itself. One naming another IdP
		// is not believed (Subject will not use it); an empty one is this
		// IdP's. Without this, any IdP of the federation could produce
		// another's persistent identifier byte for byte (security audit).
		if out.NameID.NameQualifier == "" {
			out.NameID.NameQualifier = idp.EntityID
		}
	}
	var expires time.Time
	for _, sc := range children(subj, nsAssertion, "SubjectConfirmation") {
		if sc.SelectAttrValue("Method", "") != cmBearer {
			continue
		}
		d, err := child(sc, nsAssertion, "SubjectConfirmationData")
		if err != nil {
			continue
		}
		if e, ok := bearer(d, sp.ACS, p.ID, now, skew); ok {
			expires = e
			break
		}
	}
	if expires.IsZero() {
		return nil, errors.New("no bearer confirmation is for this ACS, this request, and now")
	}

	// ââ Conditions ââââââââââââââââââââââââââââââââââââââââââââââââââââ
	cond, err := child(a, nsAssertion, "Conditions")
	if err != nil {
		return nil, err
	}
	if nb := cond.SelectAttrValue("NotBefore", ""); nb != "" {
		t, err := instant(nb)
		if err != nil {
			return nil, err
		}
		if now.Add(skew).Before(t) {
			return nil, errors.New("the assertion is not valid yet")
		}
	}
	if na := cond.SelectAttrValue("NotOnOrAfter", ""); na != "" {
		t, err := instant(na)
		if err != nil {
			return nil, err
		}
		if !now.Add(-skew).Before(t) {
			return nil, errors.New("the assertion has expired")
		}
		out.NotOnOrAfter = t
	}
	audienced := false
	for _, c := range cond.ChildElements() {
		switch {
		case is(c, nsAssertion, "AudienceRestriction"):
			// Several restrictions must ALL hold (saml-core 2.5.1.4): each
			// one has to name this SP.
			found := false
			for _, au := range children(c, nsAssertion, "Audience") {
				if text(au) == sp.EntityID {
					found = true
				}
			}
			if !found {
				return nil, errors.New("the assertion is addressed to another audience")
			}
			audienced = true
		case is(c, nsAssertion, "OneTimeUse"), is(c, nsAssertion, "ProxyRestriction"):
			// OneTimeUse is what the replay cache does to every assertion
			// anyway.
		default:
			// saml-core 2.5.1: a condition the relying party does not
			// understand makes the assertion Indeterminate, not valid.
			return nil, fmt.Errorf("condition <%s> is not understood", c.Tag)
		}
	}
	if !audienced {
		return nil, errors.New("the assertion names no audience")
	}

	// ââ Authentication ââââââââââââââââââââââââââââââââââââââââââââââââ
	stmts := children(a, nsAssertion, "AuthnStatement")
	if len(stmts) == 0 {
		return nil, errors.New("the assertion has no AuthnStatement")
	}
	as := stmts[0]
	if out.AuthnInstant, err = instant(as.SelectAttrValue("AuthnInstant", "")); err != nil {
		return nil, err
	}
	if p.ForceAuthn && out.AuthnInstant.Before(p.Issued.Add(-skew)) {
		return nil, fmt.Errorf("authentication was forced, and the IdP answered with one from %s, before the request", out.AuthnInstant.Format(time.RFC3339))
	}
	out.SessionIndex = as.SelectAttrValue("SessionIndex", "")
	if s := as.SelectAttrValue("SessionNotOnOrAfter", ""); s != "" {
		if out.SessionNotOnOrAfter, err = instant(s); err != nil {
			return nil, err
		}
		if !now.Before(out.SessionNotOnOrAfter) {
			return nil, errors.New("the IdP session behind this assertion has ended")
		}
	}
	if ac, _ := optional(as, nsAssertion, "AuthnContext"); ac != nil {
		if ref, _ := optional(ac, nsAssertion, "AuthnContextClassRef"); ref != nil {
			out.AuthnContext = text(ref)
		}
	}
	if len(p.AuthnContext) > 0 && !contains(p.AuthnContext, out.AuthnContext) {
		return nil, fmt.Errorf("authentication context %q was not one of those requested", out.AuthnContext)
	}

	// ââ Attributes ââââââââââââââââââââââââââââââââââââââââââââââââââââ
	for _, st := range children(a, nsAssertion, "AttributeStatement") {
		for _, at := range children(st, nsAssertion, "Attribute") {
			name := at.SelectAttrValue("Name", "")
			for _, v := range children(at, nsAssertion, "AttributeValue") {
				val := text(v)
				if n, _ := optional(v, nsAssertion, "NameID"); n != nil {
					// eduPersonTargetedID's value is a NameID, written the
					// way Shibboleth writes it: IdP!SP!value.
					id := nameID(n)
					// ⛔ The qualifier is the IdP's own claim about whose
					// identifier this is. Only the IdP that signed may be
					// named; an empty one is that IdP (security audit: any
					// IdP of the federation produced another's ePTID).
					switch id.NameQualifier {
					case "":
						id.NameQualifier = idp.EntityID
					case idp.EntityID:
					default:
						continue
					}
					val = id.NameQualifier + "!" + id.SPNameQualifier + "!" + id.Value
				} else if name == EduPersonTargetedID && val != "" {
					// The older string form, IdP!SP!value, is held to the same
					// rule; an opaque value is qualified by the IdP that said it.
					if i := strings.IndexByte(val, '!'); i < 0 {
						val = idp.EntityID + "!" + sp.EntityID + "!" + val
					} else if val[:i] != idp.EntityID {
						continue
					}
				}
				// â A scoped value from outside the IdP's scopes is
				// DROPPED. Without this, any IdP in a federation of hundreds
				// could say it is alice@another-university.fr, and every
				// application keyed on eduPersonPrincipalName would believe
				// it (saml-subject-id-attr-v1.0 3.5.2).
				if scoped[name] && !idp.inScope(val) {
					continue
				}
				// subject-id and pairwise-id have a grammar (saml-subject-id-attr-
				// v1.0 3.2, 3.3): ASCII, one @. A value outside it is not one.
				if (name == SubjectID || name == PairwiseID) && !subjectIDSyntax.MatchString(val) {
					continue
				}
				if val != "" {
					out.Attributes[name] = append(out.Attributes[name], val)
				}
			}
		}
	}

	// ââ Replay: last, so an invalid assertion does not burn its ID ââââ
	if !sp.Replay.Use(idp.EntityID+" "+out.ID, expires) {
		return nil, errors.New("this assertion has already been used")
	}
	return out, nil
}

// bearer checks one bearer SubjectConfirmationData (saml-profiles 4.1.4.2
// and 4.1.4.3), returning how long the assertion may be delivered for.
func bearer(d *etree.Element, acs, requestID string, now time.Time, skew time.Duration) (time.Time, bool) {
	if d.SelectAttrValue("Recipient", "") != acs {
		return time.Time{}, false
	}
	// "It MUST NOT contain a NotBefore attribute."
	if d.SelectAttrValue("NotBefore", "") != "" {
		return time.Time{}, false
	}
	// Unsolicited responses are not accepted: InResponseTo must be the
	// request this SP sent.
	if d.SelectAttrValue("InResponseTo", "") != requestID {
		return time.Time{}, false
	}
	t, err := instant(d.SelectAttrValue("NotOnOrAfter", ""))
	if err != nil || !now.Add(-skew).Before(t) {
		return time.Time{}, false
	}
	return t.Add(skew), true
}

func nameID(n *etree.Element) NameID {
	return NameID{
		Format:          n.SelectAttrValue("Format", ""),
		NameQualifier:   n.SelectAttrValue("NameQualifier", ""),
		SPNameQualifier: n.SelectAttrValue("SPNameQualifier", ""),
		Value:           text(n),
	}
}

func contains(list []string, s string) bool {
	for _, l := range list {
		if l == s {
			return true
		}
	}
	return false
}

// maxPendingAge is how long a request may wait for its response: a login
// left open for an hour is not one to complete.
const maxPendingAge = time.Hour

// subjectIDSyntax is the ABNF of saml-subject-id-attr-v1.0 3.2 and 3.3.
var subjectIDSyntax = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9=-]{0,126}@[a-zA-Z0-9][a-zA-Z0-9.-]{0,126}$`)
