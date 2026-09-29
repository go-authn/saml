// SPDX-License-Identifier: BSD-3-Clause

package saml

import (
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/beevik/etree"
)

// An IdP is one identity provider as its federation describes it: where to
// send people, which keys sign what comes back, and which scopes it may
// speak for.
type IdP struct {
	// EntityID is the IdP's name in the federation, e.g.
	// "https://idp.univ-example.fr/idp/shibboleth".
	EntityID string

	// SSO is the SingleSignOnService location for the HTTP-Redirect binding,
	// which is where an AuthnRequest goes.
	SSO string

	// Keys are the certificates it signs with. A federation's metadata is
	// what makes them trusted; see verify.
	Keys []*x509.Certificate

	// Scopes are the scopes it may assert scoped values in -- the part after
	// the "@" of eduPersonPrincipalName, subject-id, pairwise-id and
	// eduPersonScopedAffiliation. A value in any other scope is dropped.
	Scopes []string

	// Names are its display names by language ("fr", "en"), from mdui, or
	// failing that from the Organization element. The discovery page shows
	// them.
	Names map[string]string

	// Categories are its entity categories and assurance certifications,
	// e.g. "http://refeds.org/category/research-and-scholarship" or
	// "https://refeds.org/sirtfi".
	Categories []string

	// Domains are the mdui:DomainHint values, which let a discovery page
	// match somebody typing their e-mail domain.
	Domains []string
}

// Name is the IdP's display name in the first of langs that it has, then in
// English, then in any language, then its entity ID.
func (i *IdP) Name(langs ...string) string {
	for _, l := range append(langs, "en") {
		if n := i.Names[l]; n != "" {
			return n
		}
	}
	keys := make([]string, 0, len(i.Names))
	for k := range i.Names {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if n := i.Names[k]; n != "" {
			return n
		}
	}
	return i.EntityID
}

// Has says whether the IdP carries an entity category or certification.
func (i *IdP) Has(category string) bool {
	for _, c := range i.Categories {
		if c == category {
			return true
		}
	}
	return false
}

// inScope says whether a scoped value's scope is one this IdP may assert.
//
// The comparison is case-SENSITIVE, which the Subject Identifier profile
// (saml-subject-id-attr-v1.0, 3.5.2) prescribes "for compatibility reasons"
// even though the values themselves compare case-insensitively.
func (i *IdP) inScope(value string) bool {
	at := strings.LastIndexByte(value, '@')
	if at <= 0 || at == len(value)-1 {
		return false
	}
	scope := value[at+1:]
	for _, s := range i.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// Metadata is a federation's signed list of identity providers.
type Metadata struct {
	// IdPs by entity ID. Only IdPs that speak SAML 2.0 and publish an
	// HTTP-Redirect SingleSignOnService are here; the others could not be
	// sent anybody.
	IdPs map[string]*IdP

	// ValidUntil is when the signer stops vouching for this document. After
	// it, the document is refused, and a server still holding it should
	// stop trusting it rather than keep going on stale keys.
	ValidUntil time.Time

	// CacheDuration is how long the signer suggests keeping it before
	// asking again. Zero when the document does not say.
	CacheDuration time.Duration
}

// IdP returns the identity provider with this entity ID.
func (m *Metadata) IdP(entityID string) (*IdP, bool) {
	i, ok := m.IdPs[entityID]
	return i, ok
}

// Sorted returns the IdPs ordered by display name in the first of langs,
// the order a discovery page lists them in.
func (m *Metadata) Sorted(langs ...string) []*IdP {
	out := make([]*IdP, 0, len(m.IdPs))
	for _, i := range m.IdPs {
		out = append(out, i)
	}
	sort.Slice(out, func(a, b int) bool {
		na, nb := strings.ToLower(out[a].Name(langs...)), strings.ToLower(out[b].Name(langs...))
		if na != nb {
			return na < nb
		}
		return out[a].EntityID < out[b].EntityID
	})
	return out
}

// ParseMetadata verifies a federation's metadata against the certificate its
// operator publishes, and reads the identity providers out of it.
//
//	cert := ... // RENATER's metadata-signature-2026.pem, checked by fingerprint ONCE
//	md, err := saml.ParseMetadata(body, cert, time.Now())
//
// ⛔ The certificate is a parameter, never something fetched alongside the
// metadata: a key that arrives over the same channel as the document it
// vouches for vouches for nothing. RENATER says the same -- download it once,
// check its fingerprint, keep a local copy.
//
// Refused:
//   - a document that is not signed, or not signed by cert, or signed with
//     SHA-1;
//   - a document past its validUntil, or with none at all -- a signed
//     document that never expires is a key compromise that never ends;
//   - a document whose signature covers a different element than the root.
func ParseMetadata(data []byte, cert *x509.Certificate, now time.Time) (*Metadata, error) {
	if cert == nil {
		return nil, errors.New("metadata cannot be trusted without the federation's signing certificate")
	}
	root, err := parse(data)
	if err != nil {
		return nil, err
	}
	if !is(root, nsMetadata, "EntitiesDescriptor") && !is(root, nsMetadata, "EntityDescriptor") {
		return nil, fmt.Errorf("<%s> is not SAML metadata", root.Tag)
	}
	signed, err := verify(root, []*x509.Certificate{cert})
	if err != nil {
		return nil, fmt.Errorf("metadata: %w", err)
	}

	md := &Metadata{IdPs: map[string]*IdP{}}
	vu := signed.SelectAttrValue("validUntil", "")
	if vu == "" {
		return nil, errors.New("metadata has no validUntil: a signed document that never expires is refused")
	}
	if md.ValidUntil, err = instant(vu); err != nil {
		return nil, err
	}
	if !now.Before(md.ValidUntil) {
		return nil, fmt.Errorf("metadata expired at %s", md.ValidUntil.Format(time.RFC3339))
	}
	if cd := signed.SelectAttrValue("cacheDuration", ""); cd != "" {
		if md.CacheDuration, err = duration(cd); err != nil {
			return nil, err
		}
	}
	if err := collect(md, signed, now); err != nil {
		return nil, err
	}
	return md, nil
}

// collect walks nested EntitiesDescriptors, honouring each one's own
// validUntil: a group inside the aggregate can expire before the whole.
func collect(md *Metadata, el *etree.Element, now time.Time) error {
	if vu := el.SelectAttrValue("validUntil", ""); vu != "" {
		t, err := instant(vu)
		if err != nil {
			return err
		}
		if !now.Before(t) {
			return nil
		}
	}
	if is(el, nsMetadata, "EntityDescriptor") {
		idp, err := entity(el)
		if err != nil {
			return err
		}
		if idp != nil {
			if _, dup := md.IdPs[idp.EntityID]; dup {
				return fmt.Errorf("metadata describes %s twice", idp.EntityID)
			}
			md.IdPs[idp.EntityID] = idp
		}
		return nil
	}
	for _, c := range el.ChildElements() {
		if is(c, nsMetadata, "EntitiesDescriptor") || is(c, nsMetadata, "EntityDescriptor") {
			if err := collect(md, c, now); err != nil {
				return err
			}
		}
	}
	return nil
}

// entity reads one EntityDescriptor, returning nil when it is not a SAML 2.0
// identity provider.
func entity(ed *etree.Element) (*IdP, error) {
	id := ed.SelectAttrValue("entityID", "")
	var role *etree.Element
	for _, r := range children(ed, nsMetadata, "IDPSSODescriptor") {
		if hasToken(r.SelectAttrValue("protocolSupportEnumeration", ""), protocolSAML2) {
			role = r
			break
		}
	}
	if role == nil || id == "" {
		return nil, nil
	}
	idp := &IdP{EntityID: id, Names: map[string]string{}}
	for _, s := range children(role, nsMetadata, "SingleSignOnService") {
		if s.SelectAttrValue("Binding", "") == bindingRedirect {
			idp.SSO = s.SelectAttrValue("Location", "")
			break
		}
	}
	if idp.SSO == "" {
		return nil, nil
	}
	for _, kd := range children(role, nsMetadata, "KeyDescriptor") {
		// A key with no "use" is for both; one marked for encryption only is
		// not a signing key, however it is formatted.
		if u := kd.SelectAttrValue("use", ""); u != "" && u != "signing" {
			continue
		}
		for _, c := range descendants(kd, nsDSig, "X509Certificate") {
			der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(c.Text()), ""))
			if err != nil {
				return nil, fmt.Errorf("%s: a signing certificate is not base64: %w", id, err)
			}
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", id, err)
			}
			idp.Keys = append(idp.Keys, cert)
		}
	}
	// Scopes may sit on the entity or on the role; both apply to the role
	// (saml-subject-id-attr-v1.0, 3.5.2).
	for _, holder := range []*etree.Element{ed, role} {
		for _, ext := range children(holder, nsMetadata, "Extensions") {
			for _, s := range children(ext, nsShibMD, "Scope") {
				// ⛔ A regular-expression scope is ignored, not honoured. The
				// profile (3.5.2.2) says deployments SHOULD avoid them and
				// implementations MAY reject them: "extremely easy to write
				// regular expressions which match the desired patterns but also
				// permit additional, sometimes surprising, matches". Not one
				// IdP in RENATER's metadata uses one.
				if r := s.SelectAttrValue("regexp", "false"); r == "true" || r == "1" {
					continue
				}
				if v := text(s); v != "" {
					idp.Scopes = append(idp.Scopes, v)
				}
			}
		}
	}
	for _, ext := range children(role, nsMetadata, "Extensions") {
		for _, ui := range children(ext, nsMDUI, "UIInfo") {
			for _, n := range children(ui, nsMDUI, "DisplayName") {
				if l := n.SelectAttrValue("xml:lang", ""); l != "" && text(n) != "" {
					idp.Names[l] = text(n)
				}
			}
		}
		for _, h := range children(ext, nsMDUI, "DiscoHints") {
			for _, d := range children(h, nsMDUI, "DomainHint") {
				idp.Domains = append(idp.Domains, text(d))
			}
		}
	}
	if len(idp.Names) == 0 {
		for _, o := range children(ed, nsMetadata, "Organization") {
			for _, n := range children(o, nsMetadata, "OrganizationDisplayName") {
				if l := n.SelectAttrValue("xml:lang", ""); l != "" && text(n) != "" {
					idp.Names[l] = text(n)
				}
			}
		}
	}
	for _, ext := range children(ed, nsMetadata, "Extensions") {
		for _, ea := range children(ext, nsMDAttr, "EntityAttributes") {
			for _, a := range children(ea, nsAssertion, "Attribute") {
				switch a.SelectAttrValue("Name", "") {
				case "http://macedir.org/entity-category",
					"http://macedir.org/entity-category-support",
					"urn:oasis:names:tc:SAML:attribute:assurance-certification":
					for _, v := range children(a, nsAssertion, "AttributeValue") {
						idp.Categories = append(idp.Categories, text(v))
					}
				}
			}
		}
	}
	return idp, nil
}

func hasToken(list, tok string) bool {
	for _, f := range strings.Fields(list) {
		if f == tok {
			return true
		}
	}
	return false
}

// duration reads the subset of xs:duration metadata uses: PnDTnHnMnS, with
// no years or months, whose length depends on the calendar.
func duration(s string) (time.Duration, error) {
	bad := fmt.Errorf("%q is not a duration this package reads", s)
	if !strings.HasPrefix(s, "P") || len(s) < 3 {
		return 0, bad
	}
	var d time.Duration
	inTime := false
	num := ""
	for _, r := range s[1:] {
		switch {
		case r >= '0' && r <= '9' || r == '.':
			num += string(r)
			continue
		case r == 'T' && !inTime && num == "":
			inTime = true
			continue
		}
		if num == "" {
			return 0, bad
		}
		var unit time.Duration
		switch {
		case r == 'D' && !inTime:
			unit = 24 * time.Hour
		case r == 'H' && inTime:
			unit = time.Hour
		case r == 'M' && inTime:
			unit = time.Minute
		case r == 'S' && inTime:
			unit = time.Second
		default:
			return 0, bad
		}
		f, err := parseDecimal(num)
		if err != nil {
			return 0, bad
		}
		d += time.Duration(f * float64(unit))
		num = ""
	}
	if num != "" {
		return 0, bad
	}
	return d, nil
}

func parseDecimal(s string) (float64, error) {
	// ParseFloat, not Sscanf: Sscanf stops at the first thing that is not a
	// number and calls "1.2.3" 1.2.
	return strconv.ParseFloat(s, 64)
}
