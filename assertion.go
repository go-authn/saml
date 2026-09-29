// SPDX-License-Identifier: BSD-3-Clause

package saml

import (
	"strings"
	"time"
)

// Attribute names, as a federation's IdPs send them: the urn:oid form
// (NameFormat uri), which is what RENATER and eduGAIN use.
const (
	// SubjectID is the scoped, persistent, non-targeted identifier RENATER
	// recommends for research and education (saml-subject-id-attr-v1.0).
	SubjectID = "urn:oasis:names:tc:SAML:attribute:subject-id"
	// PairwiseID is the same but different for every SP, which is what
	// privacy asks for.
	PairwiseID = "urn:oasis:names:tc:SAML:attribute:pairwise-id"

	EduPersonPrincipalName     = "urn:oid:1.3.6.1.4.1.5923.1.1.1.6"
	EduPersonTargetedID        = "urn:oid:1.3.6.1.4.1.5923.1.1.1.10"
	EduPersonAffiliation       = "urn:oid:1.3.6.1.4.1.5923.1.1.1.1"
	EduPersonScopedAffiliation = "urn:oid:1.3.6.1.4.1.5923.1.1.1.9"
	EduPersonEntitlement       = "urn:oid:1.3.6.1.4.1.5923.1.1.1.7"
	EduPersonAssurance         = "urn:oid:1.3.6.1.4.1.5923.1.1.1.11"
	EduPersonOrcid             = "urn:oid:1.3.6.1.4.1.5923.1.1.1.16"
	Mail                       = "urn:oid:0.9.2342.19200300.100.1.3"
	DisplayName                = "urn:oid:2.16.840.1.113730.3.1.241"
	GivenName                  = "urn:oid:2.5.4.42"
	Surname                    = "urn:oid:2.5.4.4"
	CommonName                 = "urn:oid:2.5.4.3"
	UID                        = "urn:oid:0.9.2342.19200300.100.1.1"
	SchacHomeOrganization      = "urn:oid:1.3.6.1.4.1.25178.1.2.9"
	IsMemberOf                 = "urn:oid:1.3.6.1.4.1.5923.1.5.1.1"
	// SupannEtablissement is the French SupAnn schema's establishment code.
	// RENATER says not to depend on SupAnn for eduGAIN users.
	SupannEtablissement = "urn:oid:1.3.6.1.4.1.7135.1.2.1.14"
)

// scoped are the attributes whose values carry a scope after an "@" that the
// IdP's metadata must allow.
var scoped = map[string]bool{
	SubjectID:                  true,
	PairwiseID:                 true,
	EduPersonPrincipalName:     true,
	EduPersonScopedAffiliation: true,
}

// A NameID is the subject's name as the IdP chose to write it. In a research
// federation it is usually transient -- a new value every time -- and the
// person is identified by an attribute instead.
type NameID struct {
	Format, NameQualifier, SPNameQualifier, Value string
}

// An Assertion is what an IdP said about somebody, after every check.
type Assertion struct {
	// IdP is who said it.
	IdP *IdP

	ID     string
	NameID NameID

	AuthnInstant time.Time
	// AuthnContext is the class the IdP authenticated with, e.g.
	// "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
	// or "https://refeds.org/profile/mfa".
	AuthnContext        string
	SessionIndex        string
	SessionNotOnOrAfter time.Time
	NotOnOrAfter        time.Time

	// Attributes by name (the urn:oid form), with scoped values the IdP was
	// not allowed to assert already removed.
	Attributes map[string][]string
}

// First is the first value of an attribute, or "".
func (a *Assertion) First(name string) string {
	if v := a.Attributes[name]; len(v) > 0 {
		return v[0]
	}
	return ""
}

// Subject is the best persistent identifier the IdP released, and which one
// it was -- in RENATER's order of preference: subject-id, then pairwise-id,
// then eduPersonPrincipalName, then the (deprecated) eduPersonTargetedID,
// then a persistent NameID. It is "" when the IdP released none of them,
// which leaves nothing that identifies the same person twice.
//
// ⛔ Mail is never an identifier: it is reassigned and, RENATER notes, can be
// spoofed.
//
// Scoped identifiers compare case-insensitively
// (saml-subject-id-attr-v1.0 3.3.1), so they are returned lower-cased.
func (a *Assertion) Subject() (value, from string) {
	for _, n := range []string{SubjectID, PairwiseID, EduPersonPrincipalName} {
		if v := a.First(n); v != "" {
			if n == EduPersonPrincipalName {
				return v, n
			}
			return strings.ToLower(v), n
		}
	}
	if v := a.First(EduPersonTargetedID); v != "" {
		return v, EduPersonTargetedID
	}
	if a.NameID.Format == "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" && a.NameID.Value != "" {
		return a.NameID.NameQualifier + "!" + a.NameID.SPNameQualifier + "!" + a.NameID.Value, "persistent NameID"
	}
	return "", ""
}
