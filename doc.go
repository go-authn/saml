// SPDX-License-Identifier: BSD-3-Clause

// Package saml is a SAML 2.0 service provider for an identity federation such
// as RENATER's Fédération Éducation-Recherche or eduGAIN: it reads the
// federation's signed metadata, sends people to their own identity provider,
// and reads back what that provider says about them.
//
//	fed := &saml.Federation{URL: "https://pub.federation.renater.fr/metadata/fer/idps.xml", Cert: renaterCert}
//	sp  := &saml.SP{EntityID: "https://app.example.org/saml", ACS: "https://app.example.org/saml/acs",
//	                Key: key, Cert: cert, Federation: fed}
//
//	url, pending, err := sp.Request(idp, relayState, saml.Options{})  // redirect the browser there
//	a, err := sp.Accept(r.PostFormValue("SAMLResponse"), pending)     // at the ACS
//	id, from := a.Subject()                                           // subject-id, pairwise-id, eppn...
//
// It is the half of go-authn/bridge that faces the federation; the other
// half is an OpenID Connect provider. It is usable on its own by anything
// that wants to be a SAML SP.
//
// Almost all of the work is refusing things, so the refusals are the
// package:
//
//   - ⛔ Metadata not signed by the certificate the caller pinned, past its
//     validUntil, or with none at all.
//   - ⛔ A response in which neither the Response nor the assertion is
//     signed, or signed with SHA-1.
//   - ⛔ More than one assertion. The profile allows several; accepting them
//     is how a signed one and an unsigned one arrive together and the wrong
//     one is read.
//   - ⛔ Anything read from the document as it arrived rather than from what
//     the signature covered: the verified element is rebuilt from the bytes
//     that were digested, and only it is read.
//   - ⛔ An assertion for another SP, another ACS, another request, an
//     unsolicited one, an expired one, one already used, or one whose
//     conditions it does not understand.
//   - ⛔ A scoped identifier -- eduPersonPrincipalName, subject-id,
//     pairwise-id, eduPersonScopedAffiliation -- in a scope its IdP's metadata
//     does not grant. Without this any of a federation's hundreds of IdPs
//     could say it is alice@another-university.fr.
//   - ⛔ AES-CBC ciphertext that no verified signature covered: it is not even
//     decrypted, because unauthenticated CBC is a padding oracle. RSA PKCS#1
//     v1.5 key transport is not accepted at all.
//   - ⛔ An authentication context other than the one requested, when one was
//     requested: an IdP may ignore the request, and a caller that asked for a
//     second factor must not be told it got one.
package saml
