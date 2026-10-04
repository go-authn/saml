# saml

[![Go Reference](https://pkg.go.dev/badge/github.com/go-authn/saml.svg)](https://pkg.go.dev/github.com/go-authn/saml)
[![License](https://img.shields.io/badge/license-BSD--3--Clause-0A6E96?style=flat-square)](LICENSE)
[![CI](https://github.com/go-authn/saml/actions/workflows/ci.yml/badge.svg)](https://github.com/go-authn/saml/actions/workflows/ci.yml)

**A SAML 2.0 service provider for an identity federation** such as RENATER's
Fédération Éducation-Recherche or eduGAIN. It reads the federation's signed
metadata, sends people to their own university's identity provider, and reads
back what that provider says about them. Pure Go, `CGO_ENABLED=0`.

```go
fed := &saml.Federation{
    URL:  "https://pub.federation.renater.fr/metadata/fer/idps.xml",
    Cert: renaterCert, // metadata-signature-2026.pem, checked ONCE by fingerprint
}
if err := fed.Refresh(ctx); err != nil { ... }
go fed.Run(ctx, logError)

sp := &saml.SP{
    EntityID:   "https://app.example.org/saml",
    ACS:        "https://app.example.org/saml/acs",
    Key:        key, Cert: cert, // assertions arrive encrypted to this key
    Federation: fed,
}

url, pending, err := sp.Request(idp, relayState, saml.Options{}) // redirect there
a, err := sp.Accept(r.PostFormValue("SAMLResponse"), pending)    // at the ACS
id, from := a.Subject() // subject-id, then pairwise-id, then eppn...
```

It is the half of [go-authn/bridge](https://github.com/go-authn/bridge) that
faces the federation. The other half is an OpenID Connect provider.

## What a federation sends, and what it takes to read it

| | |
|---|---|
| **Metadata** | One signed document listing every IdP: 343 in RENATER's `fer/idps.xml`, 2.2 MB. eduGAIN's is 56 MB. Valid for nine days, re-read every 45 minutes. |
| **Signatures** | `rsa-sha256` over exclusive canonicalisation. A Shibboleth IdP signs the **Response** by default, not the assertion; both are accepted, one of them has to be there. |
| **Encryption** | On by default in a Shibboleth IdP. **AES-128-GCM** on a fresh install, **AES-CBC** on an older one, key transport **RSA-OAEP**. All of these are read. |
| **Identifiers** | RENATER recommends `subject-id`, then `pairwise-id`, then `eduPersonPrincipalName`. `eduPersonTargetedID` is deprecated. **Mail is not an identifier.** |

## What it refuses

| | why |
|---|---|
| metadata not signed by the **pinned** certificate | the certificate is a parameter, never fetched alongside the metadata: a key that arrives over the same channel as the document it vouches for vouches for nothing |
| metadata past its `validUntil`, or with **none** | a signed document that never expires is a key compromise that never ends. A failed refresh keeps the last good copy, until that copy expires |
| metadata valid for **more than 28 days** from now | a document valid for years is one a replay keeps alive for years. `Federation.MaxValidity` changes the bound; a negative value removes it |
| metadata **older** than the copy in use | it is validly signed and not yet expired, and it may be the one carrying a key since revoked, served by whoever stands on the path |
| nothing signed, or signed with **SHA-1** | saml-profiles 4.1.4.5: over POST the assertion must be signed |
| **more than one** assertion | the profile allows several; accepting them is how a signed one and an unsigned one arrive together and the wrong one is read (CVE-2022-41912) |
| anything but **what the signature covered** | only the element rebuilt from the digested bytes is read afterwards, never the document as it arrived |
| a **scoped identifier outside the IdP's scopes** | without this any of hundreds of IdPs could say it is `alice@another-university.fr`, and everything keyed on eppn would believe it |
| **CBC ciphertext nobody signed** | it is not even decrypted: unauthenticated CBC is a padding oracle ("XML Encryption is broken", 2011). RSA PKCS#1 v1.5 key transport is not accepted at all |
| another audience, ACS, request, an **unsolicited** response | saml-profiles 4.1.4.3 |
| an assertion **already used** | a bearer assertion is whoever holds it; the replay cache keeps its ID until it expires |
| a **condition** it does not understand | saml-core 2.5.1: that makes the assertion Indeterminate, not valid |
| MFA asked for, **password** returned | an IdP may ignore `RequestedAuthnContext`; a caller that asked for a second factor must not be told it got one |
| a **regular-expression scope** | the Subject Identifier profile says implementations MAY reject them, and not one IdP in RENATER uses one |

## Keys in metadata are trusted because metadata names them

A federation's IdP certificates are usually self-signed and often expired. That
is normal: the federation's signature over the metadata is what makes the key
trusted, and the certificate is only a way of carrying it. A verifier that
enforced the dates would refuse a working IdP; this one does not look at them.

## Verified against things this repository did not produce

- **RENATER's own metadata**, as RENATER signed it on 2026-09-29, is in
  `testdata/`. Its certificate is checked against the SHA-256 fingerprint
  RENATER publishes, not against itself. All 343 IdPs are read, each with a
  signing key and a scope, and a one-byte change to one `Location` is
  refused. The clock is fixed there, because the file expires. The
  architecture lanes, **s390x** included, verify that signature too.
- **xmlsec1** signs and encrypts every response in the suite, from templates:
  GCM and CBC, RSA-OAEP with SHA-1 and with SHA-256/MGF1-SHA256, Response
  signed, assertion signed, both. The package only verifies and decrypts.
- **crewjam/saml's IdP** writes whole responses to this SP's AuthnRequests,
  through the HTTP-Redirect and HTTP-POST bindings, from metadata scoped and
  signed like a federation's (`interop/crewjam`, a module of its own): signed
  with RSA-SHA256 and encrypted AES-128-CBC with the Response signed, they are
  accepted; its default RSA-SHA1 is refused by name; and the same CBC assertion
  with the Response signature removed is refused before decryption.
- The refusals were **sabotage-checked**: removing the scope filter, the CBC
  gate, the audience check, the single-assertion rule, the SHA-1 refusal and
  the replay cache each turns a test red.
- One rule could **not** be given a witness: reading the verified element
  rather than the arriving document. Every difference between the two is
  either caught by the digest or normalised by etree the same way
  canonicalisation normalises it. It stands as defence in depth, and the test
  that looks like its witness says so.

## What a deployment adds

- **Its own metadata.** `sp.Metadata(saml.Description{...})` writes the SP
  metadata the federation registers: the entity ID, the ACS, and the key,
  published without a `use` so it serves for signing and encryption, with GCM
  listed before CBC so an IdP that honours the list does not fall back.
- **Discovery.** `saml.DiscoveryURL(service, entityID, returnURL)` sends the
  person to the federation's discovery service, and `saml.Chosen(query, fed)`
  reads the IdP it sends back, refusing one that is not in the federation: the
  parameter comes through the browser, and anybody can type an entity ID.
- **⛔ A replay cache that spans the deployment.** `SP.Replay` defaults to
  `NewMemoryReplay()`, one process's memory. That is right for one process and
  wrong for several behind a load balancer: each would accept the same
  assertion once. A restart empties it too. Several instances implement
  `Replay` over shared storage; its `Use` must be atomic, so that two requests
  carrying the same assertion at the same moment get one `true` and one
  `false`.

## Upgrading to v0.3.0: some identifiers change

v0.3.0 holds an unscoped identifier to the IdP that signed it (an IdP of the
federation could otherwise produce another's, byte for byte). For honest IdPs,
two shapes of `Subject()` change:

| an IdP that sends | before v0.3.0 | from v0.3.0 |
|---|---|---|
| an opaque string `eduPersonTargetedID` `v` | `v` | `IdP!SP!v` |
| an ePTID or persistent NameID with no `NameQualifier` | `!SPQ!v` | `IdP!SPQ!v` |

Everything else (subject-id, pairwise-id, eppn, and identifiers already
qualified by their own IdP) is unchanged. **A stored identifier of those two
shapes no longer matches**: whoever keyed accounts on `Subject()` meets those
people as new. It cannot be mapped back automatically, because the old form
of the second row is the same for two IdPs that left the qualifier empty,
which is the collision this release removes. A deployment that stored them
maps each one to its IdP (it knows which IdP each session came from) before
upgrading, or stays on v0.2.x, accepting that risk.

## What it is not

No SAML IdP, no Single Logout, no artifact binding, no signed AuthnRequests
(RENATER does not require them). No attribute query. No SAML 1.1: every IdP
in RENATER's metadata also speaks 2.0.

## Licence

BSD-3-Clause.
