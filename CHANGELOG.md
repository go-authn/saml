# Changelog

## v0.7.0

- Added to `samltest.Assertion` (#28), for an SP's tests that until now had to
  build these responses with xmlsec1. A zero value writes what v0.6.1 wrote.
  - `Status`: the StatusCode and its nested codes (`Responder` then
    `NoPassive`, for a refused passive login). A Response whose top-level code
    is not Success carries no assertion, encrypted or not.
  - `Subject`: the Subject's NameID in full (`samltest.NameID`: value, format,
    NameQualifier, SPNameQualifier), in place of the transient `NameID`
    string; setting both is refused.
  - `AuthnInstant`: when the IdP says the person authenticated, apart from
    `Now`, so the authentication moves without moving the validity window.
- Added: `samltest.Attribute.NameIDs`, values that are a `saml:NameID`
  element (eduPersonTargetedID as a Shibboleth IdP releases it).
- Each shape is read back by this module's SP, and verified and decrypted by
  xmlsec1 (`TestResponseOptions`, `TestJudgedByXMLSec1`). Without xmlsec1, a
  planted fault (a refusal that keeps its assertion) still turns
  `TestResponseOptions` red.

## v0.6.1

- Added: fuzz targets next to the parser (#21). `FuzzAccept` (a response the
  fuzzer rearranged is refused, or says exactly what the IdP signed; seeded
  with a signed assertion in the clear, a signed Response around an encrypted
  one, and the signature-wrapping layouts XSW1-8), `FuzzParseMetadata`,
  `FuzzDecrypt` (GCM and CBC, the EncryptedKey inside EncryptedData's KeyInfo
  and beside it; CBC is never opened unauthenticated, and what GCM opens is
  what was sealed) and `FuzzLimits` (`limits.check` and `parse` agree on what
  is refused, and `check` allocates in proportion to its input). Seeds come
  from `samltest`; the corpus is committed under `testdata/fuzz` and replayed
  by every `go test`. A planted fault (the CBC gate removed) turns
  `FuzzDecrypt` red from its seeds alone.
- Fuzzed, 130 s each, 16 workers, on one machine at load > 8 (executions, not
  times, are the measure): `FuzzAccept` 1,502,094; `FuzzParseMetadata`
  2,120,800; `FuzzDecrypt` 5,146,715; `FuzzLimits` 1,119,772. No crash, hang or
  property violation was found.
- Added: `TestHostileInputsAreRefusedCheaply`. Under a soft memory limit, an
  entity-expansion bomb (billion laughs), an external entity, 80,000 and
  1,048,576 levels of nesting, 60,000 sibling elements, a 150 KiB CipherValue,
  a response over the cap and an all-whitespace one are each REFUSED, with
  `TotalAlloc` bounded (4 to 8 MiB).
- CI: a `fuzz` job runs each target for 30 s on every push and pull request,
  and keeps the input that broke one as an artifact. (go-authn/kdc and
  go-authn/ldap have no fuzz step; they replay their corpus in `go test`, which
  this repository does too.)
