module github.com/go-authn/saml/interop/crewjam

go 1.26.4

replace github.com/go-authn/saml => ../..

require (
	github.com/beevik/etree v1.8.1
	github.com/crewjam/saml v0.5.1
	github.com/go-authn/saml v0.0.0-00010101000000-000000000000
	github.com/russellhaering/goxmldsig v1.6.1
)

require (
	github.com/jonboulle/clockwork v0.5.0 // indirect
	github.com/mattermost/xml-roundtrip-validator v0.1.0 // indirect
	golang.org/x/crypto v0.33.0 // indirect
)
