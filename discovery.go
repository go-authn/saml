// SPDX-License-Identifier: BSD-3-Clause

package saml

import (
	"errors"
	"net/url"
	"strings"
)

// DiscoveryURL sends somebody to a discovery service to choose their IdP,
// per the SAML IdP Discovery Protocol (sstc-saml-idp-discovery, 2.4.1):
// entityID is this SP, and the service sends them back to returnURL with the
// chosen IdP in the "entityID" parameter.
//
//	saml.DiscoveryURL("https://discovery.renater.fr/renater", sp.EntityID, back)
//
// RENATER's service lists every IdP of the federation and cannot be
// restricted; an SP that trusts fewer runs its own page instead, from
// Metadata.Sorted.
func DiscoveryURL(service, spEntityID, returnURL string) (string, error) {
	u, err := url.Parse(service)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("entityID", spEntityID)
	q.Set("return", returnURL)
	q.Set("returnIDParam", "entityID")
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// Chosen reads the IdP a discovery service sent back, and refuses one that
// is not in the federation: the parameter comes through the browser, and
// anybody can type an entity ID.
func Chosen(q url.Values, federation IdPs) (*IdP, error) {
	id := strings.TrimSpace(q.Get("entityID"))
	if id == "" {
		return nil, errors.New("no identity provider was chosen")
	}
	idp, ok := federation.IdP(id)
	if !ok {
		return nil, errors.New("the chosen identity provider is not in the federation")
	}
	return idp, nil
}
