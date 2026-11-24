// SPDX-License-Identifier: BSD-3-Clause

package saml

import (
	"errors"
	"fmt"
	"net/mail"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/beevik/etree"
)

// The namespace of the REFEDS metadata extensions, whose remd:contactType
// attribute marks a security contact.
const (
	nsREFEDS         = "http://refeds.org/metadata"
	refedsSecurity   = "http://refeds.org/metadata/contactType/security"
	maxMetadataText  = 1024
	maxMetadataURL   = 2048
	maxMetadataItems = 32
)

// Organization is the <md:Organization> of the SP (saml-metadata-2.0-os
// 2.3.2.1). The schema requires at least one of each of the three, so a
// Description that has an Organization must give all three; each is by
// language, "fr" and "en" for a French federation.
type Organization struct {
	Names        map[string]string // <md:OrganizationName>
	DisplayNames map[string]string // <md:OrganizationDisplayName>
	URLs         map[string]string // <md:OrganizationURL>, https
}

// Contact is one <md:ContactPerson> (saml-metadata-2.0-os 2.3.2.2).
type Contact struct {
	// Type is one of "technical", "support", "administrative", "billing" or
	// "other".
	Type string

	// Security marks the REFEDS security contact: the ContactPerson is of type
	// "other" and carries remd:contactType="http://refeds.org/metadata/contactType/security".
	// It requires Type "other".
	Security bool

	GivenName string // optional
	Email     string // a bare address; the metadata carries it as "mailto:<addr>"
}

// Logo is an <mdui:Logo> (SAML V2.0 Metadata Extensions for Login and
// Discovery User Interface, 2.1.5). Width and Height are required there, in
// pixels; Lang is optional, and a logo without one is the default.
type Logo struct {
	URL           string // https
	Width, Height int
	Lang          string
}

var contactTypes = map[string]bool{"technical": true, "support": true, "administrative": true, "billing": true, "other": true}

var langTag = regexp.MustCompile(`^[A-Za-z]{1,8}(-[A-Za-z0-9]{1,8})*$`)

// Validate says why d would give metadata a federation refuses. Metadata
// calls it; a caller that reads its Description from a configuration file calls
// it at start, so that a bad value stops the process there rather than at the
// first request for the metadata.
func (d Description) Validate() error {
	if o := d.Organization; o != nil {
		if err := d.validateOrganization(o); err != nil {
			return err
		}
	}
	if len(d.Contacts) > maxMetadataItems {
		return fmt.Errorf("saml: %d contacts; at most %d", len(d.Contacts), maxMetadataItems)
	}
	for i, c := range d.Contacts {
		if err := c.validate(); err != nil {
			return fmt.Errorf("saml: contact %d: %w", i+1, err)
		}
	}
	if len(d.Logos) > maxMetadataItems {
		return fmt.Errorf("saml: %d logos; at most %d", len(d.Logos), maxMetadataItems)
	}
	seen := map[Logo]bool{}
	for i, l := range d.Logos {
		if err := l.validate(); err != nil {
			return fmt.Errorf("saml: logo %d: %w", i+1, err)
		}
		// The same image MAY be given at several sizes (mdui 2.1.5); the same
		// image, language and size twice is a mistake.
		key := Logo{URL: l.URL, Width: l.Width, Height: l.Height, Lang: strings.ToLower(l.Lang)}
		if seen[key] {
			return fmt.Errorf("saml: logo %d repeats logo %s at %dx%d", i+1, l.URL, l.Width, l.Height)
		}
		seen[key] = true
	}
	if err := langURLs("information_url", d.InformationURLs); err != nil {
		return err
	}
	if err := langURLs("privacy_statement_url", d.PrivacyStatementURLs); err != nil {
		return err
	}
	if d.InformationURL != "" && has(d.InformationURLs, "en") {
		return errors.New(`saml: information_url and an "en" entry of the information URLs both give the English URL`)
	}
	if d.PrivacyStatement != "" && has(d.PrivacyStatementURLs, "en") {
		return errors.New(`saml: privacy_statement_url and an "en" entry of the privacy statement URLs both give the English URL`)
	}
	return nil
}

func (d Description) validateOrganization(o *Organization) error {
	for _, f := range []struct {
		what string
		m    map[string]string
		url  bool
	}{{"organization name", o.Names, false}, {"organization display name", o.DisplayNames, false}, {"organization URL", o.URLs, true}} {
		if len(f.m) == 0 {
			return fmt.Errorf("saml: an organization needs at least one %s (saml-metadata-2.0-os 2.3.2.1)", f.what)
		}
		if err := langMap(f.what, f.m, f.url); err != nil {
			return err
		}
	}
	return nil
}

func has(m map[string]string, k string) bool { _, ok := m[k]; return ok }

// langMap checks a per-language map: language tags that are well formed and
// not given twice (case aside), values that are text or https URLs.
func langMap(what string, m map[string]string, isURL bool) error {
	if len(m) > maxMetadataItems {
		return fmt.Errorf("saml: %s in %d languages; at most %d", what, len(m), maxMetadataItems)
	}
	seen := map[string]string{}
	for _, l := range sorted(m) {
		if !langTag.MatchString(l) {
			return fmt.Errorf("saml: %s: %q is not a language tag", what, l)
		}
		if prev, dup := seen[strings.ToLower(l)]; dup {
			return fmt.Errorf("saml: %s: the language %q is given twice (%q and %q)", what, strings.ToLower(l), prev, l)
		}
		seen[strings.ToLower(l)] = l
		if isURL {
			if err := httpsURL(m[l]); err != nil {
				return fmt.Errorf("saml: %s (%s): %w", what, l, err)
			}
		} else if err := plainText(m[l]); err != nil {
			return fmt.Errorf("saml: %s (%s): %w", what, l, err)
		}
	}
	return nil
}

func langURLs(what string, m map[string]string) error {
	if len(m) == 0 {
		return nil
	}
	return langMap(what, m, true)
}

func plainText(s string) error {
	if strings.TrimSpace(s) == "" {
		return errors.New("empty")
	}
	if len(s) > maxMetadataText {
		return fmt.Errorf("longer than %d bytes", maxMetadataText)
	}
	for _, r := range s {
		if unicode.IsControl(r) || r == unicode.ReplacementChar {
			return errors.New("holds a control or invalid character")
		}
	}
	return nil
}

// httpsURL accepts an absolute https URL with a host, no credentials and no
// fragment: what a federation can show to a person and a browser can fetch
// without a mixed-content warning.
func httpsURL(s string) error {
	if err := plainText(s); err != nil {
		return err
	}
	if len(s) > maxMetadataURL || strings.ContainsAny(s, " \t") {
		return errors.New("not a URL")
	}
	u, err := url.Parse(s)
	if err != nil {
		return fmt.Errorf("not a URL: %w", err)
	}
	switch {
	case u.Scheme != "https":
		return fmt.Errorf("%q is not an https URL", s)
	case u.Hostname() == "":
		return fmt.Errorf("%q has no host", s)
	case u.User != nil:
		return fmt.Errorf("%q holds credentials", s)
	case u.Fragment != "":
		return fmt.Errorf("%q holds a fragment", s)
	}
	return nil
}

func (c Contact) validate() error {
	if !contactTypes[c.Type] {
		return fmt.Errorf("unknown contact type %q (technical, support, administrative, billing or other)", c.Type)
	}
	if c.Security && c.Type != "other" {
		return fmt.Errorf(`a security contact is of type "other", not %q`, c.Type)
	}
	if c.GivenName != "" {
		if err := plainText(c.GivenName); err != nil {
			return fmt.Errorf("given name: %w", err)
		}
	}
	if err := plainText(c.Email); err != nil {
		return fmt.Errorf("email: %w", err)
	}
	a, err := mail.ParseAddress(c.Email)
	if err != nil {
		return fmt.Errorf("email %q: %w", c.Email, err)
	}
	if a.Address != c.Email {
		return fmt.Errorf("email %q is not a bare address (no display name, no brackets)", c.Email)
	}
	return nil
}

func (l Logo) validate() error {
	if err := httpsURL(l.URL); err != nil {
		return err
	}
	if l.Width <= 0 || l.Height <= 0 {
		return fmt.Errorf("width and height are required and positive (mdui 2.1.5); got %dx%d", l.Width, l.Height)
	}
	if l.Lang != "" && !langTag.MatchString(l.Lang) {
		return fmt.Errorf("%q is not a language tag", l.Lang)
	}
	return nil
}

// addOrganization writes <md:Organization>, which follows the role descriptors
// in an EntityDescriptor.
func addOrganization(ed *etree.Element, o *Organization) {
	org := ed.CreateElement("md:Organization")
	for _, f := range []struct {
		tag string
		m   map[string]string
	}{{"md:OrganizationName", o.Names}, {"md:OrganizationDisplayName", o.DisplayNames}, {"md:OrganizationURL", o.URLs}} {
		for _, l := range sorted(f.m) {
			e := org.CreateElement(f.tag)
			e.CreateAttr("xml:lang", l)
			e.SetText(f.m[l])
		}
	}
}

// addContact writes one <md:ContactPerson>; the schema's order inside it is
// GivenName, then EmailAddress.
func addContact(ed *etree.Element, c Contact) {
	p := ed.CreateElement("md:ContactPerson")
	p.CreateAttr("contactType", c.Type)
	if c.Security {
		p.CreateAttr("remd:contactType", refedsSecurity)
	}
	if c.GivenName != "" {
		p.CreateElement("md:GivenName").SetText(c.GivenName)
	}
	p.CreateElement("md:EmailAddress").SetText("mailto:" + c.Email)
}

// addLogos writes the <mdui:Logo> elements of a UIInfo, ordered by language
// (none first), then size, then URL, so that the same Description gives the
// same bytes.
func addLogos(ui *etree.Element, logos []Logo) {
	ls := append([]Logo(nil), logos...)
	sort.SliceStable(ls, func(i, j int) bool {
		a, b := ls[i], ls[j]
		switch {
		case a.Lang != b.Lang:
			return a.Lang < b.Lang
		case a.Width != b.Width:
			return a.Width < b.Width
		case a.Height != b.Height:
			return a.Height < b.Height
		}
		return a.URL < b.URL
	})
	for _, l := range ls {
		e := ui.CreateElement("mdui:Logo")
		e.CreateAttr("height", fmt.Sprint(l.Height))
		e.CreateAttr("width", fmt.Sprint(l.Width))
		if l.Lang != "" {
			e.CreateAttr("xml:lang", l.Lang)
		}
		e.SetText(l.URL)
	}
}

func hasSecurity(cs []Contact) bool {
	for _, c := range cs {
		if c.Security {
			return true
		}
	}
	return false
}
