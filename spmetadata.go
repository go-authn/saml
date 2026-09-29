// SPDX-License-Identifier: BSD-3-Clause

package saml

import (
	"encoding/base64"
	"errors"
	"sort"

	"github.com/beevik/etree"
)

// Description is what a federation registry asks about an SP. RENATER's
// technical framework makes a French name and description, a technical
// contact and (for the Code of Conduct) a privacy statement obligatory.
type Description struct {
	// Names and Descriptions by language: "fr" is required by RENATER, "en"
	// by eduGAIN.
	Names        map[string]string
	Descriptions map[string]string

	InformationURL   string
	PrivacyStatement string

	// Discovery is where a discovery service may send people back to with
	// the IdP they chose (SAML IdP Discovery Protocol 2.4.1). A discovery
	// service SHOULD refuse to return anywhere not listed here.
	Discovery string

	// Technical is the technical contact's e-mail address -- a person, per
	// RENATER, not a list.
	Technical string

	// Attributes are the attributes the SP asks for. RENATER wants each one
	// justified at registration; the list here is what goes in the metadata.
	Attributes []string
}

// Metadata is the SP's own metadata, to register with the federation.
//
// The key is published without a "use", so it serves for both signing and
// encryption, and with the encryption methods it prefers: GCM first, so that
// an IdP that honours the list does not fall back to CBC.
func (sp *SP) Metadata(d Description) ([]byte, error) {
	if sp.Cert == nil {
		return nil, errors.New("an SP without a certificate cannot receive encrypted assertions")
	}
	if d.Names["fr"] == "" && d.Names["en"] == "" {
		return nil, errors.New("an SP needs a display name")
	}
	doc := etree.NewDocument()
	doc.CreateProcInst("xml", `version="1.0" encoding="UTF-8"`)
	ed := doc.CreateElement("md:EntityDescriptor")
	ed.CreateAttr("xmlns:md", nsMetadata)
	ed.CreateAttr("xmlns:ds", nsDSig)
	ed.CreateAttr("xmlns:mdui", nsMDUI)
	ed.CreateAttr("xmlns:idpdisc", nsIdPDisco)
	ed.CreateAttr("xmlns:saml", nsAssertion)
	ed.CreateAttr("entityID", sp.EntityID)

	role := ed.CreateElement("md:SPSSODescriptor")
	role.CreateAttr("protocolSupportEnumeration", protocolSAML2)
	role.CreateAttr("AuthnRequestsSigned", "false")
	role.CreateAttr("WantAssertionsSigned", "true")

	ext := role.CreateElement("md:Extensions")
	if d.Discovery != "" {
		dr := ext.CreateElement("idpdisc:DiscoveryResponse")
		dr.CreateAttr("Binding", nsIdPDisco)
		dr.CreateAttr("Location", d.Discovery)
		dr.CreateAttr("index", "1")
	}
	ui := ext.CreateElement("mdui:UIInfo")
	for _, l := range sorted(d.Names) {
		n := ui.CreateElement("mdui:DisplayName")
		n.CreateAttr("xml:lang", l)
		n.SetText(d.Names[l])
	}
	for _, l := range sorted(d.Descriptions) {
		n := ui.CreateElement("mdui:Description")
		n.CreateAttr("xml:lang", l)
		n.SetText(d.Descriptions[l])
	}
	if d.InformationURL != "" {
		n := ui.CreateElement("mdui:InformationURL")
		n.CreateAttr("xml:lang", "en")
		n.SetText(d.InformationURL)
	}
	if d.PrivacyStatement != "" {
		n := ui.CreateElement("mdui:PrivacyStatementURL")
		n.CreateAttr("xml:lang", "en")
		n.SetText(d.PrivacyStatement)
	}

	kd := role.CreateElement("md:KeyDescriptor")
	kd.CreateElement("ds:KeyInfo").CreateElement("ds:X509Data").CreateElement("ds:X509Certificate").
		SetText(base64.StdEncoding.EncodeToString(sp.Cert.Raw))
	for _, a := range []string{
		"http://www.w3.org/2009/xmlenc11#aes128-gcm",
		"http://www.w3.org/2009/xmlenc11#aes256-gcm",
		oaep11,
		oaepMGF1P,
	} {
		kd.CreateElement("md:EncryptionMethod").CreateAttr("Algorithm", a)
	}

	acs := role.CreateElement("md:AssertionConsumerService")
	acs.CreateAttr("Binding", bindingPOST)
	acs.CreateAttr("Location", sp.ACS)
	acs.CreateAttr("index", "0")
	acs.CreateAttr("isDefault", "true")

	if len(d.Attributes) > 0 {
		acsvc := role.CreateElement("md:AttributeConsumingService")
		acsvc.CreateAttr("index", "0")
		for _, l := range sorted(d.Names) {
			n := acsvc.CreateElement("md:ServiceName")
			n.CreateAttr("xml:lang", l)
			n.SetText(d.Names[l])
		}
		for _, a := range d.Attributes {
			ra := acsvc.CreateElement("md:RequestedAttribute")
			ra.CreateAttr("Name", a)
			ra.CreateAttr("NameFormat", "urn:oasis:names:tc:SAML:2.0:attrname-format:uri")
		}
	}

	if d.Technical != "" {
		c := ed.CreateElement("md:ContactPerson")
		c.CreateAttr("contactType", "technical")
		c.CreateElement("md:EmailAddress").SetText("mailto:" + d.Technical)
	}
	doc.Indent(2)
	return doc.WriteToBytes()
}

func sorted(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
