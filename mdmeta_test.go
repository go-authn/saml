// SPDX-License-Identifier: BSD-3-Clause

package saml

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/beevik/etree"
)

// fullDescription sets every optional block.
func fullDescription() Description {
	return Description{
		Names:            map[string]string{"fr": "Passerelle OIDC", "en": "OIDC bridge"},
		Descriptions:     map[string]string{"fr": "Connexion fédérée", "en": "Federated sign-in"},
		InformationURL:   "https://bridge.example.org/",
		PrivacyStatement: "https://bridge.example.org/privacy",
		Discovery:        "https://bridge.example.org/saml/disco",
		Technical:        "noc@example.org",
		Attributes:       []string{SubjectID, EduPersonPrincipalName, Mail},
		Organization: &Organization{
			Names:        map[string]string{"en": "Example Institute", "fr": "Institut Exemple"},
			DisplayNames: map[string]string{"en": "Example Institute", "fr": "Institut Exemple"},
			URLs:         map[string]string{"en": "https://www.example.org/en/", "fr": "https://www.example.org/fr/"},
		},
		Contacts: []Contact{
			{Type: "support", GivenName: "Help desk", Email: "help@example.org"},
			{Type: "administrative", Email: "admin@example.org"},
			{Type: "billing", Email: "billing@example.org"},
			{Type: "other", Security: true, GivenName: "CSIRT", Email: "csirt@example.org"},
		},
		Logos: []Logo{
			{URL: "https://bridge.example.org/logo-64.png", Width: 64, Height: 64},
			{URL: "https://bridge.example.org/logo-fr.png", Width: 200, Height: 80, Lang: "fr"},
			{URL: "https://bridge.example.org/logo-fr-big.png", Width: 400, Height: 160, Lang: "fr"},
		},
		InformationURLs:      map[string]string{"fr": "https://bridge.example.org/fr/"},
		PrivacyStatementURLs: map[string]string{"fr": "https://bridge.example.org/fr/privacy"},
	}
}

// The judge for the schema is xmllint (libxml2), which nobody here wrote. It
// skips where it is absent, and fails with SAML_REQUIRE_JUDGE=1, as xmlsec1
// does for the signatures.
func xmllint(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("xmllint")
	if err != nil {
		if os.Getenv("SAML_REQUIRE_JUDGE") == "1" {
			t.Fatal("xmllint is required here and is not installed")
		}
		t.Skip("xmllint is not installed: the metadata is not schema-validated here")
	}
	return p
}

// validateXSD runs the OASIS metadata schema, with the mdui and idpdisc ones,
// over doc.
func validateXSD(t *testing.T, doc []byte) error {
	t.Helper()
	lint := xmllint(t)
	xsd, err := filepath.Abs("testdata/xsd")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cat, err := os.ReadFile(filepath.Join(xsd, "catalog.xml"))
	if err != nil {
		t.Fatal(err)
	}
	catFile := filepath.Join(dir, "catalog.xml")
	if err := os.WriteFile(catFile, []byte(strings.ReplaceAll(string(cat), "XSDDIR", xsd)), 0o600); err != nil {
		t.Fatal(err)
	}
	docFile := filepath.Join(dir, "sp.xml")
	if err := os.WriteFile(docFile, doc, 0o600); err != nil {
		t.Fatal(err)
	}
	// libxml2 validates the root against the schemas it was given; the
	// wrapper has no root of its own, so the document is checked through the
	// metadata schema directly, which imports nothing it does not resolve.
	cmd := exec.Command(lint, "--noout", "--nonet", "--schema", filepath.Join(xsd, "saml-schema-metadata-2.0.xsd"), docFile)
	cmd.Env = append(os.Environ(), "XML_CATALOG_FILES="+catFile)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("%s", out)
	}
	return err
}

// The metadata, with every block set, is valid against the OASIS schema: the
// extensions (mdui, idpdisc) are processed leniently by it, so the mdui schema
// is checked on its own below.
func TestMetadataFullIsSchemaValid(t *testing.T) {
	out, err := goldenSP(t).Metadata(fullDescription())
	if err != nil {
		t.Fatal(err)
	}
	if err := validateXSD(t, out); err != nil {
		t.Fatalf("the metadata is not valid against saml-schema-metadata-2.0.xsd: %v\n%s", err, out)
	}
	validateMDUI(t, out)
}

// What v0.7.3 wrote is valid too, so that an unset block is no regression.
func TestMetadataGoldenIsSchemaValid(t *testing.T) {
	for _, name := range []string{"minimal", "full"} {
		b, err := os.ReadFile("testdata/sp-metadata-" + name + ".golden.xml")
		if err != nil {
			t.Fatal(err)
		}
		if err := validateXSD(t, b); err != nil {
			t.Errorf("%s: %v", name, err)
		}
		validateMDUI(t, b)
	}
}

// validateMDUI checks each <mdui:UIInfo> of doc against the mdui schema, which
// the metadata schema leaves to lax processing.
func validateMDUI(t *testing.T, doc []byte) {
	t.Helper()
	lint := xmllint(t)
	d := etree.NewDocument()
	if err := d.ReadFromBytes(doc); err != nil {
		t.Fatal(err)
	}
	ui := d.FindElement("//mdui:UIInfo")
	if ui == nil {
		t.Fatal("no mdui:UIInfo")
	}
	one := etree.NewDocument()
	one.SetRoot(ui.Copy())
	one.Root().CreateAttr("xmlns:mdui", nsMDUI)
	b, err := one.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}
	xsd, _ := filepath.Abs("testdata/xsd")
	dir := t.TempDir()
	f := filepath.Join(dir, "ui.xml")
	if err := os.WriteFile(f, b, 0o600); err != nil {
		t.Fatal(err)
	}
	cat, _ := os.ReadFile(filepath.Join(xsd, "catalog.xml"))
	cf := filepath.Join(dir, "catalog.xml")
	if err := os.WriteFile(cf, []byte(strings.ReplaceAll(string(cat), "XSDDIR", xsd)), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(lint, "--noout", "--nonet", "--schema", filepath.Join(xsd, "sstc-saml-metadata-ui-v1.0.xsd"), f)
	cmd.Env = append(os.Environ(), "XML_CATALOG_FILES="+cf)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("mdui:UIInfo is not valid against the mdui schema: %v\n%s\n%s", err, out, b)
	}
}

// The judge must be able to say no: an element in the wrong place is refused
// by the same command.
func TestSchemaJudgeRefusesMisplacedOrganization(t *testing.T) {
	out, err := goldenSP(t).Metadata(fullDescription())
	if err != nil {
		t.Fatal(err)
	}
	d := etree.NewDocument()
	if err := d.ReadFromBytes(out); err != nil {
		t.Fatal(err)
	}
	ed := d.Root()
	org := ed.FindElement("md:Organization")
	ed.RemoveChild(org)
	ed.InsertChildAt(0, org) // before the role descriptor
	bad, _ := d.WriteToBytes()
	if err := validateXSD(t, bad); err == nil {
		t.Fatal("an Organization before the SPSSODescriptor passed the schema")
	}
}

// In an EntityDescriptor, the role descriptor comes first, then Organization,
// then every ContactPerson (saml-metadata-2.0-os 2.3.2).
func TestMetadataElementOrder(t *testing.T) {
	out, err := goldenSP(t).Metadata(fullDescription())
	if err != nil {
		t.Fatal(err)
	}
	d := etree.NewDocument()
	if err := d.ReadFromBytes(out); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, c := range d.Root().ChildElements() {
		got = append(got, c.Tag)
	}
	want := "SPSSODescriptor Organization ContactPerson ContactPerson ContactPerson ContactPerson ContactPerson"
	if strings.Join(got, " ") != want {
		t.Errorf("children of EntityDescriptor: %v\nwant %s", got, want)
	}
	cps := d.Root().SelectElements("ContactPerson")
	if cps[0].SelectAttrValue("contactType", "") != "technical" || text(cps[0].SelectElement("EmailAddress")) != "mailto:noc@example.org" {
		t.Error("the technical contact is not first")
	}
	sec := cps[4]
	if sec.SelectAttrValue("contactType", "") != "other" || sec.SelectAttrValue("remd:contactType", "") != refedsSecurity {
		t.Errorf("the security contact is %v", sec.Attr)
	}
	if text(sec.SelectElement("EmailAddress")) != "mailto:csirt@example.org" || text(sec.SelectElement("GivenName")) != "CSIRT" {
		t.Error("the security contact lost its name or address")
	}
	if cps[1].SelectAttr("remd:contactType") != nil {
		t.Error("a contact that is not a security contact carries remd:contactType")
	}
	// Organization carries the three element kinds, in the schema's order.
	var org []string
	for _, c := range d.Root().SelectElement("Organization").ChildElements() {
		org = append(org, c.Tag)
	}
	if strings.Join(org, " ") != "OrganizationName OrganizationName OrganizationDisplayName OrganizationDisplayName OrganizationURL OrganizationURL" {
		t.Errorf("Organization children: %v", org)
	}
	// The logos are in the UIInfo, by language, without one first.
	logos := d.FindElements("//mdui:UIInfo/mdui:Logo")
	if len(logos) != 3 || logos[0].SelectAttr("xml:lang") != nil || logos[1].SelectAttrValue("width", "") != "200" || logos[2].SelectAttrValue("height", "") != "160" {
		t.Errorf("logos: %d", len(logos))
	}
	// remd is declared only when a security contact is.
	plain, _ := goldenSP(t).Metadata(Description{Names: map[string]string{"en": "x"}, Contacts: []Contact{{Type: "support", Email: "a@example.org"}}})
	if strings.Contains(string(plain), "remd") {
		t.Error("remd is declared without a security contact")
	}
}

// One refusal per rule.
func TestDescriptionRefusals(t *testing.T) {
	mut := func(f func(*Description)) Description { d := fullDescription(); f(&d); return d }
	for name, tc := range map[string]struct {
		d    Description
		want string
	}{
		"http logo":                    {mut(func(d *Description) { d.Logos[0].URL = "http://bridge.example.org/l.png" }), "not an https URL"},
		"logo data URI":                {mut(func(d *Description) { d.Logos[0].URL = "data:image/png;base64,AAAA" }), "not an https URL"},
		"logo with credentials":        {mut(func(d *Description) { d.Logos[0].URL = "https://u:p@bridge.example.org/l.png" }), "credentials"},
		"logo without host":            {mut(func(d *Description) { d.Logos[0].URL = "https:///l.png" }), "no host"},
		"zero logo width":              {mut(func(d *Description) { d.Logos[0].Width = 0 }), "positive"},
		"negative logo height":         {mut(func(d *Description) { d.Logos[0].Height = -1 }), "positive"},
		"logo language":                {mut(func(d *Description) { d.Logos[1].Lang = "fr_FR" }), "not a language tag"},
		"logo repeated":                {mut(func(d *Description) { d.Logos = append(d.Logos, d.Logos[1]) }), "repeats"},
		"logo repeated, language case": {mut(func(d *Description) { l := d.Logos[1]; l.Lang = "FR"; d.Logos = append(d.Logos, l) }), "repeats"},
		"http information URL":         {mut(func(d *Description) { d.InformationURLs["fr"] = "http://bridge.example.org/" }), "not an https URL"},
		"http privacy URL":             {mut(func(d *Description) { d.PrivacyStatementURLs["fr"] = "http://bridge.example.org/p" }), "not an https URL"},
		"http organization URL":        {mut(func(d *Description) { d.Organization.URLs["en"] = "http://www.example.org/" }), "not an https URL"},
		"language given twice":         {mut(func(d *Description) { d.InformationURLs["FR"] = "https://bridge.example.org/fr2/" }), "given twice"},
		"organization language twice":  {mut(func(d *Description) { d.Organization.Names["EN"] = "Again" }), "given twice"},
		"bad language tag":             {mut(func(d *Description) { d.Organization.DisplayNames["e n"] = "x" }), "not a language tag"},
		"information URL twice":        {mut(func(d *Description) { d.InformationURLs["en"] = "https://bridge.example.org/en/" }), "both give"},
		"privacy URL twice":            {mut(func(d *Description) { d.PrivacyStatementURLs["en"] = "https://bridge.example.org/en/p" }), "both give"},
		"organization without name":    {mut(func(d *Description) { d.Organization.Names = nil }), "organization name"},
		"organization without display": {mut(func(d *Description) { d.Organization.DisplayNames = map[string]string{} }), "display name"},
		"organization without URL":     {mut(func(d *Description) { d.Organization.URLs = nil }), "organization URL"},
		"organization name control":    {mut(func(d *Description) { d.Organization.Names["en"] = "a\x00b" }), "control"},
		"unknown contact type":         {mut(func(d *Description) { d.Contacts[0].Type = "security" }), "unknown contact type"},
		"empty contact type":           {mut(func(d *Description) { d.Contacts[0].Type = "" }), "unknown contact type"},
		"security contact not other":   {mut(func(d *Description) { d.Contacts[0].Security = true }), `of type "other"`},
		"email not an address":         {mut(func(d *Description) { d.Contacts[0].Email = "help" }), "email"},
		"email with a name":            {mut(func(d *Description) { d.Contacts[0].Email = "Help <help@example.org>" }), "bare address"},
		"email empty":                  {mut(func(d *Description) { d.Contacts[0].Email = "" }), "email"},
		"email with mailto":            {mut(func(d *Description) { d.Contacts[0].Email = "mailto:help@example.org" }), "email"},
		"given name control":           {mut(func(d *Description) { d.Contacts[0].GivenName = "a\nb" }), "control"},
		"too many contacts": {mut(func(d *Description) {
			for len(d.Contacts) <= maxMetadataItems {
				d.Contacts = append(d.Contacts, d.Contacts[0])
			}
		}), "at most"},
	} {
		t.Run(name, func(t *testing.T) {
			err := tc.d.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate() = %v, want an error holding %q", err, tc.want)
			}
			if _, err := goldenSP(t).Metadata(tc.d); err == nil {
				t.Error("Metadata wrote a Description that Validate refuses")
			}
		})
	}
	if err := fullDescription().Validate(); err != nil {
		t.Errorf("the full Description is refused: %v", err)
	}
	if err := (Description{}).Validate(); err != nil {
		t.Errorf("the empty Description is refused: %v", err)
	}
}

func FuzzDescription(f *testing.F) {
	f.Add("en", "https://a.example.org/l.png", "a@example.org", "support", 10, 10)
	f.Add("fr-CA", "https://a.example.org/", "<a@example.org>", "other", 0, 1)
	f.Add("", "", "", "", -1, -1)
	sp := &SP{EntityID: spEntity, ACS: acsURL}
	cert, _ := goldenSPCert()
	sp.Cert = cert
	f.Fuzz(func(t *testing.T, lang, u, email, typ string, w, h int) {
		d := Description{
			Names:        map[string]string{"en": "x"},
			Organization: &Organization{Names: map[string]string{lang: u}, DisplayNames: map[string]string{lang: u}, URLs: map[string]string{lang: u}},
			Contacts:     []Contact{{Type: typ, Email: email, GivenName: u, Security: w > h}},
			Logos:        []Logo{{URL: u, Width: w, Height: h, Lang: lang}},

			InformationURLs: map[string]string{lang: u},
		}
		out, err := sp.Metadata(d)
		if err != nil {
			return
		}
		// What is written is well-formed XML that holds the address back.
		doc := etree.NewDocument()
		if err := doc.ReadFromBytes(out); err != nil {
			t.Fatalf("Validate accepted what makes ill-formed XML: %v\n%q", err, out)
		}
		if got := doc.FindElement("//md:ContactPerson/md:EmailAddress"); got == nil || got.Text() != "mailto:"+email {
			t.Fatalf("the address came back as %v", got)
		}
	})
}
