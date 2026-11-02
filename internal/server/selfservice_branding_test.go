package server

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/mustra-dev/mustra/internal/proto"
)

func TestNormalizeSelfServiceBrandingRejects(t *testing.T) {
	big := "data:image/png;base64," + base64.StdEncoding.EncodeToString(make([]byte, maxSelfServiceLogoBytes+1))
	cases := map[string]proto.SelfServiceBranding{
		"javascript help link": {HelpURL: "javascript:alert(1)"},
		"relative help link":   {HelpURL: "/help"},
		"colour that is CSS":   {Accent: "red;background:url(x)"},
		"svg logo":             {LogoDataURL: "data:image/svg+xml;base64,PHN2Zy8+"},
		"oversized logo":       {LogoDataURL: big},
		"unknown tab":          {Tabs: []proto.SelfServiceTab{{ID: "shell"}}},
		"duplicate tab":        {Tabs: []proto.SelfServiceTab{{ID: "catalog"}, {ID: "catalog"}}},
		"image with no image":  {Pattern: "image"},
		"unknown theme":        {Theme: "neon"},
		"radius out of range":  {Radius: intPtr(90)},
		"every tab hidden": {Tabs: []proto.SelfServiceTab{{ID: "catalog", Hidden: true}, {ID: "updates", Hidden: true},
			{ID: "history", Hidden: true}, {ID: "activity", Hidden: true}, {ID: "device", Hidden: true}}},
		"opens on a hidden tab": {DefaultTab: "history", Tabs: []proto.SelfServiceTab{{ID: "history", Hidden: true}}},
	}
	for name, b := range cases {
		if _, err := normalizeSelfServiceBranding(b); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestNormalizeSelfServiceBrandingCanonical(t *testing.T) {
	b, err := normalizeSelfServiceBranding(proto.SelfServiceBranding{
		OrgName: "  Example Health  ", Accent: "#AABBCC", HelpURL: "mailto:help@example.com",
		Tabs: []proto.SelfServiceTab{{ID: "Activity", Label: " Now "}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if b.OrgName != "Example Health" || b.Accent != "#aabbcc" {
		t.Fatalf("not trimmed/lowercased: %+v", b)
	}
	// Tabs the operator left out are appended, so none can go missing.
	var ids []string
	for _, t := range b.Tabs {
		ids = append(ids, t.ID)
	}
	if strings.Join(ids, ",") != "activity,catalog,updates,history,device" || b.Tabs[0].Label != "Now" {
		t.Fatalf("tabs = %+v", b.Tabs)
	}

	again, _ := normalizeSelfServiceBranding(b)
	if selfServiceBrandingVersion(again) != selfServiceBrandingVersion(b) {
		t.Fatal("normalising twice changed the version; every save would roll the fleet")
	}
}

func TestSelfServiceBrandingDefaultHasNoVersion(t *testing.T) {
	b, err := normalizeSelfServiceBranding(proto.SelfServiceBranding{})
	if err != nil {
		t.Fatal(err)
	}
	if !isDefaultSelfServiceBranding(b) {
		t.Fatal("an empty submission is not the default")
	}
	if selfServiceBrandingVersion(proto.SelfServiceBranding{}) != "" {
		t.Fatal("the default look must have version \"\"")
	}
	b.Tabs[0].Label = "Software"
	if isDefaultSelfServiceBranding(b) {
		t.Fatal("a renamed tab was treated as the default")
	}
}

func intPtr(v int) *int { return &v }

// Background image fit, position and blur: known values only, a bounded
// blur, and the defaults stored as nothing so choosing them does not give
// the fleet a new version.
func TestSelfServiceBackgroundImageOptions(t *testing.T) {
	ten, zero, big, neg := 10, 0, 21, -1
	ok, err := normalizeSelfServiceBranding(proto.SelfServiceBranding{BackgroundFit: " Tile ", BackgroundPosition: "TOP", BackgroundBlur: &ten})
	if err != nil {
		t.Fatal(err)
	}
	if ok.BackgroundFit != "tile" || ok.BackgroundPosition != "top" || ok.BackgroundBlur == nil || *ok.BackgroundBlur != 10 {
		t.Errorf("not normalised: %+v", ok)
	}
	def, err := normalizeSelfServiceBranding(proto.SelfServiceBranding{BackgroundFit: "cover", BackgroundPosition: "center", BackgroundBlur: &zero})
	if err != nil {
		t.Fatal(err)
	}
	if def.BackgroundFit != "" || def.BackgroundPosition != "" || def.BackgroundBlur != nil {
		t.Errorf("defaults kept as values: %+v", def)
	}
	if !isDefaultSelfServiceBranding(def) {
		t.Error("choosing every default changed the branding version")
	}
	for name, b := range map[string]proto.SelfServiceBranding{
		"fit":      {BackgroundFit: "stretch;color:red"},
		"position": {BackgroundPosition: "50% 50%"},
		"blur>20":  {BackgroundBlur: &big},
		"blur<0":   {BackgroundBlur: &neg},
	} {
		if _, err := normalizeSelfServiceBranding(b); err == nil {
			t.Errorf("%s: accepted %+v", name, b)
		}
	}
}
