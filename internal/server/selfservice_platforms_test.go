package server

import (
	"context"
	"log/slog"
	"os"
	"slices"
	"testing"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/store"
)

// The console's Self Service page says which platforms a package is
// offered on. It reads the rule the endpoint window uses, so the two
// cannot disagree: an install that needs parameters, or a platform with no
// install at all, is not offered.
func TestSelfServicePlatformsFollowWhatEndpointsAreOffered(t *testing.T) {
	install := func(params ...proto.DeployParameter) map[string]proto.DeployAction {
		return map[string]proto.DeployAction{"install": {Parameters: params}}
	}
	param := proto.DeployParameter{Name: "licence", Type: "text"}
	cases := []struct {
		name string
		pkg  store.SoftwarePackage
		want []string
	}{
		{"legacy commands with an install", store.SoftwarePackage{Commands: map[string]store.SoftwareOps{
			"linux": {Install: "apt-get install -y jq"}, "windows": {Remove: "winget uninstall jq"}}}, []string{"linux"}},
		{"versioned variants", store.SoftwarePackage{DeployRevision: "rev-1", DeployDefinition: &proto.DeployDefinition{Variants: []proto.DeployVariant{
			{ID: "mac", OS: "darwin", Actions: install()},
			{ID: "win", OS: "windows", Actions: map[string]proto.DeployAction{"remove": {}}},
			{ID: "lin", OS: "linux", Actions: install(param)},
			{ID: "lin-v", OS: "linux", Parameters: []proto.DeployParameter{param}, Actions: install()},
		}}}, []string{"darwin"}},
		{"a parameter on the definition rules out every platform", store.SoftwarePackage{DeployRevision: "rev-1", DeployDefinition: &proto.DeployDefinition{
			Parameters: []proto.DeployParameter{param},
			Variants:   []proto.DeployVariant{{ID: "mac", OS: "darwin", Actions: install()}},
		}}, []string{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := selfServicePlatforms(c.pkg)
			if !slices.Equal(got, c.want) {
				t.Fatalf("platforms %v, want %v", got, c.want)
			}
			// Each listed platform is one the endpoint window offers it on,
			// and no other is.
			for _, os := range []string{"linux", "darwin", "windows"} {
				arch := ""
				var variant *proto.DeployVariant
				if c.pkg.DeployDefinition != nil {
					for i := range c.pkg.DeployDefinition.Variants {
						if v := &c.pkg.DeployDefinition.Variants[i]; v.OS == os {
							variant = v
							break
						}
					}
				}
				if c.pkg.DeployDefinition != nil && variant == nil {
					continue
				}
				_, offered := selfServiceOffer(c.pkg, os, arch, "", "")
				// The ambiguous pair of linux variants is not offered on
				// an endpoint either; selfServicePlatforms does not list it.
				if offered != slices.Contains(got, os) {
					t.Errorf("%s: endpoint offered=%v, page lists it=%v", os, offered, slices.Contains(got, os))
				}
			}
		})
	}
}

// A package pinned to an earlier version is offered as that version, so
// its platforms are that version's, not the latest one's.
func TestSelfServicePlatformsUseThePinnedVersion(t *testing.T) {
	dsn := os.Getenv("MUSTRA_TEST_DEPLOY_DSN")
	if dsn == "" {
		t.Skip("set MUSTRA_TEST_DEPLOY_DSN to a disposable Postgres database")
	}
	ctx := context.Background()
	st, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	s := &Server{logger: slog.Default(), store: st}

	id := idgen.New("sw-ss-pin-test-")
	if _, err = st.UpsertSoftwarePackage(ctx, store.SoftwarePackage{ID: id, Name: "Pinned", Kind: store.KindSoftware,
		Commands: map[string]store.SoftwareOps{}, Enabled: true, SelfService: true}); err != nil {
		t.Fatal(err)
	}
	// Published revisions keep a package from being deleted, so it stays in
	// the disposable database, withdrawn from Self Service.
	defer func() {
		if pkg, _ := st.GetSoftwarePackage(context.Background(), id); pkg != nil {
			pkg.SelfService, pkg.Enabled = false, false
			_, _ = st.UpsertSoftwarePackage(context.Background(), *pkg)
		}
	}()
	publish := func(label, osName string) string {
		t.Helper()
		rev, err := st.SaveDeployDraft(ctx, proto.DeployRevision{ID: idgen.New("rev-ss-pin-"), PackageID: id, Label: label, CreatedBy: "test",
			Definition: proto.DeployDefinition{Version: 1, Variants: []proto.DeployVariant{{ID: osName, OS: osName,
				Actions: map[string]proto.DeployAction{"install": {}}}}}})
		if err != nil {
			t.Fatal(err)
		}
		if err = st.PublishDeployRevision(ctx, *rev); err != nil {
			t.Fatal(err)
		}
		return rev.ID
	}
	first := publish("1", "linux") // the first publication becomes the Self Service pin
	publish("2", "darwin")

	platforms := func() []string {
		t.Helper()
		pkg, err := st.GetSoftwarePackage(ctx, id)
		if err != nil || pkg == nil {
			t.Fatal(pkg, err)
		}
		return s.selfServicePlatformsAll(ctx, []store.SoftwarePackage{*pkg})[id]
	}
	if got := platforms(); !slices.Equal(got, []string{"linux"}) {
		t.Fatalf("pinned to %s: platforms %v, want [linux]", first, got)
	}
	pkg, _ := st.GetSoftwarePackage(ctx, id)
	pkg.SelfServiceFollowLatest = true
	if _, err = st.UpsertSoftwarePackage(ctx, *pkg); err != nil {
		t.Fatal(err)
	}
	if got := platforms(); !slices.Equal(got, []string{"darwin"}) {
		t.Fatalf("following the latest: platforms %v, want [darwin]", got)
	}
}
