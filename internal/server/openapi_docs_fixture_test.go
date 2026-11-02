package server

import (
	"reflect"
	"testing"
	"time"
)

// docSourceFixture is what the generator reads: a comment wrapped over
// lines, as gofmt leaves it.
//
// A second paragraph.
type docSourceFixture struct {
	// Name is who it is,
	// across two lines.
	Name string `json:"name"`
	Kind string `json:"kind"` // rule | quick
	// Level is how loud.
	Level int `json:"level"` // 0 to 3
	// A and B share a comment.
	A, B int
	Mode string `json:"mode"` // '' is the default, as written
	// Steps are:
	//   - one
	//   - two
	// and nothing else.
	Steps  int
	Hidden string `json:"-"` // not on the wire
	Plain  int    `json:"plain"`
	docSourceEmbedded
}

// docSourceEmbedded is flattened into the type that embeds it, so its
// own comment describes nothing.
type docSourceEmbedded struct {
	Depth int `json:"depth"` // how far down
}

// docBlockFixture groups its fields in blocks, the way structs here do.
type docBlockFixture struct {
	// kind: package
	PackageID string `json:"package_id"`
	Operation string `json:"operation"` // install | remove

	// Email and Persona back the menu.
	Email   string `json:"email"`
	Persona string `json:"persona"`
	Theme   string `json:"theme"`

	// Alone is the only field of its block.
	Alone string `json:"alone"`

	// See EnforcePolicy.Deleted: a qualified name still names the field.
	Deleted bool `json:"deleted"`
	Steps   int  `json:"steps"`
}

// A comment above a field that names it describes that field, and the
// fields after it in its block (no blank line between) that it names
// too. One that does not name it, above several, heads the block and
// describes them all.
func TestTypeDocsFromBlocks(t *testing.T) {
	typ := reflect.TypeFor[docBlockFixture]()
	got, err := typeDocsFrom([]reflect.Type{typ}, func(string) []string { return []string{"openapi_docs_fixture_test.go"} })
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"PackageID": "kind: package",
		"Operation": "kind: package\n\ninstall | remove",
		"Email":     "Email and Persona back the menu.",
		"Persona":   "Email and Persona back the menu.",
		"Alone":     "Alone is the only field of its block.",
		"Deleted":   "See EnforcePolicy.Deleted: a qualified name still names the field.",
	}
	if fields := got[docKey(typ)].Fields; !reflect.DeepEqual(fields, want) {
		t.Errorf("got  %#v\nwant %#v", fields, want)
	}
}

// The generator copies the comments of the types a spec describes, and of
// the fields encoding/json writes for them, wherever they are declared:
// lines joined into paragraphs, indented lines kept as they are, and a
// field's comment above it before the one beside it.
func TestTypeDocsFromSource(t *testing.T) {
	typ := reflect.TypeFor[docSourceFixture]()
	got, err := typeDocsFrom([]reflect.Type{typ}, func(pkgPath string) []string {
		if pkgPath != serverPkgPath {
			t.Errorf("read %s", pkgPath)
		}
		return []string{"openapi_docs_fixture_test.go"}
	})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]typeDoc{
		docKey(typ): {
			Doc: "docSourceFixture is what the generator reads: a comment wrapped over lines, as gofmt leaves it.\n\nA second paragraph.",
			Fields: map[string]string{
				"Name":  "Name is who it is, across two lines.",
				"Kind":  "rule | quick",
				"Level": "Level is how loud.\n\n0 to 3",
				"A":     "A and B share a comment.",
				"B":     "A and B share a comment.",
				"Mode":  "'' is the default, as written",
				"Steps": "Steps are:\n  - one\n  - two\nand nothing else.",
			},
		},
		docKey(reflect.TypeFor[docSourceEmbedded]()): {Fields: map[string]string{"Depth": "how far down"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %#v\nwant %#v", got, want)
	}
}

type docFixtureItem struct {
	ID string `json:"id"`
}

type docFixture struct {
	Name    string           `json:"name"`
	Item    docFixtureItem   `json:"item" api:"readonly"`
	Items   []docFixtureItem `json:"items"`
	Wait    time.Duration    `json:"wait"`
	Plain   int              `json:"plain"`
	Comment string           `json:"comment"`
}

// A type's doc comment describes its component, and a field's describes
// its property; beside a $ref the description needs the same allOf
// wrapper a flag does. A unit the type's own schema states is kept.
func TestSchemaDescriptionsFromDocs(t *testing.T) {
	typ := reflect.TypeFor[docFixture]()
	docs := map[string]typeDoc{
		docKey(typ): {Doc: "A fixture.", Fields: map[string]string{
			"Name":  "Who it is.",
			"Item":  "The one it holds.",
			"Items": "The ones it lists.",
			"Wait":  "How long it waits.",
		}},
		docKey(reflect.TypeFor[docFixtureItem]()): {Doc: "An item."},
	}
	set := newSchemaSetWith(docs, typ)
	assertJSON(t, "components", set.components(), `{
		"DocFixture":{"type":"object","description":"A fixture.","properties":{
			"name":{"type":"string","description":"Who it is."},
			"item":{"allOf":[{"$ref":"#/components/schemas/DocFixtureItem"}],"readOnly":true,"description":"The one it holds."},
			"items":{"type":["array","null"],"items":{"$ref":"#/components/schemas/DocFixtureItem"},"description":"The ones it lists."},
			"wait":{"type":"integer","format":"int64","description":"How long it waits.\n\nnanoseconds"},
			"plain":{"type":"integer","format":"int64"},
			"comment":{"type":"string"}}},
		"DocFixtureItem":{"type":"object","description":"An item.","properties":{"id":{"type":"string"}}}}`)
}

type docFixtureEmbedded struct {
	MinAgeDays int `json:"min_age_days"`
}

type docFixtureNames struct {
	docFixtureEmbedded
	HomeDashboardID   string   `json:"home_dashboard_id"`
	HomeDashboardList []string `json:"home_dashboard_list"`
	Untagged          string
	Hidden            string `json:"-"`
	ID                string `json:"id"`
	OS                string `json:"os"`
}

// A comment names the type and its fields as Go does; the spec uses the
// names a client sees. A name after a dot is another type's, a field that
// is not on the wire keeps its Go name, and an initialism (ID, OS) is a
// word of the prose rather than a field's name.
func TestSchemaDescriptionsUseWireNames(t *testing.T) {
	typ := reflect.TypeFor[docFixtureNames]()
	docs := map[string]typeDoc{
		docKey(typ): {Doc: "docFixtureNames is a person's settings; HomeDashboardID picks one.", Fields: map[string]string{
			"HomeDashboardID": "HomeDashboardID is shown on Home; HomeDashboardList is shown beneath it, as in EnforcePolicy.HomeDashboardList.",
			"Untagged":        "Untagged keeps its name, and Hidden is not sent; HomeDashboardIDs is no field.",
			"OS":              "a release date every OS can give, under the same ID",
		}},
		docKey(reflect.TypeFor[docFixtureEmbedded]()): {Fields: map[string]string{"MinAgeDays": "MinAgeDays admits a patch."}},
	}
	set := newSchemaSetWith(docs, typ)
	assertJSON(t, "components", set.components(), `{
		"DocFixtureNames":{"type":"object","description":"DocFixtureNames is a person's settings; home_dashboard_id picks one.","properties":{
			"min_age_days":{"type":"integer","format":"int64","description":"min_age_days admits a patch."},
			"home_dashboard_id":{"type":"string","description":"home_dashboard_id is shown on Home; home_dashboard_list is shown beneath it, as in EnforcePolicy.HomeDashboardList."},
			"home_dashboard_list":{"type":["array","null"],"items":{"type":"string"}},
			"Untagged":{"type":"string","description":"Untagged keeps its name, and Hidden is not sent; HomeDashboardIDs is no field."},
			"id":{"type":"string"},
			"os":{"type":"string","description":"a release date every OS can give, under the same ID"}}}}`)
}
