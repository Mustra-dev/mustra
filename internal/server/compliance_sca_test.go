package server

import (
	"reflect"
	"testing"
)

// A fragment in the exact shape Wazuh publishes, including the details
// that trip a naive line parser: numeric ids, quoted values, a rule
// containing a colon and an arrow, and a `not` prefix.
const scaSample = `
policy:
  id: "cis_debian12"
  name: "CIS Debian 12 Benchmark"

requirements:
  name: "Debian check"
  rules:
    - 'f:/etc/debian_version'

checks:
  - id: 28500
    name: "Ensure cramfs kernel module is not available"
    description: "The cramfs filesystem type is a compressed read-only system."
    rationale: "Removing support reduces the attack surface."
    remediation: "Add install cramfs /bin/false to a modprobe config."
    condition: all
    compliance:
      - cis: ["1.1.1.1"]
    rules:
      - 'c:modprobe -n -v cramfs -> r:install /bin/true|install /bin/false'
      - 'not c:lsmod -> r:cramfs'

  - id: 28501
    name: "Ensure /tmp is a separate partition"
    condition: any
    rules:
      - 'c:findmnt --kernel /tmp -> r:\s/tmp\s'

  # A check with no rules can never produce a result and is dropped.
  - id: 28502
    name: "Documentation only"
`

func TestParseSCAPolicy(t *testing.T) {
	checks, err := parseSCAPolicy([]byte(scaSample))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// The requirements block also has a `rules:` key — it must not be
	// mistaken for a check, and the ruleless check must be dropped.
	if len(checks) != 2 {
		t.Fatalf("want 2 checks, got %d: %+v", len(checks), checks)
	}

	first := checks[0]
	if first.ID != "28500" {
		t.Errorf("id: got %q, want 28500", first.ID)
	}
	if first.Title != "Ensure cramfs kernel module is not available" {
		t.Errorf("title: got %q", first.Title)
	}
	if first.Condition != "all" {
		t.Errorf("condition: got %q", first.Condition)
	}
	if len(first.Rules) != 2 {
		t.Fatalf("want 2 rules, got %d: %v", len(first.Rules), first.Rules)
	}
	// The arrow and the alternation inside the regex must survive intact —
	// mangling either silently changes what the check tests.
	if first.Rules[0] != `c:modprobe -n -v cramfs -> r:install /bin/true|install /bin/false` {
		t.Errorf("rule 0 was altered: %q", first.Rules[0])
	}
	if first.Rules[1] != "not c:lsmod -> r:cramfs" {
		t.Errorf("rule 1 was altered: %q", first.Rules[1])
	}
	if first.Remediation == "" {
		t.Error("remediation was dropped")
	}

	if checks[1].ID != "28501" || checks[1].Condition != "any" {
		t.Errorf("second check: %+v", checks[1])
	}
}

func TestParseSCARejectsNonPolicy(t *testing.T) {
	if _, err := parseSCAPolicy([]byte("just: some\nrandom: yaml\n")); err == nil {
		t.Error("a file with no checks should be rejected, not silently accepted as empty")
	}
}

// The `compliance:` block becomes the check's control mappings, in the map
// form current Wazuh content uses, the list form older files use, and with
// block lists; it does not swallow the rules that follow it.
func TestParseSCAControls(t *testing.T) {
	policy := `
policy:
  id: "x"
checks:
  - id: 35500
    name: "Ensure /tmp is a separate partition."
    compliance:
      cmmc: ["CM.L2-3.4.7", "SC.L2-3.13.6"]
      nist_800_171: ["3.4.7", "3.13.6"]
      nist_800_53: ["CM-6", 'CM-7']
    condition: all
    rules:
      - 'c:findmnt -kn /tmp -> r:\s*/tmp\s'
  - id: 35501
    title: "Older file"
    compliance:
      - cis: ["1.1.2"]
      - nist_sp_800-53: ["AC-6"]
      - pci_dss:
          - "2.2.4"
          - "2.2.5"
    rules:
      - 'f:/etc/fstab -> r:/tmp'
  - id: 35502
    title: "No mappings"
    rules:
      - 'f:/etc/passwd'
`
	checks, err := parseSCAPolicy([]byte(policy))
	if err != nil {
		t.Fatal(err)
	}
	if len(checks) != 3 {
		t.Fatalf("got %d checks", len(checks))
	}
	want := []map[string][]string{
		{"cmmc": {"CM.L2-3.4.7", "SC.L2-3.13.6"}, "nist_800_171": {"3.4.7", "3.13.6"}, "nist_800_53": {"CM-6", "CM-7"}},
		{"cis": {"1.1.2"}, "nist_800_53": {"AC-6"}, "pci_dss": {"2.2.4", "2.2.5"}},
		nil,
	}
	for i, c := range checks {
		if !reflect.DeepEqual(c.Controls, want[i]) {
			t.Errorf("check %s: controls %v, want %v", c.ID, c.Controls, want[i])
		}
		if len(c.Rules) != 1 {
			t.Errorf("check %s: rules %v", c.ID, c.Rules)
		}
	}
	if checks[0].Condition != "all" {
		t.Errorf("condition after the compliance block was lost: %q", checks[0].Condition)
	}
}
