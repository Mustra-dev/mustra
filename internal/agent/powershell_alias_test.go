package agent

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// PowerShell resolves aliases before functions, so a helper named like a
// built-in alias is silently never called: the directory script's FT helper
// ran Format-Table and every AD date came back blank.
var builtinPowerShellAliases = strings.Fields(`% ? ac asnp cat cd cfs chdir clc clear clhy cli clp cls clv cnsn
copy cp cpi cpp curl cvpa dbp del diff dir dnsn ebp echo epal epcsv epsn erase etsn exsn fc fhx fl
foreach ft fw gal gbp gc gci gcm gcs gdr ghy gi gjb gl gm gmo gp gps gpv group gsn gsnp gsv gu gv
gwmi h history icm iex ihy ii ipal ipcsv ipmo ipsn irm ise iwmi iwr kill lp ls man md measure mi
mount move mp mv nal ndr ni nmo npssc nsn nv ogv oh popd ps pushd pwd r rbp rcjb rcsn rd rdr ren ri
rjb rm rmdir rmo rni rnp rp rsn rsnp rujb rv rvpa rwmi sajb sal saps sasv sbp sc select set shcm si
sl sleep sls sort sp spjb spps spsv start sujb sv swmi tee trcm type wget where wjb write`)

func TestPowerShellHelpersDoNotShadowAliases(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fn := regexp.MustCompile(`(?m)\bfunction ([A-Za-z][\w-]*)\s*[({]`)
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range fn.FindAllStringSubmatch(string(src), -1) {
			for _, a := range builtinPowerShellAliases {
				if strings.EqualFold(m[1], a) {
					t.Errorf("%s: PowerShell function %q is a built-in alias and would never run", f, m[1])
				}
			}
		}
	}
}
