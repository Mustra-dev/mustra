package agent

import "testing"

func TestParseTabbedAppsInstallDate(t *testing.T) {
	apps := parseTabbedApps([]byte("curl\t8.5.0\tamd64\nlibc6\t2.39\tamd64\nnoversion\n"), func(name, extra string) string {
		if name == "curl" && extra == "amd64" {
			return "2026-01-02"
		}
		return ""
	})
	if len(apps) != 3 || apps[0].InstallDate != "2026-01-02" || apps[1].InstallDate != "" || apps[2].Name != "noversion" {
		t.Fatalf("%+v", apps)
	}
	if rpmInstallDate("x", "1700000000") != "2023-11-14" || rpmInstallDate("x", "") != "" {
		t.Fatal(rpmInstallDate("x", "1700000000"))
	}
}

func TestExeFromDisplayIcon(t *testing.T) {
	cases := map[string]string{
		`C:\Program Files\Google\Chrome\Application\chrome.exe,0`: "chrome",
		`"C:\Program Files\7-Zip\7zFM.exe"`:                       "7zfm",
		`C:\Windows\Installer\{GUID}\icon.ico`:                    "",
		`%SystemRoot%\system32\shell32.dll,-3`:                    "",
		``:                                                        "",
	}
	for in, want := range cases {
		if got := exeFromDisplayIcon(in); got != want {
			t.Errorf("exeFromDisplayIcon(%q) = %q, want %q", in, got, want)
		}
	}
}
