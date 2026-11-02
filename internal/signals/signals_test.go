package signals

import "testing"

func TestCompileAndEval(t *testing.T) {
	cases := []struct {
		expr  string
		event map[string]string
		want  bool
	}{
		{"process.command_line contains '-enc' AND process.name equals 'powershell.exe'", map[string]string{"process.name": "PowerShell.EXE", "process.command_line": "powershell -EnC SQBF"}, true},
		{"process.command_line contains '-enc' AND process.name equals 'powershell.exe'", map[string]string{"process.name": "cmd.exe", "process.command_line": "-enc"}, false},
		{"(network.remote_port == 4444 OR network.remote_port == 1337) AND NOT network.process starts with 'ssh'", map[string]string{"network.remote_port": "1337", "network.process": "nc"}, true},
		{"(network.remote_port == 4444 OR network.remote_port == 1337) AND NOT network.process starts with 'ssh'", map[string]string{"network.remote_port": "1337", "network.process": "sshd"}, false},
		{"registry.key contains '\\CurrentVersion\\Run' AND registry.op != 'delete'", map[string]string{"registry.key": `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, "registry.op": "set"}, true},
		{"dns.query ends with '.onion' OR dns.query matches '^[a-z0-9]{20,}\\.'", map[string]string{"dns.query": "abcdefghijklmnopqrstuvwxyz.com"}, true},
		{"logon.outcome is 'failure' AND logon.type in ['10', '3']", map[string]string{"logon.outcome": "failure", "logon.type": "10"}, true},
		{"logon.outcome is not 'failure'", map[string]string{"logon.outcome": "failure"}, false},
		{"network.remote_port > 1024 AND network.remote_port <= 65535", map[string]string{"network.remote_port": "8080"}, true},
		{"network.remote_port > 1024", map[string]string{"network.remote_port": "abc"}, false},
		{"process.name not in ['bash', 'sh'] AND process.user not contains 'root'", map[string]string{"process.name": "python3", "process.user": "alex"}, true},
		{"file.path starts with '/etc/cron'", map[string]string{}, false},
	}
	for _, c := range cases {
		r, err := Compile(c.expr)
		if err != nil {
			t.Fatalf("%s: %v", c.expr, err)
		}
		if got := r.Eval(c.event); got != c.want {
			t.Errorf("%s on %v = %v, want %v", c.expr, c.event, got, c.want)
		}
	}
}

func TestObjectsAndErrors(t *testing.T) {
	r, err := Compile("process.name equals 'x' OR network.remote_ip starts with '10.'")
	if err != nil {
		t.Fatal(err)
	}
	if got := r.Objects(); len(got) != 2 || got[0] != "network" || got[1] != "process" {
		t.Errorf("objects = %v", got)
	}
	for _, bad := range []string{
		"",
		"process.cmdline contains 'x'",
		"process.name contains",
		"process.name contains 'x' AND",
		"(process.name contains 'x'",
		"process.name in 'x'",
		"process.name matches '['",
		"widget.name equals 'x'",
		"process.pid > 'many'",
		"process.name contains 'unterminated",
	} {
		if _, err := Compile(bad); err == nil {
			t.Errorf("%q should not compile", bad)
		}
	}
}
