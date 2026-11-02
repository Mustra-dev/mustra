package agent

import (
	"context"
	"encoding/json"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
)

// The directory sensor: how this endpoint belongs to a directory and who
// is signed in, with what the directory knows about them (groups, whether
// the account is enabled or locked, password age, last logon). Windows
// asks Active Directory as the computer account, which every domain member
// may do, so no credentials are configured; Entra ID membership comes from
// dsregcmd. Linux reads realmd/SSSD, macOS dsconfigad and dscl.

func collectDirectory(ctx context.Context) ([]proto.DirectoryInfo, error) {
	var d proto.DirectoryInfo
	var err error
	switch runtime.GOOS {
	case "windows":
		d, err = directoryWindows(ctx)
	case "darwin":
		d = directoryDarwin(ctx)
	default:
		d = directoryLinux(ctx)
	}
	if err != nil {
		return nil, err
	}
	if d.Users == nil {
		d.Users = []proto.DirectoryUser{}
	}
	return []proto.DirectoryInfo{d}, nil
}

// signedInNames lists who is signed in, without duplicates.
func signedInNames(ctx context.Context) []string {
	seen := map[string]bool{}
	var out []string
	users, _ := collectLoggedInUsers(ctx)
	for _, u := range users {
		n := u.User
		if i := strings.LastIndexAny(n, `\`); i >= 0 {
			n = n[i+1:]
		}
		if n != "" && !seen[strings.ToLower(n)] {
			seen[strings.ToLower(n)] = true
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

const directoryScript = `
$ErrorActionPreference = 'SilentlyContinue'
$cs = Get-CimInstance Win32_ComputerSystem
$o = [ordered]@{ joined = [bool]$cs.PartOfDomain; kind = 'workgroup'; users = @() }
if ($cs.PartOfDomain) { $o.domain = $cs.Domain }
$ds = (dsregcmd /status 2>$null) -join "` + "`" + `n"
$entra = $ds -match 'AzureAdJoined\s*:\s*YES'
if ($ds -match 'TenantName\s*:\s*(.+)') { $o.entra_tenant = $Matches[1].Trim() }
if ($ds -match 'DeviceId\s*:\s*(.+)') { $o.entra_device_id = $Matches[1].Trim() }
if ($cs.PartOfDomain -and $entra) { $o.kind = 'hybrid' } elseif ($cs.PartOfDomain) { $o.kind = 'ad' } elseif ($entra) { $o.kind = 'entra' }
function Find($filter, $props) { $s = [adsisearcher]$filter; $s.PageSize = 1; foreach ($p in $props) { [void]$s.PropertiesToLoad.Add($p) }; $s.FindOne() }
function FileTimeIso($v) { if ($v) { $n = [int64]"$v"; if ($n -gt 0 -and $n -lt 9000000000000000000) { [DateTime]::FromFileTimeUtc($n).ToString('o') } } }
function V($p, $k) { if ($p[$k].Count) { [string]$p[$k][0] } }
if ($cs.PartOfDomain) {
  try { $o.site = [System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite().Name } catch {}
  $dc = (nltest /dsgetdc:$($cs.Domain) 2>$null) -join "` + "`" + `n"
  if ($dc -match 'DC: \\\\(\S+)') { $o.dc = $Matches[1] }
  $c = Find "(&(objectCategory=computer)(sAMAccountName=$($env:COMPUTERNAME)` + "`" + `$))" @('distinguishedName','pwdLastSet','memberOf')
  if ($c) { $o.computer_dn = V $c.Properties 'distinguishedname'; $o.computer_ou = ($o.computer_dn -split ',', 2)[1]; $o.machine_password_last_set = FileTimeIso (V $c.Properties 'pwdlastset')
    $o.computer_groups = @($c.Properties['memberof'] | ForEach-Object { ($_ -split ',')[0] -replace '^CN=' } | Sort-Object) }
}
foreach ($n in ($env:MUSTRA_DIR_USERS -split ',' | Where-Object { $_ })) {
  $u = [ordered]@{ name = $n }
  $r = $null
  if ($cs.PartOfDomain) {
    $safe = $n -replace '[()*\\]', ''
    $r = Find "(&(objectCategory=person)(sAMAccountName=$safe))" @('userPrincipalName','displayName','mail','title','department','manager','distinguishedName','memberOf','userAccountControl','lockoutTime','pwdLastSet','lastLogonTimestamp','objectSid')
  }
  if ($r) {
    $p = $r.Properties
    $u.source = 'ad'; $u.upn = V $p 'userprincipalname'; $u.display_name = V $p 'displayname'; $u.email = V $p 'mail'
    $u.title = V $p 'title'; $u.department = V $p 'department'; $u.dn = V $p 'distinguishedname'
    $m = V $p 'manager'; if ($m) { $u.manager = (($m -split ',')[0] -replace '^CN=') }
    $u.groups = @($p['memberof'] | ForEach-Object { ($_ -split ',')[0] -replace '^CN=' } | Sort-Object)
    $uac = [int](V $p 'useraccountcontrol')
    $u.enabled = -not ($uac -band 2); $u.password_never_expires = [bool]($uac -band 0x10000)
    $lock = V $p 'lockouttime'; $u.locked = ($lock -and [int64]$lock -gt 0)
    $u.password_last_set = FileTimeIso (V $p 'pwdlastset'); $u.last_logon = FileTimeIso (V $p 'lastlogontimestamp')
    try { $u.sid = (New-Object Security.Principal.SecurityIdentifier($p['objectsid'][0], 0)).Value } catch {}
  } else {
    $lu = Get-LocalUser -Name $n
    if ($lu) {
      $u.source = 'local'; $u.display_name = $lu.FullName; $u.enabled = [bool]$lu.Enabled; $u.sid = $lu.SID.Value
      if ($lu.PasswordLastSet) { $u.password_last_set = $lu.PasswordLastSet.ToUniversalTime().ToString('o') }
      if ($lu.LastLogon) { $u.last_logon = $lu.LastLogon.ToUniversalTime().ToString('o') }
      $u.password_never_expires = -not $lu.PasswordExpires
      $u.groups = @(Get-LocalGroup | Where-Object { (Get-LocalGroupMember -Group $_ | Where-Object { $_.SID -eq $lu.SID }) } | ForEach-Object Name | Sort-Object)
    }
  }
  $o.users += [pscustomobject]$u
}
ConvertTo-Json -Depth 5 -Compress -InputObject ([pscustomobject]$o)
`

func directoryWindows(ctx context.Context) (proto.DirectoryInfo, error) {
	var d proto.DirectoryInfo
	cctx, cancel := context.WithTimeout(ctx, 50*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", directoryScript)
	cmd.Env = append(cmd.Environ(), "MUSTRA_DIR_USERS="+strings.Join(signedInNames(ctx), ","))
	out, err := cmd.Output()
	if err != nil {
		return d, err
	}
	if err := json.Unmarshal(out, &d); err != nil {
		return d, err
	}
	return d, nil
}

var realmField = regexp.MustCompile(`^\s+([a-z-]+): (.*)$`)

func directoryLinux(ctx context.Context) proto.DirectoryInfo {
	d := proto.DirectoryInfo{Kind: "workgroup"}
	if out, err := exec.CommandContext(ctx, "realm", "list").Output(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			if !strings.HasPrefix(line, " ") && strings.TrimSpace(line) != "" && d.Domain == "" {
				d.Domain = strings.TrimSpace(line)
			}
			if m := realmField.FindStringSubmatch(line); m != nil && m[1] == "configured" && m[2] != "no" {
				d.Joined, d.Kind = true, "ad"
			}
		}
	}
	for _, n := range signedInNames(ctx) {
		u := proto.DirectoryUser{Name: n, Source: "local"}
		if strings.Contains(n, "@") || (d.Domain != "" && strings.HasSuffix(strings.ToLower(n), "@"+strings.ToLower(d.Domain))) {
			u.Source = "ad"
		}
		if out, err := exec.CommandContext(ctx, "id", "-Gn", n).Output(); err == nil {
			u.Groups = strings.Fields(string(out))
			sort.Strings(u.Groups)
		}
		if out, err := exec.CommandContext(ctx, "getent", "passwd", n).Output(); err == nil {
			if f := strings.Split(strings.TrimSpace(string(out)), ":"); len(f) > 4 {
				u.DisplayName = strings.Split(f[4], ",")[0]
			}
		}
		d.Users = append(d.Users, u)
	}
	if !d.Joined {
		d.Domain = ""
	}
	return d
}

func directoryDarwin(ctx context.Context) proto.DirectoryInfo {
	d := proto.DirectoryInfo{Kind: "workgroup"}
	if out, err := exec.CommandContext(ctx, "dsconfigad", "-show").Output(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			k, v, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			switch strings.TrimSpace(k) {
			case "Active Directory Domain":
				d.Domain, d.Joined, d.Kind = strings.TrimSpace(v), true, "ad"
			case "Computer Account":
				d.ComputerDN = strings.TrimSpace(v)
			}
		}
	}
	names := signedInNames(ctx)
	if out, err := exec.CommandContext(ctx, "stat", "-f%Su", "/dev/console").Output(); err == nil {
		if c := strings.TrimSpace(string(out)); c != "" && c != "root" && !containsFold(names, c) {
			names = append(names, c)
		}
	}
	for _, n := range names {
		u := proto.DirectoryUser{Name: n, Source: "local"}
		if out, err := exec.CommandContext(ctx, "id", "-Gn", n).Output(); err == nil {
			u.Groups = strings.Fields(string(out))
			sort.Strings(u.Groups)
		}
		if out, err := exec.CommandContext(ctx, "dscl", ".", "-read", "/Users/"+n, "RealName").Output(); err == nil {
			lines := strings.Split(strings.TrimSpace(string(out)), "\n")
			u.DisplayName = strings.TrimSpace(lines[len(lines)-1])
			if strings.HasPrefix(u.DisplayName, "RealName:") {
				u.DisplayName = strings.TrimSpace(strings.TrimPrefix(u.DisplayName, "RealName:"))
			}
		}
		if d.Joined {
			if out, err := exec.CommandContext(ctx, "dscl", ".", "-read", "/Users/"+n, "OriginalNodeName").Output(); err == nil && strings.Contains(string(out), "Active Directory") {
				u.Source = "ad"
			}
		}
		d.Users = append(d.Users, u)
	}
	return d
}

func containsFold(list []string, v string) bool {
	for _, x := range list {
		if strings.EqualFold(x, v) {
			return true
		}
	}
	return false
}
