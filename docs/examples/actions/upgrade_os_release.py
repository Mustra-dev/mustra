# Upgrade OS release (Linux: Ubuntu, Debian, Alpine).
#
# Moves an endpoint to its distribution's next release: the fix for a
# release past its end of life, whose vulnerabilities will not be fixed.
# mode=check (the default) changes nothing: it says what would happen and
# whether the endpoint is ready. mode=upgrade does it.
#
#   Ubuntu  do-release-upgrade, non-interactive. A release past end of life
#           has moved to old-releases.ubuntu.com; its sources are pointed
#           there first so it can still reach the upgrade.
#   Debian  the official Debian repositories move to the next stable
#           codename (third-party repositories are left alone), then
#           apt-get full-upgrade.
#   Alpine  the repositories move to the latest stable branch, then
#           apk upgrade --available.
#
# Every repository file is backed up first, under
# /var/backups/mustra-os-upgrade/<time>/. Proxmox VE hosts are refused:
# they have their own upgrade procedure (pveXtoY checklists).
#
# Parameters (MUSTRA_PARAM_*):
#   mode    check (default) | upgrade
#   reboot  true to restart when the upgrade needs it to finish
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.request

MODE = (os.environ.get("MUSTRA_PARAM_mode", "") or "check").strip().lower()
REBOOT = os.environ.get("MUSTRA_PARAM_reboot", "false").strip().lower() == "true"
BACKUP_ROOT = "/var/backups/mustra-os-upgrade"
MIN_FREE_GIB = 5

# Debian stable releases in order; testing and unstable are never targets.
DEBIAN_NEXT = {"stretch": "buster", "buster": "bullseye", "bullseye": "bookworm", "bookworm": "trixie"}
DEBIAN_HOSTS = ("debian.org",)
UBUNTU_HOSTS = ("archive.ubuntu.com", "security.ubuntu.com", "ports.ubuntu.com")


def say(msg=""):
    print(msg, flush=True)


def fail(msg):
    say("FAILED: " + msg)
    sys.exit(1)


def run(cmd, check=True, env_extra=None, quiet=False):
    env = dict(os.environ, LC_ALL="C", DEBIAN_FRONTEND="noninteractive", NEEDRESTART_MODE="a")
    if env_extra:
        env.update(env_extra)
    say("$ " + " ".join(cmd))
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env)
    if not quiet and p.stdout.strip():
        lines = p.stdout.strip().splitlines()
        if len(lines) > 60:
            say("  ... (%d lines) ..." % (len(lines) - 60))
            lines = lines[-60:]
        say("\n".join("  " + l for l in lines))
    if check and p.returncode != 0:
        fail("%s exited %d" % (cmd[0], p.returncode))
    return p.returncode, p.stdout


def os_release():
    info = {}
    for path in ("/etc/os-release", "/usr/lib/os-release"):
        if os.path.exists(path):
            with open(path) as f:
                for line in f:
                    k, _, v = line.strip().partition("=")
                    if k:
                        info[k] = v.strip().strip('"')
            break
    return info


def free_gib(path):
    st = os.statvfs(path)
    return st.f_bavail * st.f_frsize / (1024 ** 3)


def backup(paths):
    dest = os.path.join(BACKUP_ROOT, time.strftime("%Y%m%d-%H%M%S"))
    os.makedirs(dest, exist_ok=True)
    for p in paths:
        if os.path.isdir(p):
            shutil.copytree(p, os.path.join(dest, p.strip("/").replace("/", "_")), dirs_exist_ok=True)
        elif os.path.exists(p):
            shutil.copy2(p, os.path.join(dest, p.strip("/").replace("/", "_")))
    say("Backed up %s to %s" % (", ".join(paths), dest))
    return dest


def apt_source_files():
    files = []
    if os.path.exists("/etc/apt/sources.list"):
        files.append("/etc/apt/sources.list")
    d = "/etc/apt/sources.list.d"
    if os.path.isdir(d):
        files += sorted(os.path.join(d, f) for f in os.listdir(d) if f.endswith((".list", ".sources")))
    return files


def rewrite_suites(files, hosts, old, new, apply):
    """Replace the codename `old` with `new` in the suites of repositories
    whose URI is on one of `hosts`, in both one-line and deb822 formats.
    Returns the number of changed lines."""
    word = re.compile(r"\b" + re.escape(old) + r"(?=$|[-\s])")
    changed = 0
    for path in files:
        with open(path) as f:
            text = f.read()
        out = []
        if path.endswith(".sources"):
            # deb822: stanzas separated by blank lines; Suites applies to
            # the stanza's URIs.
            for stanza in re.split(r"(\n\s*\n)", text):
                uris = re.search(r"(?mi)^URIs:\s*(.+)$", stanza)
                if uris and any(h in uris.group(1) for h in hosts):
                    def fix(m):
                        nonlocal changed
                        new_line = word.sub(new, m.group(0))
                        if new_line != m.group(0):
                            changed += 1
                        return new_line
                    stanza = re.sub(r"(?mi)^Suites:.*$", fix, stanza)
                out.append(stanza)
            result = "".join(out)
        else:
            for line in text.splitlines(keepends=True):
                s = line.strip()
                if s.startswith(("deb ", "deb-src ")) and any(h in s for h in hosts):
                    new_line = word.sub(new, line)
                    if new_line != line:
                        changed += 1
                        line = new_line
                out.append(line)
            result = "".join(out)
        if apply and result != text:
            with open(path, "w") as f:
                f.write(result)
    return changed


def reboot_if_asked(needed):
    if not needed:
        say("No restart needed.")
        return
    if REBOOT:
        say("Restarting in one minute to finish the upgrade.")
        subprocess.run(["shutdown", "-r", "+1", "mustra: OS release upgrade"])
    else:
        say("RESTART REQUIRED to finish the upgrade (the reboot parameter was off).")


def preflight_common():
    problems = []
    gib = free_gib("/")
    say("Free space on /: %.1f GiB" % gib)
    if gib < MIN_FREE_GIB:
        problems.append("only %.1f GiB free on /; an upgrade needs at least %d GiB" % (gib, MIN_FREE_GIB))
    if os.path.ismount("/boot"):
        boot = free_gib("/boot")
        say("Free space on /boot: %.2f GiB" % boot)
        if boot < 0.2:
            problems.append("only %.0f MiB free on /boot" % (boot * 1024))
    return problems


# ---------------------------------------------------------------- Debian

def debian(info):
    current = info.get("VERSION_CODENAME", "")
    if not current:
        fail("cannot tell this Debian release's codename (VERSION_CODENAME is not set)")
    target = DEBIAN_NEXT.get(current)
    say("Debian %s (%s)" % (info.get("VERSION_ID", "?"), current))
    if not target:
        say("Already on the newest stable release this package knows (%s); nothing to do." % current)
        return
    say("Next stable release: %s" % target)
    problems = preflight_common()
    _, audit = run(["dpkg", "--audit"], check=False, quiet=True)
    if audit.strip():
        problems.append("dpkg reports unfinished packages; run apt-get --fix-broken install first:\n" + audit.strip())
    rc, _ = run(["apt-get", "update"], check=False)
    if rc != 0:
        problems.append("apt-get update fails on the current release; fix that first")
    _, held = run(["apt-mark", "showhold"], check=False, quiet=True)
    if held.strip():
        say("Held packages (they stay where they are): " + ", ".join(held.split()))
    files = apt_source_files()
    n = rewrite_suites(files, DEBIAN_HOSTS, current, target, apply=False)
    say("Official Debian repository lines to move from %s to %s: %d (in %s)" % (current, target, n, ", ".join(files)))
    if n == 0:
        problems.append("no official Debian repository lines name %s, so there is nothing to move" % current)
    if problems:
        fail("not ready:\n- " + "\n- ".join(problems))
    if MODE != "upgrade":
        say("READY. Run again with mode=upgrade to upgrade to %s." % target)
        return
    backup(["/etc/apt/sources.list", "/etc/apt/sources.list.d"])
    opts = ["-y", "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold"]
    say("== Bringing %s fully up to date first" % current)
    rc, out = run(["apt-get"] + opts + ["full-upgrade"], check=False)
    if rc != 0:
        if "404" in out:
            # A release past its LTS loses packages from the mirror; the
            # move to the next release does not need them.
            say("Some %s updates are no longer on the mirror; going straight to %s." % (current, target))
        else:
            fail("apt-get full-upgrade on %s failed; fix that first" % current)
    say("== Moving repositories to %s" % target)
    rewrite_suites(files, DEBIAN_HOSTS, current, target, apply=True)
    rc, _ = run(["apt-get", "update"], check=False)
    if rc != 0:
        fail("apt-get update fails for %s; the repository files are backed up under %s to put back" % (target, BACKUP_ROOT))
    say("== Upgrading to %s" % target)
    run(["apt-get"] + opts + ["upgrade", "--without-new-pkgs"])
    run(["apt-get"] + opts + ["full-upgrade"])
    say("Upgraded to Debian %s." % target)
    reboot_if_asked(True)


# ---------------------------------------------------------------- Ubuntu

def forget_release_list():
    # do-release-upgrade keeps the release list it last downloaded and can
    # answer "No new release found" from a stale copy; drop it so each
    # check reads Ubuntu's current list.
    for name in ("meta-release", "meta-release-lts", "meta-release-development", "meta-release-proposed"):
        try:
            os.remove(os.path.join("/var/lib/update-manager", name))
        except OSError:
            pass


def ubuntu(info):
    current = info.get("VERSION_CODENAME", "")
    say("Ubuntu %s (%s)" % (info.get("VERSION_ID", "?"), current))
    problems = preflight_common()
    files = apt_source_files()
    rc, out = run(["apt-get", "update"], check=False)
    moved = False
    if rc != 0 and ("404" in out or "does not have a Release file" in out or "no longer has a Release file" in out):
        # A release past end of life is removed from the archive and kept
        # on old-releases.ubuntu.com; point at it so the upgrade can run.
        n = 0
        for path in files:
            with open(path) as f:
                text = f.read()
            new = re.sub(r"https?://([a-z0-9.-]+\.)?(archive|security)\.ubuntu\.com/ubuntu", "http://old-releases.ubuntu.com/ubuntu", text)
            if new != text:
                n += 1
                if MODE == "upgrade":
                    if not moved:
                        backup(["/etc/apt/sources.list", "/etc/apt/sources.list.d"])
                        moved = True
                    with open(path, "w") as f:
                        f.write(new)
        say("This release is no longer on the Ubuntu archive; %d source file(s) %s old-releases.ubuntu.com." %
            (n, "now point at" if MODE == "upgrade" else "would point at"))
        if MODE == "upgrade":
            rc, out = run(["apt-get", "update"], check=False)
    if rc != 0 and MODE == "upgrade":
        problems.append("apt-get update fails; fix the repositories first")
    _, audit = run(["dpkg", "--audit"], check=False, quiet=True)
    if audit.strip():
        problems.append("dpkg reports unfinished packages; run apt-get --fix-broken install first")
    # do-release-upgrade refuses until every update for this release is in.
    _, sim = run(["apt-get", "-s", "full-upgrade"], check=False, quiet=True)
    pending = sum(1 for l in sim.splitlines() if l.startswith("Inst "))
    say("Updates pending for %s: %d%s" % (current, pending, " (installed first)" if pending else ""))
    if not shutil.which("do-release-upgrade"):
        if MODE == "upgrade":
            run(["apt-get", "install", "-y", "update-manager-core"])
        else:
            say("do-release-upgrade is not installed; mode=upgrade installs update-manager-core first.")
    if shutil.which("do-release-upgrade"):
        m = None
        for attempt in range(3):
            forget_release_list()
            _, chk = run(["do-release-upgrade", "-c"], check=False)
            m = re.search(r"New release '([^']+)' available", chk)
            if m or "No new release found" not in chk or attempt == 2:
                break
            say("No release found this time; retrying in 30 seconds.")
            time.sleep(30)
        if m:
            say("Next release offered: %s" % m.group(1))
        elif "No new release found" in chk:
            problems.append("no new release is offered for this endpoint (Prompt= in "
                            "/etc/update-manager/release-upgrades decides between every release and LTS only)")
    if problems:
        fail("not ready:\n- " + "\n- ".join(problems))
    if MODE != "upgrade":
        say("READY. Run again with mode=upgrade to upgrade.")
        return
    opts = ["-y", "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold"]
    say("== Bringing %s fully up to date first" % current)
    run(["apt-get"] + opts + ["full-upgrade"])
    say("== Upgrading with do-release-upgrade (non-interactive; this takes a while)")
    # The release list it downloads is occasionally stale for a moment and
    # says "No new release found" right after -c offered one: try again.
    for attempt in range(3):
        forget_release_list()
        rc, out = run(["do-release-upgrade", "-f", "DistUpgradeViewNonInteractive"], check=False,
                      env_extra={"DEBIAN_PRIORITY": "critical"})
        if rc == 0 or "No new release found" not in out or attempt == 2:
            break
        say("No release found this time; retrying in 60 seconds.")
        time.sleep(60)
    if rc != 0:
        fail("do-release-upgrade exited %d" % rc)
    after = os_release()
    say("Now Ubuntu %s (%s)." % (after.get("VERSION_ID", "?"), after.get("VERSION_CODENAME", "?")))
    reboot_if_asked(True)


# ---------------------------------------------------------------- Alpine

def alpine():
    with open("/etc/alpine-release") as f:
        full = f.read().strip()
    current = ".".join(full.split(".")[:2])
    say("Alpine %s" % full)
    repos = "/etc/apk/repositories"
    with open(repos) as f:
        text = f.read()
    m = re.search(r"(https?://[^\s]+?)/v\d+\.\d+/", text)
    mirror = m.group(1) if m else "https://dl-cdn.alpinelinux.org/alpine"
    arch = subprocess.run(["apk", "--print-arch"], stdout=subprocess.PIPE, text=True).stdout.strip() or "x86_64"
    try:
        with urllib.request.urlopen("%s/latest-stable/releases/%s/latest-releases.yaml" % (mirror, arch), timeout=30) as r:
            y = r.read().decode()
        latest = re.search(r"version:\s*([0-9]+\.[0-9]+)", y).group(1)
    except Exception as e:
        fail("cannot find the latest Alpine release from %s: %s" % (mirror, e))
    say("Latest stable release: %s" % latest)
    if [int(x) for x in latest.split(".")] <= [int(x) for x in current.split(".")]:
        say("Already on the latest stable release; nothing to do.")
        return
    problems = preflight_common()
    n = len(re.findall(r"/v" + re.escape(current) + r"/", text))
    say("Repository lines to move from v%s to v%s: %d" % (current, latest, n))
    if n == 0:
        problems.append("no repository line names v%s" % current)
    if problems:
        fail("not ready:\n- " + "\n- ".join(problems))
    if MODE != "upgrade":
        say("READY. Run again with mode=upgrade to upgrade to %s." % latest)
        return
    backup([repos])
    with open(repos, "w") as f:
        f.write(text.replace("/v%s/" % current, "/v%s/" % latest))
    run(["apk", "update"])
    run(["apk", "upgrade", "--available", "--no-progress"])
    run(["sync"])
    with open("/etc/alpine-release") as f:
        say("Now Alpine %s." % f.read().strip())
    kernel = os.path.isdir("/lib/modules") and not os.path.isdir("/lib/modules/" + os.uname().release)
    reboot_if_asked(kernel)


def main():
    if os.geteuid() != 0:
        fail("must run as root")
    if MODE not in ("check", "upgrade"):
        fail("mode must be check or upgrade, not %r" % MODE)
    say("Mode: %s%s" % (MODE, " (nothing will be changed)" if MODE == "check" else ""))
    if os.path.exists("/usr/bin/pveversion") or os.path.exists("/etc/pve"):
        fail("this is a Proxmox VE host. Upgrade it with Proxmox's own procedure (the pveXtoY checklist script and its documentation), not this package.")
    if os.path.exists("/etc/alpine-release"):
        alpine()
        return
    info = os_release()
    distro = info.get("ID", "")
    if distro == "debian" or (distro == "raspbian"):
        debian(info)
    elif distro == "ubuntu":
        ubuntu(info)
    else:
        fail("unsupported distribution %r (Ubuntu, Debian and Alpine are supported)" % (info.get("PRETTY_NAME") or distro))


main()
