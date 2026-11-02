# Fix broken apt repositories.
#
# A third-party repository that has nothing for this release (404, "no
# longer has a Release file") or whose signing key expired makes every
# apt-get update fail. This finds those repositories and turns off only them,
# after backing up each file it changes. Network trouble (DNS, timeouts,
# 5xx) is not a broken repository, so it changes nothing then.
#
# Parameters (MUSTRA_PARAM_*):
#   mode              disable (default) | report | restore
#   include_os_repos  true to also disable the OS's own repositories
import os
import re
import shutil
import subprocess
import sys
import time

MODE = os.environ.get("MUSTRA_PARAM_mode", "") or "disable"
INCLUDE_OS = os.environ.get("MUSTRA_PARAM_include_os_repos", "false") == "true"
APT = "/etc/apt"
BACKUPS = "/var/backups/mustra-apt-repos"
# A 404 from the distribution's own mirror is far more likely a typo or a
# mirror hiccup than a dead repository; turning it off stops all OS updates.
OS_HOSTS = ("debian.org", "ubuntu.com", "canonical.com", "proxmox.com", "raspberrypi.com", "raspbian.org")
PERMANENT_HTTP = ("403", "404", "410")


def apt_update():
    env = dict(os.environ, LC_ALL="C", DEBIAN_FRONTEND="noninteractive")
    p = subprocess.run(["apt-get", "update"], capture_output=True, text=True, env=env)
    return p.returncode, p.stdout + p.stderr


def norm(uri):
    return uri.rstrip("/")


def configured_repos():
    """Every enabled (uri, suite) in the source files, both formats."""
    repos = set()
    for path in source_files():
        with open(path) as f:
            text = f.read()
        if path.endswith(".sources"):
            for st in re.split(r"\n[ \t]*\n", text):
                fields = {}
                for line in st.splitlines():
                    m = re.match(r"^([A-Za-z-]+):\s*(.*)$", line)
                    if m:
                        fields[m.group(1).lower()] = m.group(2)
                if fields.get("enabled", "yes").lower() == "no":
                    continue
                for u in fields.get("uris", "").split():
                    for s in fields.get("suites", "").split():
                        repos.add((norm(u), norm(s)))
        else:
            for line in text.splitlines():
                body = re.sub(r"\[[^\]]*\]", " ", line.strip()).split()
                if len(body) >= 3 and body[0] in ("deb", "deb-src"):
                    repos.add((norm(body[1]), norm(body[2])))
    return repos


def broken_repos(out):
    """(uri, suite) -> reason, for errors that will not go away on a retry.

    apt names a failing repository two ways: "The repository 'URI SUITE
    Release' ..." and "Failed to fetch URL  404 ...", where URL is
    URI/dists/SUITE/... or, for a flat repository, URI/SUITE/...; the
    latter is matched against the configured repositories."""
    configured = configured_repos()
    broken = {}
    for line in out.splitlines():
        m = re.match(r"^E: The repository '(\S+) (\S+) (?:In)?Release' (.+)$", line)
        if m:
            reason = m.group(3).rstrip(".")
            if "Release file" in reason or "not signed" in reason:
                broken[(norm(m.group(1)), norm(m.group(2)))] = reason
            continue
        m = re.match(r"^E: Failed to fetch (\S+)\s+(\d{3})\s+(.*)$", line)
        if not m or m.group(2) not in PERMANENT_HTTP:
            continue
        url, reason = m.group(1), m.group(2) + " " + m.group(3).split("[")[0].strip()
        for uri, suite in configured:
            if url.startswith(uri + "/dists/" + suite + "/") or url.startswith(uri + "/" + suite + "/"):
                broken.setdefault((uri, suite), reason)
    return broken


def is_os_repo(uri):
    host = re.sub(r"^\w+://", "", uri).split("/")[0].split(":")[0]
    return any(host == h or host.endswith("." + h) for h in OS_HOSTS)


def source_files():
    files = []
    if os.path.isfile(os.path.join(APT, "sources.list")):
        files.append(os.path.join(APT, "sources.list"))
    d = os.path.join(APT, "sources.list.d")
    if os.path.isdir(d):
        for f in sorted(os.listdir(d)):
            if f.endswith((".list", ".sources")):
                files.append(os.path.join(d, f))
    return files


def fix_list(text, broken):
    """One-line format: comment out deb lines for a broken (uri, suite)."""
    out, changes = [], []
    for line in text.splitlines(keepends=True):
        s = line.strip()
        if s.startswith(("deb ", "deb-src ", "deb\t")):
            body = re.sub(r"\[[^\]]*\]", " ", s).split()
            if len(body) >= 3 and (norm(body[1]), norm(body[2])) in broken:
                reason = broken[(norm(body[1]), norm(body[2]))]
                out.append("# mustra-disabled (" + reason + "): " + line.lstrip())
                changes.append(body[1] + " " + body[2])
                continue
        out.append(line)
    return "".join(out), changes


def fix_sources(text, broken):
    """deb822 format: drop broken suites; a stanza left with none is disabled."""
    stanzas = re.split(r"(\n[ \t]*\n)", text)
    changes = []
    for i in range(0, len(stanzas), 2):
        st = stanzas[i]
        fields = {}
        for line in st.splitlines():
            m = re.match(r"^([A-Za-z-]+):\s*(.*)$", line)
            if m:
                fields[m.group(1).lower()] = m.group(2)
        uris = [norm(u) for u in fields.get("uris", "").split()]
        suites = fields.get("suites", "").split()
        if not uris or not suites or fields.get("enabled", "yes").lower() == "no":
            continue
        # A suite goes only when every mirror in the stanza is broken for it.
        dead = [s for s in suites if all((u, norm(s)) in broken for u in uris)]
        if not dead:
            continue
        reason = broken[(uris[0], norm(dead[0]))]
        keep = [s for s in suites if s not in dead]
        lines = st.splitlines()
        if keep:
            lines = [("Suites: " + " ".join(keep)) if re.match(r"(?i)^suites:", l) else l for l in lines]
            lines.insert(0, "# mustra removed suite(s) " + " ".join(dead) + " (" + reason + ")")
        elif "enabled" in fields:
            lines = [("Enabled: no") if re.match(r"(?i)^enabled:", l) else l for l in lines]
            lines.insert(0, "# mustra-disabled (" + reason + ")")
        else:
            lines.insert(0, "# mustra-disabled (" + reason + ")")
            lines.append("Enabled: no")
        stanzas[i] = "\n".join(lines) + ("\n" if st.endswith("\n") else "")
        changes += [u + " " + s for u in uris for s in dead]
    return "".join(stanzas), changes


def restore():
    runs = sorted(os.listdir(BACKUPS)) if os.path.isdir(BACKUPS) else []
    if not runs:
        print("No backup to restore; nothing was changed by this action.")
        return 0
    last = os.path.join(BACKUPS, runs[-1])
    for root, _, files in os.walk(last):
        for f in files:
            src = os.path.join(root, f)
            dst = os.path.join(APT, os.path.relpath(src, last))
            shutil.copy2(src, dst)
            print("restored " + dst)
    shutil.rmtree(last)
    rc, out = apt_update()
    print("apt-get update now " + ("succeeds." if rc == 0 else "still fails:"))
    if rc:
        print(out)
    return 0


def main():
    if not shutil.which("apt-get"):
        print("Not an apt-based system; nothing to do.")
        return 0
    if MODE == "restore":
        return restore()
    if MODE not in ("disable", "report"):
        print("mode must be disable, report or restore", file=sys.stderr)
        return 2
    rc, out = apt_update()
    errors = [l for l in out.splitlines() if l.startswith(("E:", "W:", "Err:"))]
    if rc == 0 and not any(l.startswith("E:") for l in errors):
        warned = [l for l in errors if l.startswith("W:")]
        print("apt-get update succeeds; nothing to fix." + (" Warnings, likely temporary:" if warned else ""))
        if warned:
            print("\n".join(warned))
        return 0
    if not re.search(r"^(Hit|Get):", out, re.M):
        print("No repository answered, which is a network problem rather than a broken repository. Changed nothing.")
        print("\n".join(errors))
        return 1
    broken = broken_repos(out)
    skipped = {k: v for k, v in broken.items() if is_os_repo(k[0]) and not INCLUDE_OS}
    for k in skipped:
        del broken[k]
    for (uri, suite), reason in sorted(skipped.items()):
        print("Not touching OS repository " + uri + " " + suite + " (" + reason + "); set include_os_repos to change it.")
    if not broken:
        print("apt-get update fails, but not because of a repository this action can turn off:")
        print("\n".join(errors))
        return 1
    print("Broken repositories:")
    for (uri, suite), reason in sorted(broken.items()):
        print("  " + uri + " " + suite + ": " + reason)

    stamp = time.strftime("%Y%m%d-%H%M%S")
    changed = 0
    for path in source_files():
        with open(path) as f:
            text = f.read()
        new, changes = (fix_sources if path.endswith(".sources") else fix_list)(text, broken)
        if not changes:
            continue
        print(("Would change " if MODE == "report" else "Disabling in ") + path + ": " + ", ".join(changes))
        if MODE == "report":
            continue
        backup = os.path.join(BACKUPS, stamp, os.path.relpath(path, APT))
        os.makedirs(os.path.dirname(backup), exist_ok=True)
        shutil.copy2(path, backup)
        with open(path, "w") as f:
            f.write(new)
        changed += 1
    if MODE == "report":
        print("Report only; nothing changed.")
        return 0
    if not changed:
        print("Could not find these repositories in " + APT + "; nothing changed.")
        return 1
    print("Backed up the original files to " + os.path.join(BACKUPS, stamp) + "; run this action with mode=restore to undo.")
    rc, out = apt_update()
    if rc == 0:
        print("apt-get update now succeeds.")
        return 0
    print("apt-get update still fails:")
    print("\n".join(l for l in out.splitlines() if l.startswith(("E:", "W:", "Err:"))))
    return 1


if __name__ == "__main__":
    sys.exit(main())
