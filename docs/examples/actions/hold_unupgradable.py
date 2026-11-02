# Hold Linux packages apt cannot upgrade.
#
# An update apt cannot install (a newer build from another suite that needs
# a newer libstdc++, a hand-installed driver whose library is already held)
# stays "pending" forever and keeps patch jobs from finishing clean. Holding
# it says "leave this version alone" to apt and to mustra's patching alike.
# Updates that only need new packages (kernels, pve-firewall) install fine
# and are never held.
#
# Parameters (MUSTRA_PARAM_*):
#   mode      hold (default) | report | unhold
#   packages  names to hold or release, space or comma separated. Empty with
#             hold finds the blocked ones; empty with unhold releases every
#             hold this action placed.
import os
import re
import shutil
import subprocess
import sys

MODE = os.environ.get("MUSTRA_PARAM_mode", "") or "hold"
NAMES = [n for n in re.split(r"[\s,]+", os.environ.get("MUSTRA_PARAM_packages", "")) if n]
LEDGER = "/var/lib/mustra/apt-holds"
ENV = dict(os.environ, LC_ALL="C", DEBIAN_FRONTEND="noninteractive")


def run(*args):
    p = subprocess.run(list(args), capture_output=True, text=True, env=ENV)
    return p.returncode, p.stdout + p.stderr


def holds():
    return set(run("apt-mark", "showhold")[1].split())


def kept_back():
    _, out = run("apt-get", "-s", "upgrade")
    kept, inside = [], False
    for line in out.splitlines():
        if re.match(r"The following packages have been (kept|held) back", line):
            inside = True
            continue
        if inside:
            if not line.startswith(" "):
                inside = False
                continue
            kept += line.split()
    return kept


def why_blocked(pkg):
    """None when apt can upgrade pkg on its own, else apt's reason."""
    rc, out = run("apt-get", "-s", "install", "--only-upgrade", "--no-remove", pkg)
    if rc == 0:
        return None
    for line in out.splitlines():
        if "Depends: " in line:
            return line[line.index("Depends: "):].strip()
    for line in out.splitlines():
        if line.startswith("E: "):
            return line[3:]
    return "apt could not resolve it"


def ledger_read():
    try:
        with open(LEDGER) as f:
            return [l.strip() for l in f if l.strip()]
    except FileNotFoundError:
        return []


def ledger_write(names):
    os.makedirs(os.path.dirname(LEDGER), exist_ok=True)
    with open(LEDGER, "w") as f:
        f.write("".join(n + "\n" for n in sorted(set(names))))


def main():
    if not shutil.which("apt-get"):
        print("Not an apt-based system; nothing to do.")
        return 0
    if MODE not in ("hold", "report", "unhold"):
        print("mode must be hold, report or unhold", file=sys.stderr)
        return 2
    held = holds()
    if MODE == "unhold":
        names = NAMES or ledger_read()
        if not names:
            print("No packages given and this action has placed no holds; nothing to release.")
            return 0
        rc, out = run("apt-mark", "unhold", *names)
        print(out.strip())
        ledger_write([n for n in ledger_read() if n not in names])
        return rc

    if NAMES:
        targets = {n: "requested" for n in NAMES}
    else:
        # Fresh lists first; one broken repository must not stop the check.
        run("apt-get", "update")
        targets = {}
        for pkg in kept_back():
            if pkg in held:
                continue
            reason = why_blocked(pkg)
            if reason:
                targets[pkg] = reason
    print("Already held: " + (" ".join(sorted(held)) or "none"))
    if not targets:
        print("Every pending update can be installed; nothing to hold.")
        return 0
    for pkg, reason in sorted(targets.items()):
        print(("Would hold " if MODE == "report" else "Holding ") + pkg + ": " + reason)
    if MODE == "report":
        print("Report only; nothing changed.")
        return 0
    rc, out = run("apt-mark", "hold", *sorted(targets))
    print(out.strip())
    if rc == 0:
        ledger_write(ledger_read() + sorted(targets))
        print("Run this action with mode=unhold to release these holds.")
    return rc


if __name__ == "__main__":
    sys.exit(main())
