# macOS updates

Most patching needs nothing beyond the agent. Linux (apt, dnf, yum), Windows
(Windows Update), Intel Macs, and app updates on any Mac (Safari, Xcode
command line tools, Rapid Security Responses delivered as apps) install from
**Patch → Apply** with no further setup.

**macOS itself on Apple Silicon is the exception.** There, `softwareupdate`
installs a macOS update only with the password of a user who owns the disk
(a *volume owner*). The agent runs as root with no such password, so it
cannot. Before agent 0.57.12 it downloaded the whole update (4–12 GB) and
then failed with `Failed to authenticate`; it now skips macOS updates on
Apple Silicon, installs everything else, and says what it skipped.

To install macOS from Mustra on Apple Silicon, connect an MDM that holds the
Mac's **Bootstrap Token**. Apple lets that MDM install OS updates without a
password (the `ScheduleOSUpdate` command). Mustra supports Fleet for this.

## What a Mac needs

1. **Enrolled in Fleet with MDM on**, user-approved or through Automated
   Device Enrollment. `sudo profiles status -type enrollment` on the Mac
   shows `MDM enrollment: Yes`.
2. **Bootstrap Token escrowed to Fleet.** macOS escrows it automatically when
   a volume owner signs in after enrollment.
   `sudo profiles status -type bootstraptoken` must show
   `Bootstrap Token escrowed to server: YES`. If it says NO, have the Mac's
   user sign out and back in, or run `sudo profiles install -type bootstraptoken`
   and enter their password once.
3. **Same hostname in Mustra and Fleet.** The agent reports no serial
   number, so Mustra finds the Mac in Fleet by hostname (`Alexs-MacBook-Pro.local`
   and `alexs-macbook-pro` match). Two Macs with one name are refused.

## Connecting Fleet

1. In Fleet, create an **API-only user with the maintainer role** and copy
   its token. With `fleetctl` logged in as an admin:
   `fleetctl user create --name mustra --email mustra-api@example.com --api-only --global-role maintainer`.
   Fleet's free tier is enough: Mustra sends raw MDM commands through
   `POST /api/v1/fleet/commands/run`, not Fleet's Premium OS-update policies.
2. In Mustra, **Administration → Settings → macOS updates through the MDM**:
   enter the Fleet URL and token, Save, then **Test connection**. Only an
   administrator can change these; the token is stored with the credential
   vault when `MUSTRA_CREDENTIAL_ENCRYPTION_KEY` is set and is never shown again.
3. Leave **Also install major upgrades** off to install only updates within
   the current macOS version (26.5 → 26.7). Turn it on to allow 26 → 27.

## macOS 27 and later

macOS 27 removed the MDM software update commands this page describes
below: a Mac on 27 answers `AvailableOSUpdates` with *Unknown command*.
Apple's replacement is a declarative management configuration
(`com.apple.configuration.softwareupdate.enforcement.specific`), and
**Fleet accepts that declaration only with a Fleet Premium license** (on
the free tier it answers `402 Requires Fleet Premium license`).

**Without Fleet Premium** (or without Fleet at all), the agent does what
needs no password and leaves the rest to the person at the Mac:

1. The patch run installs everything else and downloads the macOS update
   (`softwareupdate --download`) in the background.
2. When the download finishes, the Mac shows a notification and the Self
   Service window offers **Install…**, which opens System Settings →
   General → Software Update, where the update is ready: it asks for their
   password and restarts to finish. **Later** postpones the reminder.
3. Their answer is recorded on the patch run. The update counts as
   installed once the Mac reports the new version.

**With Fleet Premium**, Mustra sends the declaration:

1. The target is the newest macOS update the agent reports pending that the
   patch lists allow (a major upgrade only when those are turned on).
2. Mustra uploads the declaration to Fleet as a configuration profile
   (`com.mustra.macos-update`, replacing any earlier one).
3. With a restart option (**if required** or **always**) the deadline is
   already past, so the Mac installs and restarts at once. Without one the
   deadline is three days away: macOS asks the signed-in user to install
   it and installs and restarts on its own after the deadline.
4. The install finishes when the Mac reports the new version, and fails a
   day after the deadline if it has not. Either way the declaration is then
   removed from Fleet.

The Mac must be **supervised**, which Automated Device Enrollment and a
user-approved enrollment both give on current macOS
(`sudo /usr/libexec/mdmclient QueryDeviceInformation | grep IsSupervised`).

**Fleet's free tier cannot aim a profile at one Mac**: that takes labels
or teams, which are Premium, so a profile reaches every Mac in no team.
Mustra therefore sends the declaration only when the Mac being patched is
the only enrolled Mac in no team, and refuses otherwise, naming the other
Macs, rather than updating Macs nobody patched. The commands in the next
section are still used for Macs on macOS 26 and earlier.

## What happens on a patch run

1. The agent installs every update it can (apps, Safari) one at a time and
   notes that macOS is left to the MDM.
2. When the agent's job finishes, the server finds the Mac in Fleet, asks it
   for its available OS updates (`AvailableOSUpdates`), and picks the newest
   one the agent also reports pending and the patch lists allow.
3. It sends `ScheduleOSUpdate`:
   - with a restart option (**if required** or **always**): `InstallASAP`.
     The Mac downloads, installs and restarts on its own, without warning
     the signed-in user beyond macOS's own notice;
   - without one: `InstallLater`. The Mac downloads the update and asks the
     signed-in user to install it, so nobody loses work to a restart.
4. The macOS install is its own row in the deployment. It succeeds when the
   Mac reports the new version, is **pending restart** when the user was
   asked to install it, and fails if the Mac refuses (the reason from macOS
   is shown) or still runs the old version after 4 hours.

## Troubleshooting

| Result | Meaning |
| --- | --- |
| `no Mac named … is enrolled in Fleet` | Not enrolled, or a different hostname in Fleet. |
| `The Mac did not answer Fleet within 3 minutes` | Asleep or offline; APNs delivers when it wakes. Run the job again. |
| `The Mac refused …: … bootstrap token …` | The token is not escrowed; see step 2 under *What a Mac needs*. |
| `Fleet's free tier cannot aim an update at one Mac, and N Macs are in no Fleet team` | macOS 27+: the declaration would reach all of them. Install from System Settings, or move the other Macs to a Fleet team. |
| `The Mac is in a Fleet team` | macOS 27+: Mustra's declaration is for Macs in no team. |
| `No macOS update to install` | Only a major upgrade is pending and major upgrades are off, or the patch lists block it. |
| Agent note `Skipped macOS …` (not `Left … to the MDM`) | Fleet is not configured; set it up as above, or install from System Settings → General → Software Update. |

The integration is in `internal/server/fleetmdm.go`; the agent side is
`applyPatchesDarwin` in `internal/agent/patches.go`.
