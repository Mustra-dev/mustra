# Enforce settings
<!-- group: Secure; order: 43; pages: /enforce -->

Hold a setting in place: check it on a timer, and put it back when it drifts. For example, keep the firewall on, keep BitLocker on, keep a risky service disabled.

## Before you start

- You need **Deploy software and run actions** (`deploy.manage`), because a fix runs a command on endpoints with full rights.
- Reading escrowed BitLocker recovery keys needs **Read BitLocker recovery keys** (`enforce.recovery_keys`), and every read is audited.

## How it keeps you safe

- **New policies only report.** They check and record and change nothing until you switch them to enforce.
- **Dry run** shows what an enforcing policy would do, without doing it.
- **It re-checks after fixing.** A fix only counts as *remediated* if the second check passes.
- **It gives up.** After three failed fixes in a row on one endpoint, it stops trying there and shows *given up*. Editing the policy or choosing **Reset history** lets it try again.
- **Every fix is in the audit log.**

## Create a policy

1. Open **Enforce → Policies**, then **New policy**.
2. Choose the platform and the computer group it applies to.
3. Choose **Add a setting**. Either pick a ready-made kind (**Windows Firewall**, **BitLocker**, **Microsoft Defender** or **AppLocker**, all Windows) and its options, or write your own:
   - **Rules** that decide whether the setting holds, in the same format Comply uses. For example `c:systemctl is-active ufw -> r:^active` runs a command and matches its output.
   - A **Fix** command per platform. Leave it empty to only report drift.
4. Leave the mode on **Report — check and record only** and choose **Save policy**.
5. Choose **Run now** and read **Standing, per endpoint**: which endpoints are *compliant* and which have *drifted*.
6. When the results look right, edit the policy, set the mode to **Enforce — fix what has drifted**, and save. It runs every 30 minutes by default.

## Read the results

**Standing, per endpoint** shows each endpoint's state for each setting:

| State | Meaning |
| --- | --- |
| compliant | The setting holds |
| drifted | It does not, and the policy is in report mode (or has no fix) |
| remediated | It did not, the fix ran, and the re-check passed |
| failed | The fix ran but the re-check still failed |
| given up | Three fixes failed in a row; it has stopped trying on this endpoint |
| unknown | The endpoint could not evaluate the rule |

Choose **output** to see what the check and fix commands printed.

**Coverage** shows the security posture of every endpoint: firewall, disk encryption, antivirus, application control and whether a recovery key is escrowed.
