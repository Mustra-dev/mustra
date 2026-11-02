# Terms of Use

These terms cover the mustra software, its source code, releases and
container images, its documentation, the mustra.dev website and the
project's email addresses (together, "mustra"). They are offered by the
mustra maintainers ("we"). By downloading, installing, running or
contributing to mustra, you accept them.

## 1. The license comes first

mustra is free software licensed under the
[GNU Affero General Public License v3.0](LICENSE) (AGPL). Nothing in these
terms takes away or restricts any right the AGPL gives you. Where these
terms and the AGPL disagree, the AGPL wins. These terms explain what the
license already says about warranty and liability, and set out
responsibilities that the law places on whoever operates the software.

## 2. No warranty

mustra is provided **"as is" and "as available", without warranty of any
kind**, express or implied, including warranties of merchantability,
fitness for a particular purpose, title, non-infringement, accuracy and
uninterrupted or error-free operation. This repeats sections 15 and 16 of
the AGPL.

In particular, we do not promise that mustra:

- will find every vulnerability, misconfiguration, threat or missing patch;
- reports correct compliance results. Compliance reports and control
  mappings help with an assessment. They are not an audit, a
  certification, or legal or regulatory advice;
- installs, removes, patches or changes software on an endpoint without
  side effects;
- is free of security vulnerabilities.

## 3. Limitation of liability

To the fullest extent the law allows, **the mustra maintainers,
contributors and copyright holders are not liable** for any damages of any
kind arising from mustra or its use, or from being unable to use it. This
includes direct, indirect, incidental, special, consequential and punitive
damages, and damages for lost data, lost profits, business interruption,
system downtime, security incidents, damage to devices, or claims by third
parties. This applies however the damage was caused and on any theory of
liability (contract, tort including negligence, or otherwise), even if we
were told the damage was possible.

Where the law does not allow liability to be excluded entirely, our total
liability is limited to the amount you paid us for mustra, which for the
software is nothing.

## 4. You operate it, and you are responsible for how it is used

mustra is self-hosted. **You run it on your own infrastructure, and you
decide what it does.** The maintainers have no access to your deployment,
its endpoints or its data, and do not operate it for you.

mustra runs commands with administrative (root or SYSTEM) rights on every
endpoint it manages. It can install and remove software, change settings,
run scripts, collect information about devices and their users, and open
remote sessions. As its operator, you are responsible for:

1. **Authorization.** Install the mustra agent only on devices you own, or
   that you are explicitly authorized to manage by their owner. Using
   mustra to access, monitor or control a device without that
   authorization may be a crime, for example under the U.S. Computer Fraud
   and Abuse Act or the UK Computer Misuse Act.
2. **Privacy and monitoring laws.** mustra can collect information about
   people: who is signed in, which processes and applications they run,
   network activity, and files that match search patterns. You are
   responsible for complying with the laws that apply to collecting it,
   including data protection law (such as the GDPR), employee-monitoring
   and notice requirements, and any works-council or consent obligations.
   For data mustra collects, you are the controller. We are not your
   processor and never receive the data.
3. **Testing before you act at scale.** Test packages, scripts, patches,
   policies, playbooks and remediations on a small number of endpoints
   first. A command run across a fleet can break every device in it.
4. **Securing your deployment.** This covers access to the console,
   accounts and roles, credentials, the encryption key, certificates,
   backups, network exposure and keeping mustra up to date.
5. **Backups.** Keep backups of the server and of anything on your
   endpoints that you cannot afford to lose.
6. **Export controls and sanctions.** Comply with the export, import and
   sanctions laws that apply to you.

You must not use mustra to gain unauthorized access to systems, to
distribute malware, to monitor people unlawfully, or for any other
unlawful purpose.

## 5. Indemnity

To the extent the law allows, if you use mustra in breach of section 4 or
of the law and a claim is made against the mustra maintainers,
contributors or copyright holders as a result, you agree to defend them
and hold them harmless against that claim and its costs.

## 6. Third-party services and data

mustra can use data and services run by others. These include OSV,
Debian's security tracker, CISA's Known Exploited Vulnerabilities
catalogue, EPSS, endoflife.date, GitHub, Let's Encrypt, Cloudflare,
Microsoft, Google, package managers and the integrations you configure.
We do not control them and are not responsible for their availability,
accuracy or terms, which apply to your use of them. [PRIVACY.md](PRIVACY.md)
lists what mustra sends to them.

## 7. No support obligation

mustra is maintained by volunteers. Issues, email to support@mustra.dev and
security reports are handled on a best-effort basis, with no promised
response time or service level. Nothing in mustra's documentation creates
a support contract.

## 8. Contributions

Contributions are accepted under the AGPL, with a Developer Certificate of
Origin sign-off on every commit (see [CONTRIBUTING.md](CONTRIBUTING.md)).
By contributing you confirm that you have the right to submit your
contribution under that license.

## 9. Name and logo

The AGPL licenses the code, not the mustra name or logo. You may use the
name to refer to the project accurately, for example "built on mustra" or
"compatible with mustra". If you distribute a modified version, do not
present it as the official mustra or imply that the maintainers endorse
it.

## 10. Changes

We may update these terms. The version in the repository's default branch
applies from the date it is committed. Changes do not affect the license
under which you received any copy of mustra.

## 11. Contact

support@mustra.dev, or security@mustra.dev for security issues (see
[SECURITY.md](SECURITY.md)).
