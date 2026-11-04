# Privacy

## The software

mustra is self-hosted. **It sends nothing to the mustra maintainers.**
There is no telemetry, no usage statistics, no crash reporting and no
licence check. Everything mustra collects about your devices and their
users stays in your own server's database, under your control. See
[TERMS.md](TERMS.md), section 4, for your responsibilities as its
operator.

Your mustra server does contact other services. Agents only connect to
your own server.

**By default, to keep vulnerability and lifecycle data current:**

| Service | What is sent |
| --- | --- |
| [OSV](https://osv.dev) | Package names, ecosystems and versions found on your endpoints. Never hostnames, IP addresses, users or anything else about your fleet. |
| [endoflife.date](https://endoflife.date) | Names of the operating systems and products it looks up. |
| Debian security tracker, CISA KEV catalogue, EPSS, Wireshark's vendor list | Nothing beyond the download request. |

**Only if you set them up:**

| Feature | Service |
| --- | --- |
| Update check and packages that follow upstream releases | GitHub, for the repository you name |
| Certificates | Let's Encrypt, Cloudflare, or your Active Directory CA |
| Sign-in and provisioning | Your identity provider (OIDC, SAML, SCIM, LDAP) |
| MDM, cloud and backup integrations | The service you connect, such as Microsoft, Google, Fleet, Proxmox or Rubrik |
| Notifications and log forwarding | The webhook, chat service, email server, SIEM or syslog server you enter |
| Library packages | Package managers on your endpoints (winget, Homebrew, apt) |

Each of these services' own privacy terms apply to what it receives.

## The project

- **Email** to support@, security@ or conduct@mustra.dev is read by the
  maintainers and kept only as long as needed to deal with it. Mail for
  mustra.dev is routed by Cloudflare.
- **GitHub.** Issues, pull requests and discussions are public and are
  governed by GitHub's privacy statement. Leave out hostnames, IP
  addresses, usernames and credentials when you post.
- **mustra.dev** has no website yet. If it gets one, this notice will say
  what it collects before it collects anything.

Questions: support@mustra.dev.
