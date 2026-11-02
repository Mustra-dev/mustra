# Integrations

Administration → Integrations shows every outside system Mustra connects to,
per category, with a link to where each is configured, and manages the
integrations Mustra pushes to.

| Category | Integration | Configured in |
| --- | --- | --- |
| Identity | OIDC single sign-on (Entra ID, Okta, Authentik, Google…), SCIM provisioning, Active Directory over LDAP (Impact) | Administration → Single Sign-On / SCIM / Directory |
| MDM | Fleet: macOS updates on Apple Silicon ([MACOS-UPDATES.md](MACOS-UPDATES.md)), enrollment offered to Macs | Administration → macOS MDM |
| Remote access | Guacamole, BeyondTrust, custom URL ([REMOTE-ACCESS.md](REMOTE-ACCESS.md)) | Access → Jump Gate |
| Certificates | Mustra Private CA, Let's Encrypt over Cloudflare DNS, Cloudflare Origin CA | Certificates → Certificate authorities |
| Exports and logs | Connect scheduled exports (webhook, file, syslog; JSON, CSV, CEF); audit log to syslog | Connect; Logging |
| **Event streaming** | Webhook, Slack, Microsoft Teams, Discord, Splunk HEC, Grafana Loki, ServiceNow | Integrations |
| **Metrics** | Prometheus (`/metrics`), for Grafana | Integrations |

## Event streaming

Every **alert** (a console notification: a failed patch run, a certificate
renewal, an approval waiting) and, when chosen, every **audit event** is
delivered as it happens to each enabled integration subscribed to its type at
or above its minimum severity. Delivery runs off a queue and never slows the
action that raised the event; a full queue drops events and counts them
(`mustra_integration_events_dropped`).

| Type | Sends | Secret |
| --- | --- | --- |
| Webhook | The event as JSON | Optional; signs the body: `X-Mustra-Signature: sha256=<HMAC-SHA256 hex>` |
| Slack | A message | — (the webhook URL is the credential) |
| Microsoft Teams | An Adaptive Card to a Workflows webhook | — |
| Discord | A message | — |
| Splunk | HEC event, `sourcetype` `mustra:alert` or `mustra:audit`, optional index | HEC token |
| Grafana Loki | A log line, labels `job="mustra"`, `type`, `severity` | Optional `user:password` (Basic) or bearer token |
| ServiceNow | An incident through the Table API, urgency from severity, optional assignment group | `user:password` (the itil role) |

Each integration has a **Test** button and shows its last delivery. Changing
integrations needs an administrator; secrets are sealed in the credential vault.

## Prometheus and Grafana

Add a **Prometheus** integration with a long random token
(`openssl rand -hex 24`), then a scrape job:

```yaml
- job_name: mustra
  scheme: https
  metrics_path: /metrics
  authorization:
    type: Bearer
    credentials_file: /etc/prometheus/mustra.token
  static_configs:
    - targets: ['mustra.example.com']
```

Metrics: `mustra_build_info`, `mustra_agents{os,online}`,
`mustra_agent_versions{version}`, `mustra_patches_pending`,
`mustra_endpoints_with_pending_patches`, `mustra_patch_jobs_open`,
`mustra_sensor_reporting{sensor}`, `mustra_sensor_stale{sensor}`,
`mustra_managed_certificate_expiry_timestamp_seconds{name,host,state}`,
`mustra_backup_age_hours{guest,vmid,node,endpoint}`,
`mustra_backup_guests{state}`, `mustra_network_devices`,
`mustra_network_devices_unmanaged`, `mustra_network_devices_new`,
`mustra_trusted_root_endpoints{root,state}`,
`mustra_integration_events_dropped`.

### Ready-made dashboard

[`deploy/grafana/mustra-overview.json`](../deploy/grafana/mustra-overview.json)
is a fleet overview: endpoints online and offline, the patch backlog,
overdue backups, unmanaged and new network devices, each guest's backup
age, certificate days left, trusted-root rollout, agent versions, stale
sensors, and (with the Loki integration) events by type and a live feed of
alerts and notable audit events. It picks its Prometheus and Loki data
sources from two drop-downs, so it imports into any Grafana: Dashboards →
New → Import → upload the file. With file provisioning, copy it into the
provider's dashboards directory instead.
