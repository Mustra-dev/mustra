package server

// Bodies two routes share: mostly a create and its update. Each of
// those updates replaces the whole record, so the shared body carries
// every field a person sets; pasted into the update, it blanks nothing
// and switches nothing off by surprise.
const (
	// The name is kept on an update: it is the attribute's key.
	assetAttributeExample = `{
		"name": "cost_centre",
		"label": "Cost centre",
		"kind": "select",
		"options": ["Engineering", "Finance", "Sales"],
		"description": "Which budget pays for the endpoint"
	}`

	// Approval "approve": a person confirms a renewal before anything is
	// written on the endpoint, and only then does the reload run.
	managedCertExample = `{
		"agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4",
		"names": ["www.example.com"],
		"cert_path": "/etc/nginx/ssl/www.example.com.crt",
		"key_path": "/etc/nginx/ssl/www.example.com.key",
		"reload_cmd": "systemctl reload nginx",
		"verify_port": 443,
		"ca": "private",
		"renew_days": 30,
		"approval": "approve",
		"enabled": true
	}`

	// A PFX to install (…/managed/{id}/upload) or to read first
	// (…/upload/preview).
	certUploadExample = `{"pfx": "<PFX file, base64>", "pfx_password": "<PFX password>"}`

	clientProfileExample = `{
		"name": "Web servers",
		"description": "Faster reporting for the web tier",
		"priority": 10,
		"group_ids": ["cgrp-1c8e4a2f6b9d43e7a5c0f2b8d6e4a1c3"],
		"settings": {"sensor_interval_seconds": 60, "log_level": "info", "random_delay_seconds": 30},
		"upgrade_ring": 2,
		"enabled": true
	}`

	exportConfigExample = `{
		"name": "Vulnerabilities to the SIEM",
		"source": "findings",
		"destination": "webhook",
		"format": "ndjson",
		"target": "https://siem.corp.example.com/ingest/mustra",
		"interval_minutes": 1440,
		"enabled": true
	}`

	contentSetExample = `{
		"name": "Service desk",
		"description": "What the service desk role may use",
		"contents": {
			"sensors": ["installed_apps", "services", "disks"],
			"packages": ["sw-7d3b9f1a5e2c48b6a0d4f8e2c6b1a9d5"],
			"dashboards": ["db-64d2472106baa7637afc9e7b7aec4f73"],
			"questions": ["sq-4739d2a01d7cbf3af69cb575c57fb394"]
		}
	}`

	dashboardAlertExample = `{
		"name": "Critical vulnerabilities on web servers",
		"dashboard_id": "db-64d2472106baa7637afc9e7b7aec4f73",
		"panel_id": "pn-d39dba1141c3f1330c20d7d5f8fe4406",
		"condition": {"op": "nonzero"},
		"severity": "high",
		"enabled": true
	}`

	deploymentTemplateExample = `{
		"name": "Staged install, no reboot",
		"description": "Pilot ring first, reboots suppressed, expires after a day",
		"is_default": false,
		"package_id": "sw-7d3b9f1a5e2c48b6a0d4f8e2c6b1a9d5",
		"operation": "install",
		"plan_id": "plan-aa84f3bbe99040d7d2c10d3c11ab9c32",
		"allow_reboot": false,
		"force_remove": false,
		"expire_seconds": 86400,
		"override_windows": false
	}`

	deploymentPlanExample = `{
		"name": "Pilot, then web servers",
		"kind": "custom",
		"rings": [
			{"name": "Pilot", "group_id": "cgrp-6ea76dc9c2fb40e65159fc3cbda2a266", "min_success": 3, "wait_minutes": 60},
			{"name": "Web servers", "group_id": "cgrp-1c8e4a2f6b9d43e7a5c0f2b8d6e4a1c3", "success_rate": 95}
		]
	}`

	eunMessageExample = `{
		"kind": "notice",
		"name": "Patch window notice",
		"title": "Updates tonight at 22:00 UTC",
		"body": "Your computer installs updates tonight between 22:00 and 23:00 UTC. Save your work before you leave.",
		"deadline_at": "2026-11-03T23:00:00Z",
		"buttons": [{"label": "Got it", "action": "acknowledged", "primary": true}]
	}`

	computerGroupExample = `{
		"name": "Web servers",
		"description": "Linux hosts running nginx",
		"kind": "dynamic",
		"match_mode": "all",
		"rules": [
			{"field": "os", "op": "equals", "value": "linux"},
			{"field": "services.name", "op": "equals", "value": "nginx"}
		]
	}`

	iocExample = `{
		"name": "Dropper from INC-2041",
		"kind": "file_hash",
		"value": "9f2c4e7a1b3d5f8e0a6c2b4d7e9f1a3c5b8d0e2f4a6c9b1d3e5f7a0c2e4b6d8f",
		"severity": "critical",
		"description": "Installer dropped by the phishing mail in INC-2041",
		"source": "INC-2041",
		"enabled": true
	}`

	signalExample = `{
		"name": "Cron or sudoers changed",
		"description": "A scheduled job or sudo rule written outside a change",
		"severity": "warning",
		"expression": "(file.path starts with '/etc/cron' OR file.path starts with '/etc/sudoers') AND file.op != 'remove'",
		"enabled": true
	}`

	integrityLabelExample = `{
		"name": "Package updates in a maintenance window",
		"expected": true,
		"criteria": {"path_prefix": "/usr/", "group_ids": ["cgrp-1c8e4a2f6b9d43e7a5c0f2b8d6e4a1c3"], "during_maintenance": true},
		"priority": 10,
		"enabled": true
	}`

	integrityMonitorExample = `{
		"name": "Web server configuration",
		"watchlist_id": "wl-8e3b1f7d2a6c49e0b5d1a9f3c7e2b4d6",
		"group_ids": ["cgrp-1c8e4a2f6b9d43e7a5c0f2b8d6e4a1c3"],
		"enabled": true
	}`

	jumpPolicyExample = `{
		"name": "Production servers need approval",
		"group_ids": ["cgrp-1c8e4a2f6b9d43e7a5c0f2b8d6e4a1c3"],
		"require_approval": true,
		"require_reason": true,
		"max_minutes": 60,
		"priority": 10,
		"enabled": true
	}`

	maintenanceWindowExample = `{
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
		"time_base": "zone",
		"observe_dst": true
	}`

	patchPolicyExample = `{
		"name": "Security updates after a week",
		"kind": "allow",
		"description": "Web servers take security updates once the fleet has seen them for seven days",
		"enabled": true,
		"group_ids": ["cgrp-1c8e4a2f6b9d43e7a5c0f2b8d6e4a1c3"],
		"rules": {"severities": ["security"], "os": ["linux"], "min_age_days": 7}
	}`

	// Deploy now and its preview take the same body.
	patchDeployExample = `{"target_agents": ["agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4", "agt-9b1d7e3a5c2f48d0a6e4b8c1f3d5a7e9"], "restart_mode": "none"}`

	// A webhook trigger fires only when its URL is called; its token is
	// returned once, when it is created.
	playbookTriggerExample = `{"playbook_id": "pb-61a3b2f60a1ace8deee382700533b5a5", "kind": "webhook", "enabled": true, "min_interval_seconds": 3600}`

	playbookExample = `{
		"name": "Weekly patching for web servers",
		"description": "Apply pending patches without restarting",
		"os": "linux",
		"group_id": "cgrp-1c8e4a2f6b9d43e7a5c0f2b8d6e4a1c3",
		"enabled": true,
		"steps": [{"name": "Apply pending patches", "kind": "patch", "on_failure": "stop"}],
		"schedule_kind": "weekly",
		"time_of_day": "22:00",
		"weekday": 2
	}`

	reportExample = `{
		"name": "Weekly patch summary",
		"description": "Missing patches across the fleet, for the Monday review",
		"sections": [
			{"title": "Missing patches by severity", "source": "patches", "group_by": "severity"},
			{"title": "Security updates outstanding", "source": "patches", "columns": ["hostname", "patch", "installed", "available"], "limit": 100, "filter_column": "severity", "filter_value": "security"}
		],
		"enabled": true,
		"schedule_kind": "weekly",
		"time_of_day": "07:00",
		"weekday": 1,
		"destination": "webhook",
		"target": "https://hooks.example.com/reports/patching",
		"webhook_style": "slack"
	}`

	revealRuleSetExample = `{
		"name": "PCI-DSS cardholder data",
		"rule_ids": ["rvl-3a7c1e9f5b2d48a6c0e4f8b2d6a1c9e3"],
		"regime": "PCI-DSS",
		"description": "Card numbers at rest on the payment servers",
		"group_ids": ["cgrp-1c8e4a2f6b9d43e7a5c0f2b8d6e4a1c3"],
		"enabled": true
	}`

	roleExample = `{
		"name": "Web server operators",
		"description": "Patch and deploy software on the web servers",
		"permissions": ["patches.manage", "deploy.manage"],
		"computer_group_ids": ["cgrp-1c8e4a2f6b9d43e7a5c0f2b8d6e4a1c3"],
		"content_set_ids": ["cs-6f2b8d4a0c7e41b9a3d5f1c8e2b6a4d0"]
	}`

	scheduleExample = `{
		"name": "Sunday update for web servers",
		"package_id": "sw-7d3b9f1a5e2c48b6a0d4f8e2c6b1a9d5",
		"operation": "update",
		"group_ids": ["cgrp-1c8e4a2f6b9d43e7a5c0f2b8d6e4a1c3"],
		"allow_reboot": false,
		"expire_seconds": 14400,
		"notify_on_finish": true,
		"kind": "weekly",
		"time_of_day": "03:00",
		"weekday": 0,
		"enabled": true
	}`

	// Saved disabled: a custom sensor has no targeting, so an enabled one
	// starts its command on every endpoint of its platforms at once.
	customSensorExample = `{
		"name": "Time sync service",
		"platforms": {
			"linux": {"output": {"format": "delimited", "delimiter": ","}},
			"windows": {"output": {"format": "json"}}
		},
		"fields": [{"name": "service", "type": "string"}, {"name": "state", "type": "string"}],
		"description": "Whether the clock-sync service is running",
		"commands": {
			"linux": "echo \"systemd-timesyncd,$(systemctl is-active systemd-timesyncd)\"",
			"windows": "[pscustomobject]@{service = 'W32Time'; state = [string](Get-Service W32Time).Status} | ConvertTo-Json"
		},
		"interval_seconds": 3600,
		"timeout_seconds": 30,
		"enabled": false
	}`

	softwarePackageExample = `{
		"name": "jq",
		"kind": "software",
		"version": "1.7.1",
		"description": "Command-line JSON processor",
		"category": "Utilities",
		"commands": {
			"linux": {"install": "apt-get install -y jq", "update": "apt-get install -y --only-upgrade jq"},
			"windows": {"install": "winget install --silent --accept-package-agreements --accept-source-agreements --id jqlang.jq", "update": "winget upgrade --silent --accept-package-agreements --accept-source-agreements --id jqlang.jq"}
		},
		"detect": {"app_name": "jq", "match": "exact"},
		"group_ids": ["cgrp-1c8e4a2f6b9d43e7a5c0f2b8d6e4a1c3"],
		"enabled": true,
		"command_timeout_seconds": 600,
		"expire_seconds": 86400
	}`

	surveyExample = `{
		"name": "Laptop refresh feedback",
		"title": "How is your new laptop?",
		"intro": "Three questions, two minutes. Your answers are anonymous.",
		"questions": [
			{"id": "overall", "kind": "rating", "text": "How happy are you with the new laptop?", "required": true},
			{"id": "speed", "kind": "choice", "text": "Compared with your old one, it is", "options": ["Faster", "About the same", "Slower"], "positive": ["Faster", "About the same"]},
			{"id": "comments", "kind": "text", "text": "Anything we should fix?"}
		],
		"anonymous": true,
		"deadline_at": "2026-11-03T22:00:00Z"
	}`

	trackedProductExample = `{
		"product_key": "example diagram studio",
		"name": "Example Diagram Studio",
		"vendor": "Example Software",
		"executables": ["diagramstudio"],
		"cost_per_seat_cents": 1500,
		"currency": "USD",
		"package_id": "sw-7d3b9f1a5e2c48b6a0d4f8e2c6b1a9d5",
		"notes": "Licensed per seat; renews in March"
	}`

	watchlistExample = `{
		"name": "Web server configuration",
		"description": "nginx and IIS configuration on the web tier",
		"paths": ["/etc/nginx", "C:\\inetpub\\wwwroot\\web.config"],
		"registry_keys": ["HKLM\\SYSTEM\\CurrentControlSet\\Services\\W3SVC"],
		"follow_symlinks": false
	}`
)

// bodyExamples are request bodies to start from, one per route that takes
// a JSON body (but for the server-wide settings the test's noBodyExample
// lists), keyed like routeDocs. The spec gives each as its body's example
// and the API reference's builder fills the body in with it. A test holds
// every example to its route's type and schema: it decodes with no
// unknown field, has every required field, sends nothing the server
// sets, and puts a <placeholder> where a secret goes.
var bodyExamples = map[string]string{
	// action-groups
	"POST /api/action-groups": `{"module": "deploy", "group_ids": ["cgrp-1c8e4a2f6b9d43e7a5c0f2b8d6e4a1c3"], "enabled": true}`,

	// agents
	"POST /api/agents/{id}/apply-patches": `{"override_windows": false, "restart_mode": "none"}`,
	"PUT /api/agents/{id}/attributes": `{
		"attr-3a7c9e1b5d2f48a6c0e4b8d2f6a1c9e3": "jdoe@example.com",
		"attr-5e9c1a7d3b2f46e8a0c4d6b8f2e1a3c7": "Finance"
	}`,
	"POST /api/agents/{id}/kill-process":    `{"pid": 48213, "name": "xmrig"}`,
	"POST /api/agents/{id}/managed":         `{"managed": false, "reason": "Decommissioned; replaced by web-02"}`,
	"POST /api/agents/{id}/sensor-interval": `{"sensor": "processes", "interval_seconds": 300}`,

	// approval-policies
	"POST /api/approval-policies": `{
		"name": "Approve deployments to 25 or more web servers",
		"module": "deploy",
		"group_ids": ["cgrp-1c8e4a2f6b9d43e7a5c0f2b8d6e4a1c3"],
		"min_devices": 25
	}`,
	"PUT /api/approval-policies/{id}": `{
		"name": "Approve deployments to 25 or more web servers",
		"module": "deploy",
		"group_ids": ["cgrp-1c8e4a2f6b9d43e7a5c0f2b8d6e4a1c3"],
		"min_devices": 25,
		"enabled": true
	}`,

	// approvals
	"POST /api/approvals/{id}/decide": `{"decision": "approve", "note": "Matches change ticket CHG-1187"}`,

	// asset-attributes
	"POST /api/asset-attributes":     assetAttributeExample,
	"PUT /api/asset-attributes/{id}": assetAttributeExample,

	// backups
	"POST /api/backups": `{"note": "Before upgrading the server", "include_package_files": false}`,

	// catalog
	"POST /api/catalog/requests/{id}/decide": `{"status": "approved"}`,

	// certificates
	"POST /api/certificates/apps/connections": `{
		"kind": "entra",
		"name": "Entra ID production",
		"config": {"tenant_id": "8d3f1a6e-4b2c-4e7a-9f05-c1d8e2b7a4f3", "client_id": "5b9e2c7a-1d4f-4a8e-b6c3-0f7d2e9a1b5c"},
		"secret": "<client secret>"
	}`,
	"PUT /api/certificates/apps/connections/{id}": `{
		"name": "Entra ID production",
		"config": {"tenant_id": "8d3f1a6e-4b2c-4e7a-9f05-c1d8e2b7a4f3", "client_id": "5b9e2c7a-1d4f-4a8e-b6c3-0f7d2e9a1b5c"}
	}`,
	"POST /api/certificates/apps/credentials": `{
		"cred_type": "client_secret",
		"app_name": "Payroll SSO",
		"display_name": "Client secret of the Payroll app registration",
		"expires_at": "2027-03-31T00:00:00Z",
		"renew_days": 30,
		"mode": "remind"
	}`,
	"PUT /api/certificates/apps/credentials/{id}": `{
		"display_name": "Client secret of the Payroll app registration",
		"expires_at": "2027-03-31T00:00:00Z",
		"rotate_days": 0,
		"renew_days": 30,
		"mode": "remind",
		"grace_days": 7
	}`,
	"POST /api/certificates/issued/{id}/revoke":  `{"reason": "superseded", "replace": true}`,
	"POST /api/certificates/managed":             managedCertExample,
	"PUT /api/certificates/managed/{id}":         managedCertExample,
	"POST /api/certificates/managed/{id}/upload": certUploadExample,
	"POST /api/certificates/trust/{id}":          `{"mode": "off"}`,
	"POST /api/certificates/upload/preview":      certUploadExample,

	// clients
	"POST /api/clients/profiles":     clientProfileExample,
	"PUT /api/clients/profiles/{id}": clientProfileExample,

	// compliance
	"POST /api/compliance/exceptions": `{
		"title": "Ensure separate partition exists for /var/log",
		"reason": "Needs a reinstall; planned with the hardware refresh in CHG-1187",
		"group_id": "cgrp-1c8e4a2f6b9d43e7a5c0f2b8d6e4a1c3",
		"expires": "2027-03-31"
	}`,
	"POST /api/compliance/scan": `{"agent_ids": ["agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4"]}`,

	// connect
	"POST /api/connect/exports":     exportConfigExample,
	"PUT /api/connect/exports/{id}": exportConfigExample,

	// content-sets
	"POST /api/content-sets":     contentSetExample,
	"PUT /api/content-sets/{id}": contentSetExample,

	// dashboard-alerts
	"POST /api/dashboard-alerts":     dashboardAlertExample,
	"PUT /api/dashboard-alerts/{id}": dashboardAlertExample,

	// dashboards
	"POST /api/dashboards": `{
		"name": "Web tier posture",
		"description": "Platforms and open vulnerabilities on the web servers",
		"shared": true,
		"panels": [
			{"title": "Web servers by platform", "source": "endpoints", "group_by": "platform", "chart": "donut", "group_ids": ["cgrp-1c8e4a2f6b9d43e7a5c0f2b8d6e4a1c3"]},
			{"title": "Critical vulnerabilities", "source": "findings", "filter_column": "severity", "filter_value": "critical", "chart": "number", "group_ids": ["cgrp-1c8e4a2f6b9d43e7a5c0f2b8d6e4a1c3"], "highlight": {"op": "nonzero"}}
		]
	}`,
	"POST /api/dashboards/preview": `{
		"title": "Web servers by platform",
		"source": "endpoints",
		"group_by": "platform",
		"chart": "donut",
		"group_ids": ["cgrp-1c8e4a2f6b9d43e7a5c0f2b8d6e4a1c3"]
	}`,
	// The panels keep their ids: a panel saved without one gets a new id,
	// which detaches its alerts and history.
	"PUT /api/dashboards/{id}": `{
		"name": "Web tier posture",
		"description": "Platforms and open vulnerabilities on the web servers",
		"shared": true,
		"panels": [
			{"id": "pn-ff888df99f1c427a9cfa7bd1fde8e70f", "title": "Web servers by platform", "source": "endpoints", "group_by": "platform", "chart": "donut", "group_ids": ["cgrp-1c8e4a2f6b9d43e7a5c0f2b8d6e4a1c3"]},
			{"id": "pn-d39dba1141c3f1330c20d7d5f8fe4406", "title": "Critical vulnerabilities", "source": "findings", "filter_column": "severity", "filter_value": "critical", "chart": "number", "group_ids": ["cgrp-1c8e4a2f6b9d43e7a5c0f2b8d6e4a1c3"], "highlight": {"op": "nonzero"}}
		]
	}`,

	// deploy
	"POST /api/deploy/credentials":       `{"name": "Linux deploy key", "username": "mustra-deploy", "auth_type": "private_key", "secret": "<PEM private key>"}`,
	"POST /api/deploy/jobs/{job}/cancel": `{"force": false}`,
	// Every detail is sent: one left out is cleared, not kept.
	"PUT /api/deploy/packages/{id}": `{
		"name": "Log shipper",
		"vendor": "Example Corp",
		"description": "Forwards nginx and system logs to the central collector",
		"category": "Monitoring",
		"group_ids": ["cgrp-1c8e4a2f6b9d43e7a5c0f2b8d6e4a1c3"],
		"self_service": false,
		"allow_requests": false,
		"self_service_revision": "",
		"self_service_follow_latest": false,
		"enabled": true,
		"expire_seconds": 86400
	}`,
	"POST /api/deploy/packages/{id}/import": `{
		"url": "https://downloads.example.com/log-shipper/log-shipper_2.4.1_amd64.deb",
		"name": "log-shipper_2.4.1_amd64.deb",
		"sha256": "1e6bd13666a86b48563bb9db9643994c965b748ba927eb3339b051d011c24367"
	}`,
	// A draft of an action package, whose one step only reads. The name
	// counts only when the path's id is "new", which creates the package;
	// an existing package must be an action package too, since a revision
	// cannot change its kind.
	"POST /api/deploy/packages/{id}/revisions": `{
		"name": "Nginx status",
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
		}
	}`,
	"POST /api/deploy/preview": `{"package_id": "sw-7d3b9f1a5e2c48b6a0d4f8e2c6b1a9d5", "operation": "install", "group_ids": ["cgrp-1c8e4a2f6b9d43e7a5c0f2b8d6e4a1c3"]}`,
	"POST /api/deploy/push": `{
		"target": "192.0.2.23",
		"credential_id": "cred-ec987fc368dc0f4a5cc17d6a3bbfd96b",
		"hostname": "web-03.corp.example.com",
		"site": "hq"
	}`,
	"POST /api/deploy/revisions/{revision}/publish": `{"retire_previous": true}`,
	"POST /api/deploy/revisions/{revision}/references": `{
		"replacement": "rev-8c59c2e37d2fd48f5fd97dc1900ce3dc",
		"references": {
			"schedule:sch-eaca5eca33f5a9e8420c80fc77001e80": "2974153195a89e3370d6fb882a7fe1109ef8a4028507a61772e66de7cc902aac",
			"playbook:pb-a2ee726f006fe7786489587cb1760e68:0": "155d3efdbeebf718758259142d5b88d1a22787cc6280079ce8ca1dd3319024f0"
		}
	}`,
	"POST /api/deploy/revisions/{revision}/retire": `{"entire_package": false, "note": "Superseded by 2.4.1"}`,
	"POST /api/deploy/run": `{
		"package_id": "sw-7d3b9f1a5e2c48b6a0d4f8e2c6b1a9d5",
		"operation": "install",
		"plan_id": "plan-aa84f3bbe99040d7d2c10d3c11ab9c32",
		"expire_seconds": 86400,
		"group_ids": ["cgrp-1c8e4a2f6b9d43e7a5c0f2b8d6e4a1c3"],
		"notify_on_finish": true
	}`,
	"POST /api/deploy/scan":          `{"cidr": "192.0.2.0/24"}`,
	"POST /api/deploy/templates":     deploymentTemplateExample,
	"PUT /api/deploy/templates/{id}": deploymentTemplateExample,
	// A draft is tested on exactly one endpoint, named.
	"POST /api/deploy/test": `{
		"package_id": "sw-7d3b9f1a5e2c48b6a0d4f8e2c6b1a9d5",
		"operation": "install",
		"revision_id": "rev-4d8381cf716ba31cc205ee77a6f67eb1",
		"agent_ids": ["agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4"]
	}`,

	// deployment-plans
	"POST /api/deployment-plans":     deploymentPlanExample,
	"PUT /api/deployment-plans/{id}": deploymentPlanExample,

	// directory
	"POST /api/directory/test": `{
		"url": "ldap://dc01.corp.example.com",
		"bind_dn": "CN=svc-mustra,OU=Service Accounts,DC=corp,DC=example,DC=com",
		"bind_password": "<bind account password>",
		"base_dn": "DC=corp,DC=example,DC=com",
		"starttls": true
	}`,

	// discover
	"PUT /api/discover/devices/{mac}": `{"label": "Lobby printer", "ignored": false}`,

	// enforce
	"POST /api/enforce/compile": `{
		"kind": "defender",
		"config": {
			"realtime": true,
			"cloud_level": "advanced",
			"pua": "block",
			"signature_max_age_hours": 48,
			"daily_quick_scan": true,
			"check_tamper_protection": true
		}
	}`,
	"POST /api/enforce/policies": `{
		"name": "Time sync on web servers",
		"description": "chronyd keeps the clock right on every web server",
		"os": "linux",
		"group_id": "cgrp-1c8e4a2f6b9d43e7a5c0f2b8d6e4a1c3",
		"mode": "report",
		"enabled": true,
		"settings": [
			{
				"name": "chronyd is running",
				"severity": "medium",
				"rules": ["p:chronyd"],
				"remediate_linux": "systemctl start chronyd"
			}
		]
	}`,
	"PUT /api/enforce/policies/{id}": `{
		"name": "Time sync on web servers",
		"description": "chronyd keeps the clock right on every web server",
		"os": "linux",
		"group_id": "cgrp-1c8e4a2f6b9d43e7a5c0f2b8d6e4a1c3",
		"mode": "report",
		"enabled": true,
		"settings": [
			{
				"id": "set-6b1e9d3a7c2f48e5a0d4b8c2f6e1a9d3",
				"name": "chronyd is running",
				"severity": "medium",
				"rules": ["p:chronyd"],
				"remediate_linux": "systemctl start chronyd"
			}
		]
	}`,
	"POST /api/enforce/policies/{id}/run": `{"dry_run": true}`,

	// enrollment-tokens
	"POST /api/enrollment-tokens": `{"label": "Web servers, rack B", "site": "dc-east", "max_uses": 10, "expires_hours": 24}`,

	// eun
	"POST /api/eun":           eunMessageExample,
	"PUT /api/eun/{id}":       eunMessageExample,
	"POST /api/eun/{id}/send": `{"agent_ids": ["agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4", "agt-9b1d7e3a5c2f48d0a6e4b8c1f3d5a7e9"]}`,

	// groups
	"POST /api/admin/groups":              `{"display_name": "Helpdesk"}`,
	"POST /api/admin/groups/{id}/members": `{"user_id": "usr-2e6a0c4f8b1d47e3a9c5f1b7d3e0a8c6"}`,
	"POST /api/admin/groups/{id}/roles":   `{"role_id": "role-user"}`,
	"POST /api/groups":                    computerGroupExample,
	"POST /api/groups/preview": `{
		"match_mode": "all",
		"rules": [
			{"field": "os", "op": "equals", "value": "linux"},
			{"field": "services.name", "op": "equals", "value": "nginx"}
		]
	}`,
	"PUT /api/groups/{id}": computerGroupExample,

	// hunt
	"POST /api/hunt/findings/{id}/ack":        `{"acknowledged": true}`,
	"POST /api/hunt/iocs":                     iocExample,
	"PUT /api/hunt/iocs/{id}":                 iocExample,
	"POST /api/hunt/signal-findings/{id}/ack": `{"acknowledged": true}`,
	"POST /api/hunt/signals":                  signalExample,
	"POST /api/hunt/signals/test":             `{"expression": "(file.path starts with '/etc/cron' OR file.path starts with '/etc/sudoers') AND file.op != 'remove'"}`,
	"PUT /api/hunt/signals/{id}":              signalExample,

	// integrations
	"POST /api/admin/mail-test": `{"to": "you@example.com"}`,
	"POST /api/admin/integrations": `{
		"kind": "webhook",
		"name": "SOC webhook",
		"enabled": true,
		"config": {"url": "https://hooks.example.com/mustra"},
		"events": ["alert", "audit"],
		"min_severity": "warning"
	}`,
	"PUT /api/admin/integrations/{id}": `{
		"kind": "webhook",
		"name": "SOC webhook",
		"enabled": true,
		"config": {"url": "https://hooks.example.com/mustra"},
		"events": ["alert", "audit"],
		"min_severity": "warning"
	}`,

	// integrity
	"POST /api/integrity/labels":       integrityLabelExample,
	"POST /api/integrity/labels/test":  `{"criteria": {"path_prefix": "/usr/", "group_ids": ["cgrp-1c8e4a2f6b9d43e7a5c0f2b8d6e4a1c3"], "during_maintenance": true}}`,
	"PUT /api/integrity/labels/{id}":   integrityLabelExample,
	"POST /api/integrity/monitors":     integrityMonitorExample,
	"PUT /api/integrity/monitors/{id}": integrityMonitorExample,

	// interact
	"POST /api/interact/ask": `{
		"get": ["platform_version"],
		"where": [{"field": "os", "op": "equals", "value": "linux"}, {"field": "services.name", "op": "equals", "value": "nginx"}],
		"match_all": true
	}`,
	"POST /api/interact/saved": `{
		"name": "Web servers by OS version",
		"description": "Linux endpoints running nginx, counted by OS version",
		"get": ["platform_version"],
		"where": [{"field": "os", "op": "equals", "value": "linux"}, {"field": "services.name", "op": "equals", "value": "nginx"}],
		"match_all": true
	}`,

	// jump
	"POST /api/jump/grants/{id}/decide": `{"decision": "approve", "note": "Approved for INC-2041", "minutes": 30}`,
	"POST /api/jump/policies":           jumpPolicyExample,
	"PUT /api/jump/policies/{id}":       jumpPolicyExample,
	"POST /api/jump/requests":           `{"agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4", "reason": "Investigating high CPU on INC-2041"}`,

	// maintenance-windows
	"POST /api/maintenance-windows":       maintenanceWindowExample,
	"POST /api/maintenance-windows/check": `{"agent_ids": ["agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4", "agt-9b1d7e3a5c2f48d0a6e4b8c1f3d5a7e9"], "kind": "patch"}`,
	"PUT /api/maintenance-windows/{id}":   maintenanceWindowExample,

	// oidc-providers
	// Created disabled: its sign-in button appears only once it is enabled
	// (…/{id}/enabled), after the secret and URLs are real.
	"POST /api/admin/oidc-providers": `{
		"id": "corp-sso",
		"label": "Sign in with Corp SSO",
		"kind": "keycloak",
		"issuer_url": "https://sso.corp.example.com/realms/corp",
		"client_id": "mustra",
		"client_secret": "<client secret>",
		"redirect_url": "https://mustra.corp.example.com/auth/callback/corp-sso",
		"enabled": false,
		"sort_order": 10
	}`,
	// The id is the path's, and a secret left out keeps the stored one.
	"PUT /api/admin/oidc-providers/{id}": `{
		"label": "Sign in with Corp SSO",
		"kind": "keycloak",
		"issuer_url": "https://sso.corp.example.com/realms/corp",
		"client_id": "mustra",
		"redirect_url": "https://mustra.corp.example.com/auth/callback/corp-sso",
		"enabled": true,
		"sort_order": 10
	}`,
	"POST /api/admin/oidc-providers/{id}/enabled": `{"enabled": true}`,

	// patch-policies
	// A Proxmox Backup Server read with a read-only API token, its
	// self-signed certificate pinned. The secret is a placeholder.
	"POST /api/backup-sources": `{
		"kind": "pbs",
		"name": "Backup server",
		"url": "https://pbs.corp.example.com:8007",
		"token_id": "mustra@pbs!status",
		"secret": "<token secret>",
		"fingerprint": "24:c9:ca:cb:c2:11:c8:77:2d:bb:a0:28:9d:47:a1:b2:c3:d4:e5:f6:07:18:29:3a:4b:5c:6d:7e:8f:90:12:34"
	}`,
	// Renamed; the secret stays as stored because the URL, token and
	// fingerprint do not change.
	"PUT /api/backup-sources/{id}": `{
		"name": "Backup server (local)",
		"url": "https://pbs.corp.example.com:8007",
		"token_id": "mustra@pbs!status",
		"fingerprint": "24:c9:ca:cb:c2:11:c8:77:2d:bb:a0:28:9d:47:a1:b2:c3:d4:e5:f6:07:18:29:3a:4b:5c:6d:7e:8f:90:12:34"
	}`,
	// A briefing written for two CVEs: how to find PHP on an endpoint and
	// a question to hunt with.
	"POST /api/threats":        threatBriefBodyExample,
	"PUT /api/threats/{id}":    threatBriefBodyExample,
	"POST /api/patch-policies": patchPolicyExample,
	// Imported paused, so nothing changes until someone enables it. A
	// group named here that this mustra lacks refuses the whole import.
	"POST /api/patch-policies/import": `{
		"patch_lists": [{
			"name": "Hold kernel updates",
			"kind": "block",
			"description": "Keep kernel updates back on the web servers",
			"enabled": false,
			"groups": ["Web servers"],
			"rules": {"os": ["linux"], "name_patterns": ["linux-image-*"]}
		}]
	}`,
	"PUT /api/patch-policies/{id}": patchPolicyExample,

	// patches
	"POST /api/patches/deploy":           patchDeployExample,
	"POST /api/patches/deploy/preview":   patchDeployExample,
	"POST /api/patches/list-assignments": `{"patch_list_id": "plist-3a7e1c9b5d2f48a6b0e4c8d2f6a1b3e5", "target_agent": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4"}`,
	"POST /api/patches/lists": `{
		"name": "Debian internal mirror",
		"os_family": "apt",
		"repos": "deb https://mirror.corp.example.com/debian bookworm main\ndeb https://mirror.corp.example.com/debian-security bookworm-security main",
		"description": "Scan and patch from the internal mirror only"
	}`,
	"POST /api/patches/rescan": `{"agent_ids": ["agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4", "agt-9b1d7e3a5c2f48d0a6e4b8c1f3d5a7e9"]}`,
	"POST /api/patches/schedules": `{
		"name": "Weekly patching for web servers",
		"target_agents": ["agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4", "agt-9b1d7e3a5c2f48d0a6e4b8c1f3d5a7e9"],
		"kind": "weekly",
		"time_of_day": "22:00",
		"weekday": 2
	}`,
	"POST /api/patches/schedules/{id}/enabled": `{"enabled": false}`,

	// playbook-approvals
	"POST /api/playbook-approvals/{id}": `{"approve": true, "note": "Canary endpoints are healthy; continue the rollout"}`,

	// playbook-triggers
	"POST /api/playbook-triggers":     playbookTriggerExample,
	"PUT /api/playbook-triggers/{id}": playbookTriggerExample,

	// playbooks
	"POST /api/playbooks":     playbookExample,
	"PUT /api/playbooks/{id}": playbookExample,

	// query
	"POST /api/query": `{"kind": "services", "agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4"}`,

	// remote
	"POST /api/remote/sessions": `{"agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4", "protocol": "ssh", "reason": "Investigating high CPU on INC-2041"}`,

	// reports
	"POST /api/reports":     reportExample,
	"PUT /api/reports/{id}": reportExample,

	// reveal
	"POST /api/reveal/rule-sets":     revealRuleSetExample,
	"PUT /api/reveal/rule-sets/{id}": revealRuleSetExample,
	"POST /api/reveal/rules": `{
		"name": "Payment cards on finance shares",
		"description": "Card numbers in exports on the finance file servers",
		"enabled": true,
		"group_ids": ["cgrp-1c8e4a2f6b9d43e7a5c0f2b8d6e4a1c3"],
		"roots": {"linux": ["/srv/finance"], "windows": ["D:\\Finance"]},
		"exclude": ["archive"],
		"extensions": ["csv", "txt"],
		"modified_within_days": 90,
		"pattern_ids": ["credit_card"],
		"min_matches": 3,
		"interval_hours": 24,
		"snippets": false
	}`,
	"POST /api/reveal/rules/{id}/run": `{"agent_ids": ["agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4"]}`,
	"POST /api/reveal/search": `{
		"query": "syslog-old.corp.example.com",
		"agent_ids": ["agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4"],
		"roots": ["/etc"],
		"extensions": ["conf"],
		"max_size_mb": 1
	}`,

	// risk
	"POST /api/risk/criticality": `{"level": "critical", "agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4"}`,

	// roles
	"POST /api/admin/roles":     roleExample,
	"PUT /api/admin/roles/{id}": roleExample,

	// schedules
	"POST /api/schedules":     scheduleExample,
	"PUT /api/schedules/{id}": scheduleExample,

	// sensors
	"POST /api/sensors/custom": customSensorExample,
	"POST /api/sensors/custom/complete": `{
		"platform": "linux",
		"session": "9c2e4f1a-3b7d5e08-c6a1f3d9-2e8b4c70",
		"language": "shell",
		"script": "systemctl is-act",
		"position": {"line": 0, "character": 16}
	}`,
	"POST /api/sensors/custom/parse": `{
		"raw": "systemd-timesyncd,active\n",
		"output": {"format": "delimited", "delimiter": ","},
		"fields": [{"name": "service", "type": "string"}, {"name": "state", "type": "string"}]
	}`,
	"POST /api/sensors/custom/test": `{
		"agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4",
		"sensor": {
			"platforms": {"linux": {"output": {"format": "delimited", "delimiter": ","}}},
			"fields": [{"name": "service", "type": "string"}, {"name": "state", "type": "string"}],
			"name": "Time sync service",
			"commands": {"linux": "echo \"systemd-timesyncd,$(systemctl is-active systemd-timesyncd)\""},
			"timeout_seconds": 30
		}
	}`,
	"POST /api/sensors/custom/validate": `{
		"commands": {"linux": "echo \"systemd-timesyncd,$(systemctl is-active systemd-timesyncd)\""},
		"platforms": {"linux": {"language": "shell", "output": {"format": "delimited", "delimiter": ","}}}
	}`,
	"PUT /api/sensors/custom/{id}": customSensorExample,

	// shell
	"POST /api/shell/sessions":           `{"agent_id": "agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4", "reason": "Collect the nginx error log for INC-2041"}`,
	"POST /api/shell/sessions/{id}/exec": `{"command": "tail -n 50 /var/log/nginx/error.log"}`,

	// software
	"POST /api/software":       softwarePackageExample,
	"POST /api/software/adopt": `{"name": "jq", "version": "1.7.1", "platforms": ["linux"]}`,
	"POST /api/software/deploy": `{
		"package_id": "sw-7d3b9f1a5e2c48b6a0d4f8e2c6b1a9d5",
		"operation": "install",
		"agent_ids": ["agt-4f2a9c1e7b3d48e6a05c9d2f81b7e3a4", "agt-9b1d7e3a5c2f48d0a6e4b8c1f3d5a7e9"]
	}`,
	"PUT /api/software/{id}": softwarePackageExample,

	// software-inventory
	"POST /api/software-inventory/product/{key}/remove-unused": `{"unused_days": 90, "dry_run": true}`,

	// surveys
	"POST /api/surveys": surveyExample,
	// The laptop survey again, to one of the workstations it went to.
	"POST /api/surveys/{id}/send": `{"agent_ids": ["agt-9b1d7e3a5c2f48d0a6e4b8c1f3d5a7e9"]}`,
	"PUT /api/surveys/{id}":       surveyExample,

	// tokens
	"POST /api/admin/tokens":     `{"name": "SIEM session transcript export", "permissions": ["sessions.audit"], "expires_days": 90}`,
	"PUT /api/admin/tokens/{id}": `{"name": "SIEM session transcript export", "permissions": ["sessions.audit", "alerts.triage"], "approval_exempt": false}`,

	// tracked-products
	"POST /api/tracked-products":     trackedProductExample,
	"PUT /api/tracked-products/{id}": trackedProductExample,

	// users
	// The placeholder is shorter than the 12 characters a password needs,
	// so sent as written it creates nobody: it is not a password anyone
	// reading the spec could sign in with.
	"POST /api/admin/users":             `{"username": "jdoe", "password": "<password>", "display_name": "Jane Doe"}`,
	"POST /api/admin/users/{id}/active": `{"active": false}`,
	"POST /api/admin/users/{id}/admin":  `{"is_admin": false}`,
	"POST /api/admin/users/{id}/roles":  `{"role_id": "role-5e1b9d3f7a2c46e8b0d4a6c2e8f1b3d7"}`,

	// mfa: a placeholder where the authenticator's current code goes, so
	// sent as written each is refused as a wrong code.
	"POST /api/me/mfa/enable":         `{"code": "<6-digit code>"}`,
	"POST /api/me/mfa/recovery-codes": `{"code": "<6-digit code>"}`,
	"POST /api/me/mfa/disable":        `{"code": "<6-digit code>"}`,

	// watchlists
	"POST /api/watchlists":     watchlistExample,
	"PUT /api/watchlists/{id}": watchlistExample,
}

const threatBriefBodyExample = `{
	"title": "PHP2Shell: CVE-2026-109618 and CVE-2026-109619",
	"cves": ["CVE-2026-109618", "CVE-2026-109619"],
	"summary": "Two critical PHP flaws let an unauthenticated request run code on a web server.",
	"mitigation": "Update PHP to 8.5.12, 8.4.27, 8.3.36 or 8.2.35.",
	"refs": [{"label": "PHP.net advisory", "url": "https://www.php.net/ChangeLog-8.php"}],
	"rule": {"label": "PHP", "apps": ["php[0-9.]*(-cli|-fpm|-common)?"], "processes": ["php-fpm"]},
	"questions": ["get hostname and processes.name from all machines with processes.name contains php"]
}`
