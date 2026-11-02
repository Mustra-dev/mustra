package auth

// Permission keys gate the admin-facing features: settings, user/group/role
// management, patch management, and agent deployment (credential
// vault/scan/push). Every other authenticated route (the endpoint list,
// live queries, cached sensor reads) is open to any logged-in user — these
// four are the ones with real blast radius if misused.
const (
	PermSettingsManage = "settings.manage"
	PermUsersManage    = "users.manage"
	PermPatchesManage  = "patches.manage"
	// PermGroupsManage covers creating and editing computer groups — the
	// reusable fleet slices that patch deployments and the software catalog
	// target. Reading them is open to any signed-in user, since a group is
	// just a saved view of inventory.
	PermGroupsManage = "groups.manage"

	PermDeployManage = "deploy.manage"

	// PermDeployOverride lets a deployment run outside maintenance windows.
	// Separate from deploy.manage on purpose: the person who may deploy is
	// not always the person who may deploy at two in the afternoon.
	PermDeployOverride = "deploy.override_windows"

	// PermRecoveryKeys lets a user read an escrowed BitLocker recovery
	// password. Separate from everything else because it unlocks a disk,
	// and every read is audited.
	PermRecoveryKeys = "enforce.recovery_keys"

	// PermApprovalsDecide lets a user approve or deny somebody else's
	// parked operation. Deliberately its own permission and never granted
	// by holding deploy.manage: an approval whose only requirement is
	// being allowed to do the thing yourself is not an approval.
	PermApprovalsDecide = "approvals.decide"

	// PermSessionsAudit lets a user read Direct Connect transcripts
	// without being able to open a session. That separation is the point:
	// the person who reviews what was run on an endpoint should not need
	// the ability to run things on it.
	PermSessionsAudit = "sessions.audit"

	// PermJumpApprove lets a user grant somebody else time-boxed access to
	// an endpoint. Separate from deploy.manage for the same reason
	// approvals.decide is: being allowed in yourself is not a reason to
	// decide who else gets in.
	PermJumpApprove = "jump.approve"

	// PermAlertsTriage lets a user dismiss Guide alerts and acknowledge
	// integrity changes. Both hide evidence from everybody else's view, so
	// they are not open to every signed-in viewer.
	PermAlertsTriage = "alerts.triage"

	// The permissions below cover settings that used to need an
	// administrator's own session. Each is a lever on the whole server, so
	// each is its own grant (a role or token holds exactly the ones it
	// needs) and, like every permission, only someone holding it can give
	// it. Their routes also need settings.manage. Making someone an
	// administrator, granting the admin role, the break-glass account and
	// approval-exempt tokens stay with administrators' sessions: a
	// permission for those would be the administrator flag by another name.

	// PermAllowlistsManage changes the internal destinations allowlist
	// (which internal hosts webhooks, syslog, LDAP and remote_write may
	// reach) and the import allowlist. Both guard against the server being
	// used to reach the internal network.
	PermAllowlistsManage = "network.allowlists"

	// PermAgentTrustManage changes the public URL agents download
	// installers and updates from, the address agents connect to, and
	// whether the legacy shared agent credential is accepted.
	PermAgentTrustManage = "agents.trust"

	// PermIdentityManage changes who can sign in: identity providers, the
	// SSO allowlist and the SCIM token. Whoever controls sign-in can sign
	// in as anyone that provider vouches for.
	PermIdentityManage = "identity.manage"

	// PermIntegrationsManage connects and disconnects outside systems:
	// event streaming and Prometheus, Entra ID and Intune, the macOS MDM,
	// certificate authorities and the remote desktop gateway, including
	// the credentials mustra holds for them.
	PermIntegrationsManage = "integrations.manage"

	// PermBackupsRestore restores a backup made somewhere else. A restore
	// replaces every account, role and token with the backup's.
	PermBackupsRestore = "backups.restore"

	// PermTokensManage lets an API token create and change API tokens.
	// People manage tokens with settings.manage; a token needs this too. A
	// token made by a token never has more permissions than it, and stops
	// working when it is revoked, deleted or expires.
	PermTokensManage = "tokens.manage"

	// PermFleetRead lets an account see the fleet at all: endpoints, their
	// inventory and telemetry, findings, deployments and reports, and ask
	// read-only questions of endpoints. An account without it, and without
	// any other way in, sees only its own preferences, two-step sign-in and
	// Help. The built-in read-only role holds it.
	PermFleetRead = "fleet.read"

	// PermAuditRead lets an account read the audit log: who did what, to
	// which endpoint, from where. Separate from fleet.read because the log
	// is evidence about people, not machines.
	PermAuditRead = "audit.read"
)

// AllPermissions is the full permission set — what the builtin "admin" role
// is reseeded with on every startup (see store.SeedBuiltinRoles).
var AllPermissions = []string{PermSettingsManage, PermUsersManage, PermPatchesManage, PermDeployManage, PermGroupsManage, PermDeployOverride, PermRecoveryKeys, PermApprovalsDecide, PermSessionsAudit, PermJumpApprove, PermAlertsTriage,
	PermAllowlistsManage, PermAgentTrustManage, PermIdentityManage, PermIntegrationsManage, PermBackupsRestore, PermTokensManage, PermFleetRead, PermAuditRead}
