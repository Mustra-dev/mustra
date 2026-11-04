package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	bnats "github.com/mustra-dev/mustra/internal/nats"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
	"github.com/mustra-dev/mustra/internal/version"
)

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()

	// Unauthenticated liveness, for compose's healthcheck, a reverse proxy,
	// or an orchestrator. It answers only "is this process serving requests
	// against a database it can reach" — no fleet state, nothing worth
	// authenticating, and nothing an unauthenticated caller learns from it
	// that the TCP port has not already told them.
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	// Prometheus scrapes with a token from Administration → Integrations.
	mux.HandleFunc("GET /metrics", s.handleMetrics)
	// Endpoint host metrics for Prometheus to scrape (telemetry.go), behind
	// the same Prometheus integration token as /metrics.
	mux.HandleFunc("GET /metrics/endpoints", s.handleEndpointMetrics)

	// First-run setup: unauthenticated by necessity, since it exists to
	// create the first account there is. Both handlers refuse once the
	// deployment has been claimed.
	mux.HandleFunc("GET /setup", s.handleSetupPage)
	mux.HandleFunc("POST /setup", s.handleSetupSubmit)

	// Unauthenticated: the login flow itself, and SCIM (which has its own
	// bearer-token auth, independent of console sessions).
	mux.HandleFunc("GET /login", s.handleLoginPage)
	mux.HandleFunc("POST /login/local", s.auth.HandleLocalLogin)
	mux.HandleFunc("POST /login/code", s.auth.HandleMFALogin)
	// Per-provider SSO paths, plus the original slug-less ones — kept so a
	// single-provider deployment that predates multi-IdP support keeps
	// working against the redirect URI already registered at its IdP.
	mux.HandleFunc("GET /login/sso", s.auth.HandleSSOLogin)
	mux.HandleFunc("GET /login/sso/{provider}", s.auth.HandleSSOLogin)
	mux.HandleFunc("GET /auth/callback", s.auth.HandleSSOCallback)
	mux.HandleFunc("GET /auth/callback/{provider}", s.auth.HandleSSOCallback)
	mux.HandleFunc("POST /logout", s.auth.HandleLogout)
	mux.Handle("/scim/v2/", http.StripPrefix("/scim/v2", s.scim.Routes()))
	// Also unauthenticated, and for the same reason SCIM is: an outside
	// system posting here has no console session. The token in the path is
	// the entire credential — see handlePlaybookWebhook for why every
	// failure answers identically.
	mux.HandleFunc("POST /hooks/playbook/{token}", s.handlePlaybookWebhook)
	mux.Handle("GET /static/", staticAssetHandler())
	// Also unauthenticated: agent binary downloads and install scripts — a
	// copy-pasted `curl`/`irm` one-liner has no browser session to send.
	mux.HandleFunc("GET /branding/logo", s.handleBrandingLogo)
	// The private CA's revocation list: whatever checks a certificate it
	// signed must reach it without signing in.
	mux.HandleFunc("GET "+crlPath, s.handlePrivateCRL)
	mux.HandleFunc("GET /downloads/{name}", s.handleDownloadAgent)
	mux.HandleFunc("GET /downloads/mustra-haos-addon.tar.gz", s.handleHAOSAddon)
	// Token-gated rather than session-gated: an agent has no session. The
	// token is minted per dispatch and travels over the authenticated
	// command channel.
	mux.HandleFunc("GET /package-files/{fileID}", s.handleDownloadPackageFile)
	mux.HandleFunc("GET /deploy-files/{job}/{file}", s.handleDeployFile)
	mux.HandleFunc("GET /deploy-artifacts/{job}/{key}", s.handleDeployArtifact)
	mux.HandleFunc("GET /sensor-artifacts/{key}", s.handleGoSensorArtifact)
	mux.HandleFunc("GET /install.sh", s.handleInstallSh)
	mux.HandleFunc("GET /install.ps1", s.handleInstallPs1)
	mux.HandleFunc("GET /ca.crt", s.handleCACert)
	mux.HandleFunc("GET /install/full-disk-access.mobileconfig", s.handleFullDiskAccessProfile)

	// Everything else requires a session.
	protected := s.newRouteTable()
	protected.HandleFunc("GET /api/agents", s.handleListAgents)
	// The sensor catalog is documentation plus live coverage — readable by
	// anyone signed in, since knowing what a sensor does grants nothing.
	protected.HandleFunc("GET /api/sensors", s.handleListSensors)
	protected.HandleFunc("GET /api/sensors/builtin/{kind}/source", s.handleSensorSource)
	// Notifications are per-viewer: the list carries this user's read state,
	// and the count is split out because the badge is polled.
	protected.HandleFunc("GET /api/preferences", s.handleGetPreferences)
	protected.HandleFunc("PUT /api/preferences", s.handleSetPreferences)
	// Two-step sign-in for the signed-in local account. Any account may
	// manage its own; each change past setup needs a current code.
	protected.HandleFunc("GET /api/me/mfa", s.handleGetMFA)
	protected.HandleFunc("POST /api/me/mfa/setup", s.handleSetupMFA)
	protected.HandleFunc("POST /api/me/mfa/enable", s.handleEnableMFA)
	protected.HandleFunc("POST /api/me/mfa/recovery-codes", s.handleMFARecoveryCodes)
	protected.HandleFunc("POST /api/me/mfa/disable", s.handleDisableMFA)
	protected.HandleFunc("GET /api/notifications", s.handleListNotifications)
	protected.HandleFunc("GET /api/notifications/count", s.handleNotificationCount)
	protected.HandleFunc("POST /api/notifications/{id}/read", s.handleReadNotification)
	protected.HandleFunc("GET /api/agents/stream", s.handleAgentsStream)
	protected.HandleFunc("POST /api/query", s.handleStartQuery)
	protected.HandleFunc("GET /api/query/{id}/stream", s.handleQueryStream)
	protected.HandleFunc("GET /api/me", s.handleMe)
	protected.HandleFunc("GET /api/agents/{id}/sensor/{kind}", s.handleGetCachedSensor)
	protected.HandleFunc("GET /api/agents/{id}/versions", s.handleAgentVersionHistory)
	protected.HandleFunc("GET /api/agents/{id}/actions", s.handleAgentActions)
	protected.HandleFunc("GET /api/agent-versions", s.handleRecentAgentVersions)

	// perm wraps a handler behind a permission check (composed inside
	// RequireAuth below, so auth.CurrentUser is already populated) — the
	// admin tabs (Settings, Users/Groups/Roles, Patches) and agent
	// deployment (credential vault/scan/push) all sit behind one of the
	// four fixed permission keys; see auth.AllPermissions.
	perm := func(p string, h http.Handler) http.Handler {
		wrap := func(h http.Handler) http.Handler { return s.auth.RequirePermission(p)(h) }
		return &permGuard{perms: []string{p}, check: wrap(h), next: h, wrap: wrap}
	}
	// permAny admits either key: a Direct Connect transcript is read both
	// by the operator who ran the session and by an auditor who may not
	// open one, and neither should have to hold the other's powers.
	permAny := func(p1, p2 string, h http.Handler) http.Handler {
		wrap := func(h http.Handler) http.Handler { return s.auth.RequireAnyPermission(p1, p2)(h) }
		return &permGuard{perms: []string{p1, p2}, check: wrap(h), next: h, wrap: wrap}
	}
	hf := func(fn http.HandlerFunc) http.Handler { return fn }
	// Changing a sensor's interval can silence an endpoint's telemetry, so
	// it is an operator's action on that endpoint, not a viewer's.
	protected.Handle("POST /api/agents/{id}/sensor-interval", perm(auth.PermDeployManage, hf(s.handleSetSensorInterval)))

	// End-user notifications: what the person at the endpoint is told.
	// Sending one is as consequential as a deployment, so it takes the same
	// permission.
	protected.HandleFunc("GET /api/eun", s.handleListEUN)
	protected.Handle("POST /api/eun", perm(auth.PermDeployManage, hf(s.handleUpsertEUN)))
	protected.Handle("PUT /api/eun/{id}", perm(auth.PermDeployManage, hf(s.handleUpsertEUN)))
	protected.Handle("DELETE /api/eun/{id}", perm(auth.PermDeployManage, hf(s.handleDeleteEUN)))
	protected.Handle("POST /api/eun/{id}/send", perm(auth.PermDeployManage, hf(s.handleSendEUN)))
	// Engage surveys. Reading the results is open to anyone signed in;
	// asking the fleet a question is not, because it puts something on
	// somebody's screen.
	// Playbook triggers and approval gates. Deciding a gate is
	// approvals.decide, never deploy.manage: an approval whose only
	// requirement is being allowed to do the thing yourself is not one.
	protected.Handle("GET /api/playbook-triggers", perm(auth.PermDeployManage, hf(s.handleListPlaybookTriggers)))
	protected.Handle("POST /api/playbook-triggers", perm(auth.PermDeployManage, hf(s.handleUpsertPlaybookTrigger)))
	protected.Handle("PUT /api/playbook-triggers/{id}", perm(auth.PermDeployManage, hf(s.handleUpsertPlaybookTrigger)))
	protected.Handle("DELETE /api/playbook-triggers/{id}", perm(auth.PermDeployManage, hf(s.handleDeletePlaybookTrigger)))
	protected.HandleFunc("GET /api/playbook-approvals", s.handleListPlaybookPauses)
	protected.Handle("POST /api/playbook-approvals/{id}", perm(auth.PermApprovalsDecide, hf(s.handleDecidePlaybookPause)))
	protected.HandleFunc("GET /api/surveys", s.handleListSurveys)
	protected.HandleFunc("GET /api/surveys/{id}", s.handleSurveyDetail)
	protected.Handle("POST /api/surveys", perm(auth.PermDeployManage, hf(s.handleUpsertSurvey)))
	protected.Handle("PUT /api/surveys/{id}", perm(auth.PermDeployManage, hf(s.handleUpsertSurvey)))
	protected.Handle("DELETE /api/surveys/{id}", perm(auth.PermDeployManage, hf(s.handleDeleteSurvey)))
	protected.Handle("POST /api/surveys/{id}/send", perm(auth.PermDeployManage, hf(s.handleSendSurvey)))

	// Custom sensors run operator-written code on every endpoint, which is
	// the same boundary a package command crosses — so the same permission.
	protected.HandleFunc("GET /api/sensors/custom", s.handleListCustomSensors)
	protected.Handle("POST /api/sensors/custom/complete", perm(auth.PermDeployManage, hf(s.handleCompleteCustomSensorScript)))
	protected.Handle("POST /api/sensors/custom/test", perm(auth.PermDeployManage, hf(s.handleTestCustomSensor)))
	protected.Handle("POST /api/sensors/custom/parse", perm(auth.PermDeployManage, hf(s.handleParseCustomOutput)))
	protected.Handle("POST /api/sensors/custom/validate", perm(auth.PermDeployManage, hf(s.handleValidateCustomSensorScripts)))
	protected.Handle("POST /api/sensors/custom", perm(auth.PermDeployManage, hf(s.handleUpsertCustomSensor)))
	protected.Handle("PUT /api/sensors/custom/{id}", perm(auth.PermDeployManage, hf(s.handleUpsertCustomSensor)))
	protected.Handle("DELETE /api/sensors/custom/{id}", perm(auth.PermDeployManage, hf(s.handleDeleteCustomSensor)))
	protected.HandleFunc("GET /api/sensors/custom/{id}/results", s.handleCustomSensorResults)

	protected.Handle("POST /api/deploy/scan", perm(auth.PermDeployManage, hf(s.handleDeployScan)))
	protected.Handle("POST /api/deploy/autoscan", perm(auth.PermDeployManage, hf(s.handleDeployAutoScan)))
	protected.Handle("GET /api/deploy/credentials", perm(auth.PermDeployManage, hf(s.handleListCredentials)))
	protected.Handle("POST /api/deploy/credentials", perm(auth.PermDeployManage, hf(s.handleCreateCredential)))
	protected.Handle("GET /api/deploy/credentials/{id}/public-key", perm(auth.PermDeployManage, hf(s.handleCredentialPublicKey)))
	protected.Handle("DELETE /api/deploy/credentials/{id}", perm(auth.PermDeployManage, hf(s.handleDeleteCredential)))
	protected.Handle("POST /api/deploy/push", perm(auth.PermDeployManage, hf(s.handleDeployPush)))
	protected.Handle("GET /api/deploy/deployments", perm(auth.PermDeployManage, hf(s.handleListAgentDeployments)))
	protected.Handle("GET /agents", perm(auth.PermDeployManage, agentsPageHandler()))

	protected.HandleFunc("GET /api/patches", s.handlePatchesSummary) // viewable by anyone logged in
	protected.Handle("POST /api/agents/{id}/apply-patches", perm(auth.PermPatchesManage, hf(s.handleApplyPatches)))
	protected.Handle("POST /api/patches/deploy", perm(auth.PermPatchesManage, hf(s.handleDeployPatchesBulk)))
	protected.Handle("POST /api/patches/rescan", perm(auth.PermPatchesManage, hf(s.handleRescanPatches)))
	protected.Handle("GET /api/patches/schedules", perm(auth.PermPatchesManage, hf(s.handleListPatchSchedules)))
	protected.Handle("POST /api/patches/schedules", perm(auth.PermPatchesManage, hf(s.handleCreatePatchSchedule)))
	protected.Handle("POST /api/patches/schedules/{id}/enabled", perm(auth.PermPatchesManage, hf(s.handleSetPatchScheduleEnabled)))
	protected.Handle("DELETE /api/patches/schedules/{id}", perm(auth.PermPatchesManage, hf(s.handleDeletePatchSchedule)))
	protected.Handle("GET /api/patches/history", perm(auth.PermPatchesManage, hf(s.handleListPatchHistory)))
	protected.Handle("GET /api/patches/lists", perm(auth.PermPatchesManage, hf(s.handleListPatchLists)))
	protected.Handle("POST /api/patches/lists", perm(auth.PermPatchesManage, hf(s.handleCreatePatchList)))
	protected.Handle("DELETE /api/patches/lists/{id}", perm(auth.PermPatchesManage, hf(s.handleDeletePatchList)))
	protected.Handle("GET /api/patches/list-assignments", perm(auth.PermPatchesManage, hf(s.handleListPatchListAssignments)))
	protected.Handle("POST /api/patches/list-assignments", perm(auth.PermPatchesManage, hf(s.handleCreatePatchListAssignment)))
	protected.Handle("DELETE /api/patches/list-assignments/{id}", perm(auth.PermPatchesManage, hf(s.handleDeletePatchListAssignment)))
	protected.HandleFunc("GET /api/patches/deployments", s.handleListDeployments) // a deployment record is history; readable by anyone signed in
	protected.HandleFunc("GET /api/patches/deployments/{id}", s.handleGetDeployment)
	protected.Handle("GET /patches", patchesPageHandler())
	protected.Handle("GET /sensors", sensorsPageHandler())
	protected.Handle("GET /eun", eunPageHandler())
	protected.Handle("GET /engage", engagePageHandler())
	protected.Handle("GET /hunt", huntPageHandler())
	protected.Handle("GET /enforce", enforcePageHandler())
	protected.Handle("GET /playbooks", playbooksPageHandler())
	protected.Handle("GET /reports", reportsPageHandler())
	// Dashboards: authored by anyone signed in (edited by the author or an
	// administrator); alerts write into everyone's Guide tray, so they
	// are administration.
	protected.Handle("GET /dashboards", staticPageHandler("static/dashboards.html"))
	protected.HandleFunc("GET /api/dashboards", s.handleListDashboards)
	protected.HandleFunc("POST /api/dashboards", s.handleSaveDashboard)
	protected.HandleFunc("POST /api/dashboards/preview", s.handlePanelPreview)
	protected.HandleFunc("GET /api/dashboards/columns", s.handleDashboardColumns)
	protected.HandleFunc("GET /api/dashboards/{id}", s.handleGetDashboard)
	protected.HandleFunc("PUT /api/dashboards/{id}", s.handleSaveDashboard)
	protected.HandleFunc("DELETE /api/dashboards/{id}", s.handleDeleteDashboard)
	protected.HandleFunc("POST /api/dashboards/{id}/clone", s.handleCloneDashboard)
	protected.HandleFunc("GET /api/dashboards/{id}/data", s.handleDashboardData)
	protected.HandleFunc("GET /api/dashboard-alerts", s.handleListDashboardAlerts)
	protected.Handle("POST /api/dashboard-alerts", perm(auth.PermSettingsManage, hf(s.handleSaveDashboardAlert)))
	protected.Handle("POST /api/dashboard-alerts/evaluate", perm(auth.PermSettingsManage, hf(s.handleEvaluateAlerts)))
	protected.Handle("PUT /api/dashboard-alerts/{id}", perm(auth.PermSettingsManage, hf(s.handleSaveDashboardAlert)))
	protected.Handle("DELETE /api/dashboard-alerts/{id}", perm(auth.PermSettingsManage, hf(s.handleDeleteDashboardAlert)))

	protected.HandleFunc("POST /api/interact/ask", s.handleAskQuestion) // querying is read-only; anyone signed in may
	protected.HandleFunc("GET /api/interact/saved", s.handleListSavedQuestions)
	protected.HandleFunc("POST /api/interact/saved", s.handleSaveQuestion)
	protected.HandleFunc("DELETE /api/interact/saved/{id}", s.handleDeleteSavedQuestion)
	protected.HandleFunc("GET /api/interact/history", s.handleQuestionHistory)
	protected.Handle("GET /interact", interactPageHandler())

	protected.HandleFunc("GET /api/health", s.handleHealth) // endpoint health is everyone's business
	protected.HandleFunc("GET /api/risk/scores", s.handleRiskScores)
	protected.Handle("POST /api/risk/criticality", perm(auth.PermPatchesManage, hf(s.handleSetCriticality)))
	protected.Handle("GET /health", healthPageHandler())

	// A live shell is the same authority a software package already
	// carries, reached faster — so it takes the same permission, and
	// every command is logged with who ran it.
	protected.Handle("POST /api/shell/sessions", perm(auth.PermDeployManage, hf(s.handleOpenShell)))
	protected.Handle("POST /api/shell/sessions/{id}/exec", perm(auth.PermDeployManage, hf(s.handleShellExec)))
	protected.Handle("DELETE /api/shell/sessions/{id}", perm(auth.PermDeployManage, hf(s.handleCloseShell)))
	protected.Handle("GET /api/shell/sessions", perm(auth.PermDeployManage, hf(s.handleListShellSessions)))
	protected.Handle("GET /api/shell/audit", perm(auth.PermDeployManage, hf(s.handleShellAudit)))
	// Jump Gate. Requesting access needs only the permission to use Direct
	// Connect at all; deciding is its own permission, and reading a
	// transcript is a third — an auditor reviews what was run without
	// being able to run anything.
	protected.Handle("POST /api/jump/requests", perm(auth.PermDeployManage, hf(s.handleRequestJumpAccess)))
	// Integrations (integrations.go): event streaming and the Prometheus token.
	protected.Handle("GET /api/admin/integrations", perm(auth.PermSettingsManage, hf(s.handleListIntegrations)))
	protected.Handle("POST /api/admin/integrations", perm(auth.PermSettingsManage, hf(s.handleSaveIntegration)))
	protected.Handle("PUT /api/admin/integrations/{id}", perm(auth.PermSettingsManage, hf(s.handleSaveIntegration)))
	protected.Handle("DELETE /api/admin/integrations/{id}", perm(auth.PermSettingsManage, hf(s.handleDeleteIntegration)))
	protected.Handle("POST /api/admin/integrations/{id}/test", perm(auth.PermSettingsManage, hf(s.handleTestIntegration)))
	// Certificate renewal (certs_renew.go).
	protected.HandleFunc("GET /api/certificates/managed", s.handleListManagedCerts)
	protected.Handle("POST /api/certificates/managed", perm(auth.PermDeployManage, hf(s.handleSaveManagedCert)))
	protected.Handle("PUT /api/certificates/managed/{id}", perm(auth.PermDeployManage, hf(s.handleSaveManagedCert)))
	protected.Handle("DELETE /api/certificates/managed/{id}", perm(auth.PermDeployManage, hf(s.handleDeleteManagedCert)))
	protected.Handle("POST /api/certificates/managed/{id}/renew", perm(auth.PermDeployManage, hf(s.handleRenewManagedCert)))
	protected.Handle("POST /api/certificates/managed/{id}/upload", perm(auth.PermDeployManage, hf(s.handleUploadManagedCert)))
	protected.Handle("POST /api/certificates/upload/preview", perm(auth.PermDeployManage, hf(s.handlePreviewUpload)))
	// Expiry alerts (expiry_alerts.go).
	protected.HandleFunc("GET /api/certificates/alerts", s.handleGetExpiryAlerts)
	protected.Handle("POST /api/certificates/alerts", perm(auth.PermSettingsManage, hf(s.handleSaveExpiryAlerts)))
	protected.Handle("POST /api/certificates/alerts/test", perm(auth.PermSettingsManage, hf(s.handleTestExpiryAlert)))
	// Enterprise application credentials (appcreds.go).
	protected.HandleFunc("GET /api/certificates/apps", s.handleListAppCreds)
	protected.Handle("POST /api/certificates/apps/connections", perm(auth.PermDeployManage, hf(s.handleSaveAppCredConnection)))
	protected.Handle("PUT /api/certificates/apps/connections/{id}", perm(auth.PermDeployManage, hf(s.handleSaveAppCredConnection)))
	protected.Handle("DELETE /api/certificates/apps/connections/{id}", perm(auth.PermDeployManage, hf(s.handleDeleteAppCredConnection)))
	protected.Handle("GET /api/certificates/apps/connections/{id}/discover", perm(auth.PermDeployManage, hf(s.handleDiscoverAppCreds)))
	protected.Handle("POST /api/certificates/apps/credentials", perm(auth.PermDeployManage, hf(s.handleSaveAppCred)))
	protected.Handle("PUT /api/certificates/apps/credentials/{id}", perm(auth.PermDeployManage, hf(s.handleSaveAppCred)))
	protected.Handle("DELETE /api/certificates/apps/credentials/{id}", perm(auth.PermDeployManage, hf(s.handleDeleteAppCred)))
	protected.Handle("POST /api/certificates/apps/credentials/{id}/renew", perm(auth.PermDeployManage, hf(s.handleRenewAppCred)))
	protected.Handle("GET /api/certificates/apps/credentials/{id}/download", perm(auth.PermDeployManage, hf(s.handleDownloadAppCred)))
	protected.HandleFunc("GET /api/certificates/issued", s.handleListIssued)
	protected.Handle("POST /api/certificates/issued/{id}/revoke", perm(auth.PermDeployManage, hf(s.handleRevokeIssued)))
	protected.HandleFunc("GET /api/certificates/trust", s.handleListTrustRoots)
	protected.Handle("POST /api/certificates/trust/{id}", perm(auth.PermDeployManage, hf(s.handleSetTrustRoot)))
	protected.HandleFunc("GET /api/certificates/ca.crt", s.handleDownloadCA)
	protected.Handle("POST /api/admin/cert-authorities", perm(auth.PermSettingsManage, hf(s.handleSaveCertAuthorities)))
	// Remote desktop (remote_api.go): RDP, VNC and SSH through Guacamole,
	// BeyondTrust or a URL template, behind the same checks as a shell.
	protected.HandleFunc("GET /api/remote/config", s.handleRemoteConfig)
	protected.Handle("POST /api/remote/sessions", perm(auth.PermDeployManage, hf(s.handleOpenRemote)))
	protected.Handle("GET /api/remote/sessions", permAny(auth.PermSessionsAudit, auth.PermDeployManage, hf(s.handleListRemoteSessions)))
	protected.Handle("GET /api/remote/sessions/{id}/recording", permAny(auth.PermSessionsAudit, auth.PermDeployManage, hf(s.handleRemoteRecording)))
	protected.Handle("POST /api/admin/remote", perm(auth.PermSettingsManage, hf(s.handleSaveRemoteConfig)))
	// Every method Guacamole's page, API and WebSocket tunnel use; a
	// method-less pattern would conflict with "GET /".
	for _, m := range []string{"GET", "POST", "PUT", "PATCH", "DELETE"} {
		protected.Handle(m+" /guacamole/", perm(auth.PermDeployManage, hf(s.handleGuacamoleProxy)))
	}
	protected.HandleFunc("GET /api/jump/grants", s.handleListJumpGrants)
	protected.Handle("POST /api/jump/grants/{id}/decide", perm(auth.PermJumpApprove, hf(s.handleDecideJumpGrant)))
	protected.Handle("POST /api/jump/grants/{id}/revoke", perm(auth.PermJumpApprove, hf(s.handleRevokeJumpGrant)))
	protected.Handle("GET /api/jump/policies", perm(auth.PermSettingsManage, hf(s.handleListJumpPolicies)))
	protected.Handle("POST /api/jump/policies", perm(auth.PermSettingsManage, hf(s.handleSaveJumpPolicy)))
	protected.Handle("PUT /api/jump/policies/{id}", perm(auth.PermSettingsManage, hf(s.handleSaveJumpPolicy)))
	protected.Handle("DELETE /api/jump/policies/{id}", perm(auth.PermSettingsManage, hf(s.handleDeleteJumpPolicy)))
	protected.Handle("GET /api/sessions", permAny(auth.PermSessionsAudit, auth.PermDeployManage, hf(s.handleListTranscripts)))
	protected.Handle("GET /api/sessions/{id}", permAny(auth.PermSessionsAudit, auth.PermDeployManage, hf(s.handleGetTranscript)))
	protected.Handle("GET /shell", perm(auth.PermDeployManage, shellPageHandler()))

	// The audit log is readable by every role that ships, deliberately: a
	// record only administrators can see is a weaker control than one
	// everybody knows is being kept. It is still its own permission, so an
	// account with no role, or an API token made for one job, does not read
	// who did what across the fleet.
	protected.Handle("GET /api/audit", perm(auth.PermAuditRead, hf(s.handleAuditEvents)))
	protected.Handle("GET /api/admin/logging", perm(auth.PermSettingsManage, hf(s.handleGetLogging)))
	protected.Handle("POST /api/admin/logging", perm(auth.PermSettingsManage, hf(s.handleUpdateLogging)))
	protected.Handle("GET /logs", perm(auth.PermAuditRead, logsPageHandler()))

	protected.HandleFunc("GET /api/compliance/policies", s.handleListPolicies)
	protected.HandleFunc("GET /api/compliance/results", s.handleComplianceResults)
	protected.HandleFunc("GET /api/compliance/scores", s.handleComplianceScores)
	protected.HandleFunc("GET /api/compliance/report.csv", s.handleComplianceReport)
	protected.HandleFunc("GET /api/compliance/controls", s.handleComplianceControls)
	protected.HandleFunc("GET /api/compliance/controls.csv", s.handleComplianceControlsCSV)
	protected.Handle("POST /api/compliance/scan", perm(auth.PermPatchesManage, hf(s.handleScanBenchmarks)))
	protected.HandleFunc("GET /api/compliance/exceptions", s.handleListComplianceExceptions)
	protected.Handle("POST /api/compliance/exceptions", perm(auth.PermPatchesManage, hf(s.handleCreateComplianceException)))
	protected.Handle("DELETE /api/compliance/exceptions/{id}", perm(auth.PermPatchesManage, hf(s.handleDeleteComplianceException)))
	protected.Handle("POST /api/compliance/settings", perm(auth.PermSettingsManage, hf(s.handleComplianceSettings)))
	protected.Handle("POST /api/compliance/policies/{id}/run", perm(auth.PermPatchesManage, hf(s.handleRunCompliance)))
	protected.Handle("POST /api/compliance/import", perm(auth.PermPatchesManage, hf(s.handleImportPolicy)))
	protected.Handle("DELETE /api/compliance/policies/{id}", perm(auth.PermPatchesManage, hf(s.handleDeletePolicy)))
	protected.Handle("GET /compliance", compliancePageHandler())

	protected.HandleFunc("GET /api/integrity", s.handleIntegrity)
	// Integrity Monitor management: watchlists, monitors and labels change
	// what every endpoint watches and how findings are classified, so
	// writing them is settings.manage; acknowledging a change is any
	// signed-in operator's job.
	// Access control: content sets, action groups and approval policies all
	// change what other people may do, so writing them is settings.manage.
	// Deciding an approval is its own permission — see PermApprovalsDecide.
	protected.Handle("GET /access", staticPageHandler("static/access.html"))
	// Asset attributes and retention. Reading is open to anyone signed in
	// (an attribute is inventory); defining one changes the targeting
	// vocabulary, so that takes groups.manage, and retiring an endpoint by
	// hand takes deploy.manage like any other fleet action.
	protected.HandleFunc("GET /api/asset-attributes", s.handleListAssetAttributes)
	protected.Handle("POST /api/asset-attributes/lifecycle-preset", perm(auth.PermGroupsManage, hf(s.handleLifecyclePreset)))
	protected.HandleFunc("GET /api/lifecycle", s.handleLifecycle)
	protected.HandleFunc("GET /api/lifecycle.csv", s.handleLifecycleCSV)
	protected.Handle("POST /api/asset-attributes", perm(auth.PermGroupsManage, hf(s.handleSaveAssetAttribute)))
	protected.Handle("PUT /api/asset-attributes/{id}", perm(auth.PermGroupsManage, hf(s.handleSaveAssetAttribute)))
	protected.Handle("DELETE /api/asset-attributes/{id}", perm(auth.PermGroupsManage, hf(s.handleDeleteAssetAttribute)))
	protected.HandleFunc("GET /api/agents/{id}/attributes", s.handleAgentAttributes)
	protected.Handle("PUT /api/agents/{id}/attributes", perm(auth.PermGroupsManage, hf(s.handleAgentAttributes)))
	protected.Handle("POST /api/agents/{id}/managed", perm(auth.PermDeployManage, hf(s.handleSetAgentManaged)))
	protected.Handle("POST /api/assets/purge-after", perm(auth.PermSettingsManage, hf(s.handleSetPurgeAfter)))
	// Confidence: what this fleet's own history says about a package.
	// Readable by anyone signed in — it is a property of the catalog.
	protected.HandleFunc("GET /api/confidence", s.handleConfidence)
	protected.HandleFunc("GET /api/confidence/patches", s.handlePatchConfidence)
	protected.HandleFunc("GET /api/access/me", s.handleMyAccess)
	protected.Handle("GET /api/content-sets", perm(auth.PermSettingsManage, hf(s.handleListContentSets)))
	protected.Handle("POST /api/content-sets", perm(auth.PermSettingsManage, hf(s.handleSaveContentSet)))
	protected.Handle("PUT /api/content-sets/{id}", perm(auth.PermSettingsManage, hf(s.handleSaveContentSet)))
	protected.Handle("DELETE /api/content-sets/{id}", perm(auth.PermSettingsManage, hf(s.handleDeleteContentSet)))
	protected.Handle("GET /api/action-groups", perm(auth.PermSettingsManage, hf(s.handleListActionGroups)))
	protected.Handle("POST /api/action-groups", perm(auth.PermSettingsManage, hf(s.handleSaveActionGroup)))
	protected.Handle("DELETE /api/action-groups/{module}", perm(auth.PermSettingsManage, hf(s.handleDeleteActionGroup)))
	protected.Handle("GET /api/approval-policies", perm(auth.PermSettingsManage, hf(s.handleListApprovalPolicies)))
	protected.Handle("POST /api/approval-policies", perm(auth.PermSettingsManage, hf(s.handleSaveApprovalPolicy)))
	protected.Handle("PUT /api/approval-policies/{id}", perm(auth.PermSettingsManage, hf(s.handleSaveApprovalPolicy)))
	protected.Handle("DELETE /api/approval-policies/{id}", perm(auth.PermSettingsManage, hf(s.handleDeleteApprovalPolicy)))
	// Reading the queue is open to anyone signed in: seeing that your own
	// operation is waiting is not a privilege. Deciding one is.
	protected.HandleFunc("GET /api/approvals", s.handleListApprovalRequests)
	protected.HandleFunc("GET /api/approve-info", s.handleApproveInfo)
	protected.Handle("GET /approve", staticPageHandler("static/approve.html"))
	protected.Handle("POST /api/approvals/{id}/decide", perm(auth.PermApprovalsDecide, hf(s.handleDecideApproval)))
	protected.HandleFunc("GET /api/watchlists", s.handleListWatchlists)
	protected.Handle("POST /api/watchlists", perm(auth.PermSettingsManage, hf(s.handleSaveWatchlist)))
	protected.Handle("PUT /api/watchlists/{id}", perm(auth.PermSettingsManage, hf(s.handleSaveWatchlist)))
	protected.Handle("DELETE /api/watchlists/{id}", perm(auth.PermSettingsManage, hf(s.handleDeleteWatchlist)))
	protected.HandleFunc("GET /api/integrity/monitors", s.handleListIntegrityMonitors)
	protected.Handle("POST /api/integrity/monitors", perm(auth.PermSettingsManage, hf(s.handleSaveIntegrityMonitor)))
	protected.Handle("PUT /api/integrity/monitors/{id}", perm(auth.PermSettingsManage, hf(s.handleSaveIntegrityMonitor)))
	protected.Handle("DELETE /api/integrity/monitors/{id}", perm(auth.PermSettingsManage, hf(s.handleDeleteIntegrityMonitor)))
	protected.HandleFunc("GET /api/integrity/watch-status", s.handleWatchStatus)
	protected.Handle("POST /api/integrity/watch-status/apply", perm(auth.PermSettingsManage, hf(s.handleWatchApply)))
	protected.HandleFunc("GET /api/integrity/labels", s.handleListIntegrityLabels)
	protected.Handle("POST /api/integrity/labels", perm(auth.PermSettingsManage, hf(s.handleSaveIntegrityLabel)))
	protected.Handle("POST /api/integrity/labels/test", perm(auth.PermSettingsManage, hf(s.handleTestIntegrityLabel)))
	protected.Handle("PUT /api/integrity/labels/{id}", perm(auth.PermSettingsManage, hf(s.handleSaveIntegrityLabel)))
	protected.Handle("DELETE /api/integrity/labels/{id}", perm(auth.PermSettingsManage, hf(s.handleDeleteIntegrityLabel)))
	// Acknowledging hides a change from everybody's view, which is exactly
	// what tampering evidence must not be open to: it takes triage rights.
	protected.Handle("POST /api/integrity/changes/{id}/ack", permAny(auth.PermAlertsTriage, auth.PermSettingsManage, hf(s.handleAckIntegrityChange)))
	protected.Handle("GET /integrity", integrityPageHandler())

	protected.HandleFunc("GET /api/certificates", s.handleCertificates) // expiry is read-only and everyone's problem
	protected.HandleFunc("GET /api/certificates/coverage", s.handleCertificateCoverage)
	protected.HandleFunc("GET /api/certificates/{fingerprint}", s.handleCertificate)
	protected.Handle("GET /certificates", certificatesPageHandler())

	// Impact: reading the analysis is open to anyone signed in, like
	// certificates -- it is a view over data the console already shows.
	// The directory connection and forcing a recompute are administration.
	protected.HandleFunc("GET /api/impact/overview", s.handleImpactOverview)
	protected.HandleFunc("GET /api/impact/search", s.handleImpactSearch)
	protected.HandleFunc("GET /api/impact/path", s.handleImpactPath)
	protected.HandleFunc("GET /api/impact/object/{id}", s.handleImpactObject)
	protected.HandleFunc("GET /api/impact/{kind}", s.handleImpactList)
	protected.Handle("POST /api/impact/recompute", perm(auth.PermSettingsManage, hf(s.handleImpactRecompute)))
	protected.Handle("GET /api/directory", perm(auth.PermSettingsManage, hf(s.handleDirectorySettings)))
	protected.Handle("POST /api/directory", perm(auth.PermSettingsManage, hf(s.handleUpdateDirectorySettings)))
	protected.Handle("POST /api/directory/test", perm(auth.PermSettingsManage, hf(s.handleDirectoryTest)))
	protected.Handle("POST /api/directory/sync", perm(auth.PermSettingsManage, hf(s.handleDirectorySync)))
	protected.Handle("GET /impact", impactPageHandler())

	// Reveal reads files on endpoints with the agent's rights and returns
	// masked evidence about them. Every route is an operator's.
	protected.Handle("GET /api/reveal/overview", perm(auth.PermDeployManage, hf(s.handleRevealOverview)))
	protected.Handle("GET /api/reveal/patterns", perm(auth.PermDeployManage, hf(s.handleRevealPatterns)))
	protected.Handle("GET /api/reveal/templates", perm(auth.PermDeployManage, hf(s.handleRevealTemplates)))
	protected.Handle("GET /api/reveal/rule-sets", perm(auth.PermDeployManage, hf(s.handleListRevealRuleSets)))
	protected.Handle("POST /api/reveal/rule-sets", perm(auth.PermDeployManage, hf(s.handleSaveRevealRuleSet)))
	protected.Handle("PUT /api/reveal/rule-sets/{id}", perm(auth.PermDeployManage, hf(s.handleSaveRevealRuleSet)))
	protected.Handle("DELETE /api/reveal/rule-sets/{id}", perm(auth.PermDeployManage, hf(s.handleDeleteRevealRuleSet)))
	protected.Handle("GET /api/reveal/rules", perm(auth.PermDeployManage, hf(s.handleRevealRules)))
	protected.Handle("POST /api/reveal/rules", perm(auth.PermDeployManage, hf(s.handleSaveRevealRule)))
	protected.Handle("DELETE /api/reveal/rules/{id}", perm(auth.PermDeployManage, hf(s.handleDeleteRevealRule)))
	protected.Handle("POST /api/reveal/rules/{id}/run", perm(auth.PermDeployManage, hf(s.handleRunRevealRule)))
	protected.Handle("POST /api/reveal/search", perm(auth.PermDeployManage, hf(s.handleRevealSearch)))
	protected.Handle("GET /api/reveal/results", perm(auth.PermDeployManage, hf(s.handleRevealResults)))
	protected.Handle("GET /api/reveal/scans", perm(auth.PermDeployManage, hf(s.handleRevealScans)))
	protected.Handle("GET /reveal", perm(auth.PermDeployManage, revealPageHandler()))
	// Maintenance windows and deployment templates: both shape when and
	// how deployments run, so they share deploy.manage. Overriding a window
	// is deploy.override_windows, checked inside the deploy handlers.
	protected.Handle("GET /api/maintenance-windows", perm(auth.PermDeployManage, hf(s.handleListMaintenanceWindows)))
	protected.Handle("POST /api/maintenance-windows", perm(auth.PermDeployManage, hf(s.handleSaveMaintenanceWindow)))
	protected.Handle("PUT /api/maintenance-windows/{id}", perm(auth.PermDeployManage, hf(s.handleSaveMaintenanceWindow)))
	protected.Handle("DELETE /api/maintenance-windows/{id}", perm(auth.PermDeployManage, hf(s.handleDeleteMaintenanceWindow)))
	protected.Handle("POST /api/maintenance-windows/check", perm(auth.PermDeployManage, hf(s.handleMaintenanceWindowCheck)))
	// Patch lists and block lists share patches.manage with the deployments
	// they shape; import/export are the same permission.
	protected.Handle("GET /api/patch-policies", perm(auth.PermPatchesManage, hf(s.handleListPatchPolicies)))
	protected.Handle("POST /api/patch-policies", perm(auth.PermPatchesManage, hf(s.handleSavePatchPolicy)))
	protected.Handle("PUT /api/patch-policies/{id}", perm(auth.PermPatchesManage, hf(s.handleSavePatchPolicy)))
	protected.Handle("DELETE /api/patch-policies/{id}", perm(auth.PermPatchesManage, hf(s.handleDeletePatchPolicy)))
	protected.Handle("GET /api/patch-policies/export", perm(auth.PermPatchesManage, hf(s.handleExportPatchPolicies)))
	protected.Handle("POST /api/patch-policies/import", perm(auth.PermPatchesManage, hf(s.handleImportPatchPolicies)))
	protected.Handle("POST /api/patches/deploy/preview", perm(auth.PermPatchesManage, hf(s.handlePatchDeployPreview)))
	protected.Handle("GET /api/deploy/templates", perm(auth.PermDeployManage, hf(s.handleListDeploymentTemplates)))
	protected.Handle("POST /api/deploy/templates", perm(auth.PermDeployManage, hf(s.handleSaveDeploymentTemplate)))
	protected.Handle("PUT /api/deploy/templates/{id}", perm(auth.PermDeployManage, hf(s.handleSaveDeploymentTemplate)))
	protected.Handle("DELETE /api/deploy/templates/{id}", perm(auth.PermDeployManage, hf(s.handleDeleteDeploymentTemplate)))

	// Guide: the tray. Reading it is for anyone signed in. Dismissing an
	// item hides it for everybody (a dismissal is per condition, not per
	// user), so it takes triage rights; refreshing only recomputes.
	protected.HandleFunc("GET /api/guide", s.handleGuide)
	protected.HandleFunc("POST /api/guide/refresh", s.handleGuideRefresh)
	protected.Handle("POST /api/guide/{id}/dismiss", permAny(auth.PermAlertsTriage, auth.PermSettingsManage, hf(s.handleGuideDismiss)))
	protected.Handle("POST /api/guide/{id}/undismiss", permAny(auth.PermAlertsTriage, auth.PermSettingsManage, hf(s.handleGuideDismiss)))
	protected.Handle("GET /guide", guidePageHandler())
	// Help: the step-by-step guides, open to every account, roles or not.
	protected.Handle("GET /help", helpPageHandler())
	protected.HandleFunc("GET /api/help", s.handleHelpIndex)
	protected.HandleFunc("GET /api/help/{slug}", s.handleHelpGuide)

	protected.HandleFunc("GET /api/discover", s.handleDiscover) // read-only view of the network
	protected.HandleFunc("GET /api/openapi.json", s.handleOpenAPI)
	protected.HandleFunc("GET /api/openapi.yaml", s.handleOpenAPIYAML)
	protected.Handle("GET /api-docs", staticPageHandler("static/api-docs.html"))
	protected.HandleFunc("GET /api/backup-status", s.handleBackups)
	protected.HandleFunc("GET /api/entra/devices", s.handleEntraDevices)
	protected.Handle("GET /api/admin/entra", perm(auth.PermSettingsManage, hf(s.handleEntraConfig)))
	protected.Handle("POST /api/admin/entra", perm(auth.PermSettingsManage, hf(s.handleSaveEntraConfig)))
	protected.Handle("POST /api/admin/entra/sync", perm(auth.PermSettingsManage, hf(s.handleEntraSync)))
	protected.Handle("POST /api/agents/{id}/intune/{action}", perm(auth.PermDeployManage, hf(s.handleIntuneAction)))
	protected.Handle("POST /api/backup-status/settings", perm(auth.PermSettingsManage, hf(s.handleBackupSettings)))
	protected.Handle("GET /api/backup-sources", perm(auth.PermSettingsManage, hf(s.handleListBackupSources)))
	protected.Handle("POST /api/backup-sources", perm(auth.PermSettingsManage, hf(s.handleSaveBackupSource)))
	protected.Handle("PUT /api/backup-sources/{id}", perm(auth.PermSettingsManage, hf(s.handleSaveBackupSource)))
	protected.Handle("DELETE /api/backup-sources/{id}", perm(auth.PermSettingsManage, hf(s.handleDeleteBackupSource)))
	protected.Handle("POST /api/backup-sources/{id}/poll", perm(auth.PermSettingsManage, hf(s.handlePollBackupSource)))
	protected.Handle("GET /backup-status", staticPageHandler("static/backup-status.html"))
	// Threat briefings: anyone signed in reads them (the endpoints listed
	// are the ones they may see); writing one is the security analysts'.
	protected.HandleFunc("GET /api/threats", s.handleListThreats)
	protected.HandleFunc("GET /api/threats/{id}", s.handleGetThreat)
	protected.Handle("POST /api/threats", perm(auth.PermAlertsTriage, hf(s.handleSaveThreat)))
	protected.Handle("PUT /api/threats/{id}", perm(auth.PermAlertsTriage, hf(s.handleSaveThreat)))
	protected.Handle("DELETE /api/threats/{id}", perm(auth.PermAlertsTriage, hf(s.handleDeleteThreat)))
	protected.HandleFunc("GET /api/threat-settings", s.handleGetThreatSettings)
	protected.Handle("PUT /api/threat-settings", perm(auth.PermPatchesManage, hf(s.handlePutThreatSettings)))
	protected.Handle("GET /api/telemetry", perm(auth.PermSettingsManage, hf(s.handleGetTelemetry)))
	protected.Handle("PUT /api/telemetry", perm(auth.PermSettingsManage, hf(s.handlePutTelemetry)))
	protected.Handle("POST /api/telemetry/test", perm(auth.PermSettingsManage, hf(s.handleTestTelemetry)))
	protected.Handle("GET /threats", staticPageHandler("static/threats.html"))
	protected.Handle("PUT /api/discover/devices/{mac}", perm(auth.PermGroupsManage, hf(s.handleUpdateNetworkDevice)))
	protected.Handle("POST /api/discover/settings", perm(auth.PermSettingsManage, hf(s.handleDiscoverSettings)))
	protected.Handle("GET /discover", discoverPageHandler())

	protected.Handle("GET /api/connect/exports", perm(auth.PermSettingsManage, hf(s.handleListExports)))
	protected.Handle("POST /api/connect/exports", perm(auth.PermSettingsManage, hf(s.handleUpsertExport)))
	protected.Handle("PUT /api/connect/exports/{id}", perm(auth.PermSettingsManage, hf(s.handleUpsertExport)))
	protected.Handle("DELETE /api/connect/exports/{id}", perm(auth.PermSettingsManage, hf(s.handleDeleteExport)))
	protected.Handle("POST /api/connect/exports/{id}/run", perm(auth.PermSettingsManage, hf(s.handleRunExport)))
	protected.Handle("GET /connect", perm(auth.PermSettingsManage, connectPageHandler()))
	protected.Handle("GET /backup", perm(auth.PermSettingsManage, backupPageHandler()))

	protected.HandleFunc("GET /api/groups", s.handleListComputerGroups) // a group is a saved view of inventory; readable by anyone signed in
	protected.HandleFunc("GET /api/groups/{id}/members", s.handleGetComputerGroupMembers)
	protected.Handle("POST /api/groups", perm(auth.PermGroupsManage, hf(s.handleUpsertComputerGroup)))
	protected.Handle("PUT /api/groups/{id}", perm(auth.PermGroupsManage, hf(s.handleUpsertComputerGroup)))
	protected.Handle("DELETE /api/groups/{id}", perm(auth.PermGroupsManage, hf(s.handleDeleteComputerGroup)))
	protected.Handle("POST /api/groups/preview", perm(auth.PermGroupsManage, hf(s.handlePreviewComputerGroup)))
	protected.Handle("GET /groups", groupsPageHandler())

	protected.Handle("PUT /api/deploy/packages/{id}", perm(auth.PermDeployManage, hf(s.handleDeployPackageMetadata)))
	protected.Handle("GET /api/deploy/settings", perm(auth.PermDeployManage, hf(s.handleDeploySettings)))
	protected.Handle("PUT /api/deploy/settings", perm(auth.PermDeployManage, hf(s.handleDeploySettings)))
	protected.Handle("GET /api/deploy/packages/{id}/revisions", perm(auth.PermDeployManage, hf(s.handleDeployRevisions)))
	protected.Handle("POST /api/deploy/packages/{id}/revisions", perm(auth.PermDeployManage, hf(s.handleDeployRevisions)))
	protected.Handle("GET /api/deploy/revisions/{revision}/references", perm(auth.PermDeployManage, hf(s.handleDeployReferences)))
	protected.Handle("POST /api/deploy/revisions/{revision}/references", perm(auth.PermDeployManage, hf(s.handleDeployReferences)))
	protected.Handle("POST /api/deploy/revisions/{revision}/retire", perm(auth.PermDeployManage, hf(s.handleRetireDeploy)))
	// Drafts can be deleted; published versions are retired, not deleted.
	protected.Handle("DELETE /api/deploy/revisions/{revision}", perm(auth.PermDeployManage, hf(s.handleDeleteDeployDraft)))
	protected.Handle("POST /api/deploy/packages/{id}/convert-action", perm(auth.PermDeployManage, hf(s.handleConvertAction)))
	protected.Handle("GET /api/deploy/jobs/{job}/log-sensor", perm(auth.PermDeployManage, hf(s.handleActionLogSensor)))
	protected.Handle("POST /api/deploy/revisions/{revision}/publish", perm(auth.PermDeployManage, hf(s.handlePublishDeploy)))
	protected.Handle("POST /api/deploy/run", perm(auth.PermDeployManage, hf(s.handleDeployRun)))
	protected.Handle("POST /api/deploy/preview", perm(auth.PermDeployManage, hf(s.handleDeployRun)))
	protected.Handle("POST /api/deploy/test", perm(auth.PermDeployManage, hf(s.handleDeployRun)))
	protected.Handle("GET /api/deploy/jobs", perm(auth.PermDeployManage, hf(s.handleDeployJobs)))
	protected.Handle("POST /api/deploy/jobs/{job}/cancel", perm(auth.PermDeployManage, hf(s.handleCancelDeploy)))
	protected.Handle("GET /api/deploy/jobs/{job}/logs", perm(auth.PermDeployManage, hf(s.handleDeployLogs)))
	protected.Handle("POST /api/deploy/packages/{id}/import", perm(auth.PermDeployManage, hf(s.handleImportDeployFile)))
	// Updating an agent runs an installer as LocalSystem/root on the
	// endpoint, which is the same boundary a package command crosses -- so
	// the same permission.
	protected.Handle("POST /api/agents/{id}/update", perm(auth.PermDeployManage, hf(s.handleUpdateAgents)))
	// Removing the row, not the agent. Same permission, because an operator
	// who can push commands to an endpoint can already stop it reporting.
	protected.Handle("DELETE /api/agents/{id}", perm(auth.PermDeployManage, hf(s.handleDeleteAgent)))
	protected.Handle("POST /api/agents/update-outdated", perm(auth.PermDeployManage, hf(s.handleUpdateAgents)))
	// Agent identity (enroll_tokens.go). Minting a token admits a new
	// endpoint into the fleet, and revoking a credential cuts one off, so
	// both are deployment acts. The trust settings (public URL, legacy
	// shared credential) are settings.
	protected.Handle("GET /api/enrollment-tokens", perm(auth.PermDeployManage, hf(s.handleListEnrollTokens)))
	protected.Handle("POST /api/enrollment-tokens", perm(auth.PermDeployManage, hf(s.handleCreateEnrollToken)))
	protected.Handle("DELETE /api/enrollment-tokens/{id}", perm(auth.PermDeployManage, hf(s.handleRevokeEnrollToken)))
	protected.Handle("GET /api/agent-identities", perm(auth.PermDeployManage, hf(s.handleListAgentIdentities)))
	protected.Handle("POST /api/agents/{id}/revoke-credential", perm(auth.PermDeployManage, hf(s.handleRevokeAgentCredential)))
	protected.Handle("GET /api/agent-trust", perm(auth.PermSettingsManage, hf(s.handleGetAgentTrust)))
	protected.Handle("PUT /api/agent-trust", perm(auth.PermSettingsManage, hf(s.handlePutAgentTrust)))
	protected.HandleFunc("GET /api/software", s.handleListSoftware) // the catalog is readable by anyone signed in
	protected.Handle("POST /api/software", perm(auth.PermDeployManage, hf(s.handleUpsertSoftware)))
	protected.Handle("PUT /api/software/{id}", perm(auth.PermDeployManage, hf(s.handleUpsertSoftware)))
	protected.Handle("DELETE /api/software/{id}", perm(auth.PermDeployManage, hf(s.handleDeleteSoftware)))
	protected.Handle("GET /api/software/discover", perm(auth.PermDeployManage, hf(s.handleDiscoverSoftware)))
	// The package library: ready-made definitions an operator adds to the
	// catalog as drafts (software_library.go).
	protected.Handle("GET /api/software-library", perm(auth.PermDeployManage, hf(s.handleListLibrary)))
	protected.Handle("POST /api/software-library/{id}", perm(auth.PermDeployManage, hf(s.handleAddFromLibrary)))
	protected.Handle("POST /api/software/adopt", perm(auth.PermDeployManage, hf(s.handleAdoptSoftware)))
	// Software Inventory & Usage: reading is for anyone signed in (it is
	// the same inventory the catalog shows); tracking, refreshing and
	// removing go through deploy.manage. Its own prefix, not
	// /api/software/inventory/…: that would be ambiguous with the
	// /api/software/{id}/… package routes and the mux refuses to start.
	protected.HandleFunc("GET /api/software-inventory", s.handleSoftwareInventory)
	protected.Handle("POST /api/software-inventory/refresh", perm(auth.PermDeployManage, hf(s.handleSoftwareInventoryRefresh)))
	protected.HandleFunc("GET /api/software-inventory/product/{key}", s.handleSoftwareInventoryProduct)
	protected.Handle("POST /api/software-inventory/product/{key}/remove-unused", perm(auth.PermDeployManage, hf(s.handleRemoveUnusedSoftware)))
	protected.HandleFunc("GET /api/tracked-products", s.handleListTrackedProducts)
	protected.Handle("POST /api/tracked-products", perm(auth.PermDeployManage, hf(s.handleUpsertTrackedProduct)))
	protected.Handle("PUT /api/tracked-products/{id}", perm(auth.PermDeployManage, hf(s.handleUpsertTrackedProduct)))
	protected.Handle("DELETE /api/tracked-products/{id}", perm(auth.PermDeployManage, hf(s.handleDeleteTrackedProduct)))
	protected.HandleFunc("GET /api/software/{id}/applicability", s.handleSoftwareApplicability)
	protected.Handle("POST /api/software/deploy", perm(auth.PermDeployManage, hf(s.handleDeploySoftware)))
	// Package files: the payload staged to the endpoint before the command
	// runs. Uploading one is authoring what will execute, so it takes the
	// same permission as writing the command.
	// Scheduled actions: run a package on a cadence. Scheduling something
	// unattended is at least as consequential as deploying it by hand.
	// Threat hunting. Reading indicators and findings is open to anyone
	// signed in — knowing what is being looked for grants nothing — but
	// authoring an indicator shapes what the fleet reports, so it takes a
	// permission.
	// Live response. Killing a process on someone's server is at least as
	// consequential as deploying to it, so it takes the same permission and
	// is recorded the same way.
	protected.Handle("POST /api/agents/{id}/kill-process", perm(auth.PermDeployManage, hf(s.handleKillProcess)))
	protected.HandleFunc("GET /api/hunt/iocs", s.handleListIOCs)
	protected.Handle("POST /api/hunt/iocs", perm(auth.PermSettingsManage, hf(s.handleUpsertIOC)))
	protected.Handle("PUT /api/hunt/iocs/{id}", perm(auth.PermSettingsManage, hf(s.handleUpsertIOC)))
	protected.Handle("DELETE /api/hunt/iocs/{id}", perm(auth.PermSettingsManage, hf(s.handleDeleteIOC)))
	protected.HandleFunc("GET /api/hunt/findings", s.handleListIOCFindings)
	// Real-time file events. Reading is open like every other reporting
	// view: an event says a watched path changed and when, which is what
	// the Integrity page already shows in slower form.
	protected.HandleFunc("GET /api/file-events", s.handleListFileEvents)
	protected.HandleFunc("GET /api/process-events", s.handleListProcessEvents)
	protected.HandleFunc("GET /api/recorder-events", s.handleListRecorderEvents)
	// Client Management: status and health are readable with the same
	// permission as the page; profiles and ring upgrades change endpoints.
	protected.Handle("GET /api/clients/status", perm(auth.PermDeployManage, hf(s.handleClientStatus)))
	protected.Handle("GET /api/clients/health", perm(auth.PermDeployManage, hf(s.handleClientHealth)))
	protected.Handle("GET /api/clients/profiles", perm(auth.PermDeployManage, hf(s.handleListClientProfiles)))
	protected.Handle("POST /api/clients/profiles", perm(auth.PermDeployManage, hf(s.handleSaveClientProfile)))
	protected.Handle("PUT /api/clients/profiles/{id}", perm(auth.PermDeployManage, hf(s.handleSaveClientProfile)))
	protected.Handle("DELETE /api/clients/profiles/{id}", perm(auth.PermDeployManage, hf(s.handleDeleteClientProfile)))
	protected.Handle("POST /api/clients/profiles/apply", perm(auth.PermDeployManage, hf(s.handleApplyClientProfiles)))
	protected.Handle("POST /api/clients/upgrade", perm(auth.PermDeployManage, hf(s.handleUpgradeRing)))
	protected.HandleFunc("GET /api/risk/exploitability", s.handleExploitability)
	protected.HandleFunc("GET /api/risk/levels", s.handleVulnLevels)
	protected.HandleFunc("GET /api/risk/remediation", s.handleRemediation)
	protected.Handle("POST /api/risk/intel/refresh", perm(auth.PermPatchesManage, hf(s.handleExploitIntelRefresh)))
	// Signals are operator-written detection rules; authoring shares the
	// indicators' permission, reading is open like every other report.
	protected.HandleFunc("GET /api/hunt/signals", s.handleListSignals)
	protected.Handle("POST /api/hunt/signals", perm(auth.PermSettingsManage, hf(s.handleSaveSignal)))
	protected.Handle("PUT /api/hunt/signals/{id}", perm(auth.PermSettingsManage, hf(s.handleSaveSignal)))
	protected.Handle("DELETE /api/hunt/signals/{id}", perm(auth.PermSettingsManage, hf(s.handleDeleteSignal)))
	protected.Handle("POST /api/hunt/signals/test", perm(auth.PermSettingsManage, hf(s.handleTestSignal)))
	protected.HandleFunc("GET /api/hunt/signal-findings", s.handleListSignalFindings)
	protected.Handle("POST /api/hunt/signal-findings/{id}/ack", perm(auth.PermSettingsManage, hf(s.handleAckSignalFinding)))
	protected.Handle("POST /api/hunt/findings/{id}/ack", perm(auth.PermSettingsManage, hf(s.handleAckIOCFinding)))
	protected.Handle("POST /api/hunt/run", perm(auth.PermSettingsManage, hf(s.handleRunHunt)))

	// Enforce: desired state. Reading is open like every other reporting
	// view; authoring is not. A policy is operator-written code that runs
	// on a timer on every targeted endpoint, which is the same trust a
	// package command asks for and then keeps asking, unattended — so it
	// takes the same permission, and running one by hand takes it too.
	protected.HandleFunc("GET /api/enforce/policies", s.handleListEnforcePolicies)
	protected.HandleFunc("GET /api/enforce/policies/{id}", s.handleGetEnforcePolicy)
	protected.Handle("POST /api/enforce/policies", perm(auth.PermDeployManage, hf(s.handleSaveEnforcePolicy)))
	protected.Handle("PUT /api/enforce/policies/{id}", perm(auth.PermDeployManage, hf(s.handleSaveEnforcePolicy)))
	protected.Handle("DELETE /api/enforce/policies/{id}", perm(auth.PermDeployManage, hf(s.handleDeleteEnforcePolicy)))
	protected.Handle("POST /api/enforce/policies/{id}/run", perm(auth.PermDeployManage, hf(s.handleRunEnforcePolicy)))
	protected.Handle("POST /api/enforce/policies/{id}/reset", perm(auth.PermDeployManage, hf(s.handleResetEnforcePolicy)))
	protected.HandleFunc("GET /api/enforce/results", s.handleListEnforceResults)
	protected.HandleFunc("GET /api/enforce/kinds", s.handleEnforceKinds)
	protected.Handle("POST /api/enforce/compile", perm(auth.PermDeployManage, hf(s.handleEnforceCompile)))
	protected.HandleFunc("GET /api/enforce/coverage", s.handleEnforceCoverage)
	// Listing which keys are escrowed is deploy.manage; reading a password
	// is enforce.recovery_keys, and every read is audited.
	protected.Handle("GET /api/enforce/recovery-keys", perm(auth.PermDeployManage, hf(s.handleListRecoveryKeys)))
	protected.Handle("POST /api/enforce/recovery-keys/{agent}/{key}/reveal", perm(auth.PermRecoveryKeys, hf(s.handleRevealRecoveryKey)))

	// Playbooks: several of the above in order, per endpoint, on a
	// schedule. Nothing new reaches the endpoint — a playbook is the
	// server being patient on your behalf — but a sequence that can patch,
	// reboot and enforce unattended is at least as consequential as any
	// one of those, so authoring and running take the same permission.
	protected.HandleFunc("GET /api/playbooks", s.handleListPlaybooks)
	protected.HandleFunc("GET /api/playbooks/runs", s.handleListPlaybookRuns)
	protected.HandleFunc("GET /api/playbooks/runs/{id}", s.handleGetPlaybookRun)
	protected.HandleFunc("GET /api/playbooks/{id}", s.handleGetPlaybook)
	protected.Handle("POST /api/playbooks", perm(auth.PermDeployManage, hf(s.handleSavePlaybook)))
	protected.Handle("PUT /api/playbooks/{id}", perm(auth.PermDeployManage, hf(s.handleSavePlaybook)))
	protected.Handle("DELETE /api/playbooks/{id}", perm(auth.PermDeployManage, hf(s.handleDeletePlaybook)))
	protected.Handle("POST /api/playbooks/{id}/run", perm(auth.PermDeployManage, hf(s.handleRunPlaybook)))

	// Reports: the same data Connect streams, rendered as a page for
	// somebody who does not have a console login. Reading one is reading
	// what the console already shows; authoring one decides where fleet
	// data goes when it leaves, which is Connect's permission exactly.
	protected.HandleFunc("GET /api/reports", s.handleListReports)
	protected.HandleFunc("GET /api/reports/runs", s.handleListReportRuns)
	protected.HandleFunc("GET /api/reports/runs/{id}", s.handleGetReportRun)
	protected.HandleFunc("GET /api/reports/{id}", s.handleGetReport)
	protected.Handle("POST /api/reports", perm(auth.PermSettingsManage, hf(s.handleSaveReport)))
	protected.Handle("PUT /api/reports/{id}", perm(auth.PermSettingsManage, hf(s.handleSaveReport)))
	protected.Handle("DELETE /api/reports/{id}", perm(auth.PermSettingsManage, hf(s.handleDeleteReport)))
	protected.Handle("POST /api/reports/{id}/run", perm(auth.PermSettingsManage, hf(s.handleRunReport)))
	protected.HandleFunc("GET /api/schedules", s.handleListScheduledActions)
	protected.Handle("POST /api/schedules", perm(auth.PermDeployManage, hf(s.handleUpsertScheduledAction)))
	protected.Handle("PUT /api/schedules/{id}", perm(auth.PermDeployManage, hf(s.handleUpsertScheduledAction)))
	protected.Handle("DELETE /api/schedules/{id}", perm(auth.PermDeployManage, hf(s.handleDeleteScheduledAction)))
	protected.Handle("POST /api/schedules/{id}/run", perm(auth.PermDeployManage, hf(s.handleRunScheduledActionNow)))
	protected.HandleFunc("GET /api/software/{id}/files", s.handleListPackageFiles)
	protected.Handle("POST /api/software/{id}/files", perm(auth.PermDeployManage, hf(s.handleUploadPackageFile)))
	protected.Handle("DELETE /api/software/files/{fileID}", perm(auth.PermDeployManage, hf(s.handleDeletePackageFile)))
	protected.HandleFunc("GET /api/deployment-plans", s.handleListPlans)
	protected.Handle("POST /api/deployment-plans", perm(auth.PermDeployManage, hf(s.handleUpsertPlan)))
	protected.Handle("PUT /api/deployment-plans/{id}", perm(auth.PermDeployManage, hf(s.handleUpsertPlan)))
	protected.Handle("DELETE /api/deployment-plans/{id}", perm(auth.PermDeployManage, hf(s.handleDeletePlan)))
	protected.Handle("GET /software", perm(auth.PermDeployManage, softwarePageHandler()))

	protected.Handle("GET /api/catalog/requests", perm(auth.PermDeployManage, hf(s.handleListCatalogRequests)))
	protected.Handle("POST /api/catalog/requests/{id}/decide", perm(auth.PermDeployManage, hf(s.handleDecideCatalogRequest)))
	protected.Handle("GET /catalog", perm(auth.PermDeployManage, catalogPageHandler()))
	protected.Handle("GET /api/selfservice/branding", perm(auth.PermDeployManage, hf(s.handleGetSelfServiceBranding)))
	protected.Handle("PUT /api/selfservice/branding", perm(auth.PermDeployManage, hf(s.handleUpdateSelfServiceBranding)))
	protected.Handle("GET /selfservice/preview", perm(auth.PermDeployManage, hf(handleSelfServicePreview)))

	protected.HandleFunc("GET /api/risk", s.handleRiskSummary) // viewable by anyone logged in, same as /api/patches
	protected.Handle("POST /api/risk/scan", perm(auth.PermPatchesManage, hf(s.handleRiskScanNow)))
	protected.Handle("GET /risk", riskPageHandler())

	protected.Handle("GET /api/admin/settings", perm(auth.PermSettingsManage, hf(s.handleGetSettings)))
	protected.Handle("POST /api/admin/settings", perm(auth.PermSettingsManage, hf(s.handleUpdateSettings)))
	protected.Handle("POST /api/admin/mail-test", perm(auth.PermSettingsManage, hf(s.handleMailTest)))
	protected.Handle("GET /api/admin/email-templates", perm(auth.PermSettingsManage, hf(s.handleGetEmailTemplates)))
	protected.Handle("PUT /api/admin/email-templates/{kind}", perm(auth.PermSettingsManage, hf(s.handleSaveEmailTemplate)))
	protected.Handle("POST /api/admin/email-templates/{kind}/preview", perm(auth.PermSettingsManage, hf(s.handleEmailPreview)))
	protected.Handle("POST /api/admin/email-templates/{kind}/test", perm(auth.PermSettingsManage, hf(s.handleEmailTemplateTest)))
	protected.Handle("PUT /api/admin/email-shared", perm(auth.PermSettingsManage, hf(s.handleSaveEmailShared)))
	protected.Handle("POST /email-preview/{kind}", perm(auth.PermSettingsManage, hf(s.handleEmailPreviewPage)))
	protected.Handle("POST /api/admin/settings/fleet-test", perm(auth.PermSettingsManage, hf(s.handleTestFleet)))
	protected.Handle("POST /api/admin/branding", perm(auth.PermSettingsManage, hf(s.handleUpdateBranding)))

	// Backup and restore. Everything here is settings.manage: taking a
	// backup reads every table, and downloading one takes the estate off
	// the machine, so this is not a permission to hand out widely.
	protected.Handle("GET /api/backups", perm(auth.PermSettingsManage, hf(s.handleListBackups)))
	protected.Handle("POST /api/backups", perm(auth.PermSettingsManage, hf(s.handleCreateBackup)))
	protected.Handle("GET /api/backups/{id}/download", perm(auth.PermSettingsManage, hf(s.handleDownloadBackup)))
	protected.Handle("DELETE /api/backups/{id}", perm(auth.PermSettingsManage, hf(s.handleDeleteBackup)))
	protected.Handle("PUT /api/backups/settings", perm(auth.PermSettingsManage, hf(s.handleUpdateBackupSettings)))
	protected.Handle("POST /api/backups/restore", perm(auth.PermSettingsManage, hf(s.handleRestoreBackup)))
	protected.HandleFunc("GET /api/about", s.handleAbout)     // build identity is not a secret; any signed-in user can see what's running
	protected.HandleFunc("GET /api/version", s.handleVersion) // the same, small enough for every page's footer
	protected.Handle("POST /api/admin/update-check", perm(auth.PermSettingsManage, hf(s.handleUpdateCheck)))
	protected.Handle("GET /api/admin/oidc-providers", perm(auth.PermSettingsManage, hf(s.handleListOIDCProviders)))
	protected.Handle("POST /api/admin/oidc-providers", perm(auth.PermSettingsManage, hf(s.handleUpsertOIDCProvider)))
	protected.Handle("PUT /api/admin/oidc-providers/{id}", perm(auth.PermSettingsManage, hf(s.handleUpsertOIDCProvider)))
	protected.Handle("POST /api/admin/oidc-providers/{id}/enabled", perm(auth.PermSettingsManage, hf(s.handleSetOIDCProviderEnabled)))
	protected.Handle("DELETE /api/admin/oidc-providers/{id}", perm(auth.PermSettingsManage, hf(s.handleDeleteOIDCProvider)))
	protected.Handle("GET /api/admin/tokens", perm(auth.PermSettingsManage, hf(s.handleListAPITokens)))
	protected.Handle("POST /api/admin/tokens", perm(auth.PermSettingsManage, hf(s.handleCreateAPIToken)))
	protected.Handle("PUT /api/admin/tokens/{id}", perm(auth.PermSettingsManage, hf(s.handleUpdateAPIToken)))
	protected.Handle("POST /api/admin/tokens/{id}/revoke", perm(auth.PermSettingsManage, hf(s.handleRevokeAPIToken)))
	protected.Handle("DELETE /api/admin/tokens/{id}", perm(auth.PermSettingsManage, hf(s.handleDeleteAPIToken)))
	protected.Handle("GET /settings", perm(auth.PermSettingsManage, settingsPageHandler()))

	protected.Handle("GET /api/admin/users", perm(auth.PermUsersManage, hf(s.handleListUsers)))
	protected.Handle("POST /api/admin/users", perm(auth.PermUsersManage, hf(s.handleCreateLocalUser)))
	protected.Handle("DELETE /api/admin/users/{id}", perm(auth.PermUsersManage, hf(s.handleDeleteUser)))
	protected.Handle("POST /api/admin/users/{id}/active", perm(auth.PermUsersManage, hf(s.handleSetUserActive)))
	protected.Handle("POST /api/admin/users/{id}/admin", perm(auth.PermUsersManage, hf(s.handleSetUserAdmin)))
	protected.Handle("POST /api/admin/users/{id}/mfa/reset", perm(auth.PermUsersManage, hf(s.handleResetUserMFA)))
	protected.Handle("POST /api/admin/users/{id}/roles", perm(auth.PermUsersManage, hf(s.handleAssignUserRole)))
	protected.Handle("DELETE /api/admin/users/{id}/roles/{role_id}", perm(auth.PermUsersManage, hf(s.handleRemoveUserRole)))
	protected.Handle("GET /api/admin/groups", perm(auth.PermUsersManage, hf(s.handleListGroups)))
	protected.Handle("POST /api/admin/groups", perm(auth.PermUsersManage, hf(s.handleCreateGroup)))
	protected.Handle("DELETE /api/admin/groups/{id}", perm(auth.PermUsersManage, hf(s.handleDeleteGroup)))
	protected.Handle("POST /api/admin/groups/{id}/members", perm(auth.PermUsersManage, hf(s.handleAddGroupMember)))
	protected.Handle("DELETE /api/admin/groups/{id}/members/{user_id}", perm(auth.PermUsersManage, hf(s.handleRemoveGroupMember)))
	protected.Handle("POST /api/admin/groups/{id}/roles", perm(auth.PermUsersManage, hf(s.handleAssignGroupRole)))
	protected.Handle("DELETE /api/admin/groups/{id}/roles/{role_id}", perm(auth.PermUsersManage, hf(s.handleRemoveGroupRole)))
	protected.Handle("GET /api/admin/roles", perm(auth.PermUsersManage, hf(s.handleListRoles)))
	protected.Handle("POST /api/admin/roles", perm(auth.PermUsersManage, hf(s.handleCreateRole)))
	protected.Handle("PUT /api/admin/roles/{id}", perm(auth.PermUsersManage, hf(s.handleUpdateRole)))
	protected.Handle("DELETE /api/admin/roles/{id}", perm(auth.PermUsersManage, hf(s.handleDeleteRole)))
	protected.Handle("GET /admin", perm(auth.PermUsersManage, adminPageHandler()))

	protected.Handle("GET /endpoint/{id}", endpointPageHandler())
	protected.Handle("GET /", consoleUIHandler())
	protected.HandleFunc("GET /api/idnums", s.handleIDNumbers)
	mux.Handle("/", s.auth.RequireAuth(s.resolveShortIDs(protected)))

	// Cross-origin refusal and the shared security headers wrap everything,
	// the unauthenticated routes included: /login/local and /setup are
	// exactly the forms a login-CSRF would post to.
	return s.secureHandler(s.scrubInternalErrors(mux))
}

type meResponse struct {
	Username    string   `json:"username"`
	DisplayName string   `json:"display_name"`
	Source      string   `json:"source"`
	IsAdmin     bool     `json:"is_admin"`
	Permissions []string `json:"permissions"`
	// LogoURL points at the admin-uploaded console logo, versioned so a
	// replacement takes effect immediately. Empty when none is set — the
	// console then keeps its built-in mark. Sent here rather than as its
	// own request because every page already calls /api/me on load.
	LogoURL string `json:"logo_url,omitempty"`

	// Email and Persona back the profile menu. Persona is the name for
	// the named permission set someone is acting under; here it is the
	// user's roles, or "Administrator" for an admin, because knowing what
	// you are currently able to do is worth being able to see at a glance
	// in a console that can act on a whole fleet.
	Email   string `json:"email,omitempty"`
	Persona string `json:"persona,omitempty"`
	// SignedInAt is when the session being used right now began, and
	// PreviousSignIn is the one before it.
	//
	// Only the previous one used to be sent, on the reasoning that the
	// current session's start is something you already know. With sessions
	// that live for days that is not true -- it showed a sign-in from two
	// logins and twelve days ago, which reads as a clock that stopped. Both
	// are sent now and the menu labels them, so the fresh one answers "when
	// did this session start" and the older one still answers "was that me".
	SignedInAt     string `json:"signed_in_at,omitempty"`
	PreviousSignIn string `json:"previous_sign_in,omitempty"`
	// ServerTimeZone is the IANA zone the control plane runs on, and
	// ServerUTCOffsetSeconds its current offset. The console draws
	// timestamps on this clock by default so they line up with the audit
	// log and the agent logs beside them. The offset is a fallback for a
	// zone name the browser's Intl does not recognize.
	ServerTimeZone         string `json:"server_time_zone"`
	ServerUTCOffsetSeconds int    `json:"server_utc_offset_seconds"`
}

// serverZone reports the control plane's timezone as the console needs it.
// TZ wins when the container sets one; otherwise Go's own name for the
// local zone, which is "UTC" in an image that ships no zoneinfo.
func serverZone() (string, int) {
	now := time.Now()
	_, offset := now.Zone()
	name := time.Local.String()
	if tz := os.Getenv("TZ"); tz != "" {
		name = tz
	}
	if name == "" || name == "Local" {
		// Not something Intl can resolve; the offset carries it instead.
		name = ""
	}
	return name, offset
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	u := auth.CurrentUser(r.Context())
	if u == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	perms, err := s.auth.GrantedPermissions(r.Context(), u)
	if err != nil {
		http.Error(w, "load permissions: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if perms == nil {
		perms = []string{}
	}
	persona := "Default Persona"
	if u.IsAdmin {
		persona = "Administrator"
	} else if names, rerr := s.store.RoleNamesForUser(r.Context(), u.ID); rerr == nil && len(names) > 0 {
		persona = strings.Join(names, ", ")
	}
	signedInAt, previousSignIn := "", ""
	if u.LastSignIn != nil {
		signedInAt = u.LastSignIn.UTC().Format(time.RFC3339)
	}
	if u.PreviousSignIn != nil {
		previousSignIn = u.PreviousSignIn.UTC().Format(time.RFC3339)
	}
	zone, offset := serverZone()
	writeJSONResponse(w, meResponse{
		Username: u.Username, DisplayName: u.DisplayName, Source: u.Source,
		IsAdmin: u.IsAdmin, Permissions: perms, LogoURL: s.logoURL(),
		Email: u.Email, Persona: persona,
		SignedInAt: signedInAt, PreviousSignIn: previousSignIn,
		ServerTimeZone: zone, ServerUTCOffsetSeconds: offset,
	})
}

func writeJSONResponse(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

type agentsPayload struct {
	Agents []store.AgentRecord `json:"agents"`
	// ServingVersion is the agent build this server hands out, which is
	// what "behind" means: the fleet's own newest version is not it when
	// no endpoint has updated yet.
	ServingVersion string `json:"serving_version"`
}

func encodeAgents(agents []store.AgentRecord) ([]byte, error) {
	if agents == nil {
		agents = []store.AgentRecord{}
	}
	return json.Marshal(agentsPayload{Agents: agents, ServingVersion: version.Agent()})
}

func (s *Server) handleListAgents(w http.ResponseWriter, r *http.Request) {
	agents, err := s.store.ListAgents(r.Context(), s.staleAfter())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	payload, err := encodeAgents(agents)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(payload)
}

// handleAgentsStream is the SSE feed backing the console's live endpoint
// list. On connect it sends the current snapshot immediately, then relays
// every subsequent broadcast from the agent hub (triggered by registration,
// heartbeat, facts, and the periodic staleness sweep).
func (s *Server) handleAgentsStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	setSSEHeaders(w)

	agents, err := s.store.ListAgents(r.Context(), s.staleAfter())
	if err == nil {
		if payload, err := encodeAgents(agents); err == nil {
			writeSSE(w, payload)
			flusher.Flush()
		}
	}

	ch := s.agentHub.Subscribe()
	defer s.agentHub.Unsubscribe(ch)

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case payload := <-ch:
			writeSSE(w, payload)
			flusher.Flush()
		}
	}
}

type startQueryRequest struct {
	Kind    string `json:"kind"`               // facts (default) | processes | services | installed_apps
	AgentID string `json:"agent_id,omitempty"` // target one agent instead of the fleet
	OS      string `json:"os,omitempty"`       // predicate: narrow to this OS (ignored if AgentID set)
	Site    string `json:"site,omitempty"`     // predicate: narrow to this site (ignored if AgentID set)
}

type startQueryResponse struct {
	QueryID  string `json:"query_id"`
	Expected int    `json:"expected"`
}

var validQueryKinds = map[proto.QueryKind]bool{
	proto.QueryKindFacts:         true,
	proto.QueryKindProcesses:     true,
	proto.QueryKindServices:      true,
	proto.QueryKindInstalledApps: true,
	proto.QueryKindPatches:       true,
}

// handleStartQuery issues a live query/sensor read: the fixed, safe kinds
// in proto.QueryKind — no arbitrary code execution on agents yet, see
// docs/ROADMAP.md. Defaults to facts against the whole fleet if the body is
// empty, for backward compatibility with the original query button.
func (s *Server) handleStartQuery(w http.ResponseWriter, r *http.Request) {
	var req startQueryRequest
	if r.ContentLength != 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
			return
		}
	}
	kind := proto.QueryKind(req.Kind)
	if kind == "" {
		kind = proto.QueryKindFacts
	}
	if !validQueryKinds[kind] {
		http.Error(w, "unknown query kind: "+string(kind), http.StatusBadRequest)
		return
	}
	// Facts are the endpoint's identity; the other kinds are sensors of
	// the same name.
	if kind != proto.QueryKindFacts && !s.requireSensor(w, r, string(kind)) {
		return
	}

	agents, err := s.store.ListAgents(r.Context(), s.staleAfter())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var (
		targetSubject string
		predicate     *proto.Predicate
		expected      int
	)
	if req.AgentID != "" {
		targetSubject = bnats.QAgent(req.AgentID)
		expected = 1
	} else {
		targetSubject = bnats.QAll()
		if req.OS != "" || req.Site != "" {
			predicate = &proto.Predicate{OS: req.OS, Site: req.Site}
		}
		for _, a := range agents {
			if !a.Online {
				continue
			}
			if req.OS != "" && a.OS != req.OS {
				continue
			}
			if req.Site != "" && a.Site != req.Site {
				continue
			}
			expected++
		}
	}

	aq, err := s.queryMgr.Start(kind, predicate, targetSubject, expected)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	payload, err := json.Marshal(startQueryResponse{QueryID: aq.ID, Expected: aq.Expected})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(payload)
}

// handleQueryStream streams live results for one query as they arrive.
func (s *Server) handleQueryStream(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	aq, ok := s.queryMgr.Get(id)
	if !ok {
		http.Error(w, "query not found or expired", http.StatusNotFound)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	setSSEHeaders(w)

	if payload, err := json.Marshal(aq.snapshot()); err == nil {
		writeSSE(w, payload)
		flusher.Flush()
	}

	ch := aq.hub.Subscribe()
	defer aq.hub.Unsubscribe(ch)
	streamQuerySnapshots(r.Context(), aq, ch, queryStreamInterval, func(payload []byte) {
		writeSSE(w, payload)
		flusher.Flush()
	})
}

// queryStreamInterval is the most often a live query's stream sends a new
// snapshot. Each snapshot carries every result so far, so sending one per
// arriving result made a query's stream O(fleet²) bytes; a few a second is
// as live as the console's counter needs to be.
const queryStreamInterval = 250 * time.Millisecond

// streamQuerySnapshots sends aq's current snapshot after each notification
// on ch, at most once per interval, until ctx ends. Notifications that pile
// up meanwhile — or are dropped by the hub because ch is full — are all
// covered by the next snapshot, which is read after they are drained, so
// the last result to arrive is always sent.
func streamQuerySnapshots(ctx context.Context, aq *activeQuery, ch <-chan []byte, interval time.Duration, send func([]byte)) {
	last := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ch:
		}
		if wait := interval - time.Since(last); wait > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(wait):
			}
		}
	drain:
		for {
			select {
			case <-ch:
			default:
				break drain
			}
		}
		payload, err := json.Marshal(aq.snapshot())
		if err != nil {
			continue
		}
		send(payload)
		last = time.Now()
	}
}

type sensorDataResponse struct {
	AgentID     string          `json:"agent_id"`
	Sensor      string          `json:"sensor"`
	CollectedAt string          `json:"collected_at"`
	Data        json.RawMessage `json:"data"`
}

// handleGetCachedSensor returns the last known snapshot for one agent's
// sensor without triggering a live query — this is what backs the console
// showing "current" processes/services/apps instantly, relying on the
// periodic sensor loop having kept it fresh (default every 15 minutes,
// adjustable — see handleSetSensorInterval).
func (s *Server) handleGetCachedSensor(w http.ResponseWriter, r *http.Request) {
	if !s.requireSensor(w, r, r.PathValue("kind")) {
		return
	}
	rec, err := s.store.GetSensorData(r.Context(), r.PathValue("id"), r.PathValue("kind"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if rec == nil {
		http.Error(w, "no cached data yet for this sensor", http.StatusNotFound)
		return
	}
	writeJSONResponse(w, sensorDataResponse{
		AgentID:     rec.AgentID,
		Sensor:      rec.Sensor,
		CollectedAt: rec.CollectedAt.UTC().Format("2006-01-02T15:04:05.000Z"),
		Data:        rec.Data,
	})
}

const (
	minSensorIntervalSeconds = 5
	maxSensorIntervalSeconds = 24 * 60 * 60
)

// sensorNamePattern is the shape of a built-in or custom sensor key.
var sensorNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_.:-]{0,63}$`)

type setSensorIntervalRequest struct {
	Sensor          string `json:"sensor" api:"required"`
	IntervalSeconds int    `json:"interval_seconds" api:"required"`
}

// handleSetSensorInterval is the "changed on the fly" half of the sensor
// refresh story: sends an AgentCommand over mustra.cmd.<id> (request/reply)
// so a running agent adjusts one sensor's periodic publish interval without
// a restart. A one-time immediate refresh is just a live query and doesn't
// go through this path.
func (s *Server) handleSetSensorInterval(w http.ResponseWriter, r *http.Request) {
	var req setSensorIntervalRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
		http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	// Bounded on both sides: five seconds on every sensor floods the bus
	// and the database, and a value of years silences the endpoint.
	if req.IntervalSeconds < minSensorIntervalSeconds || req.IntervalSeconds > maxSensorIntervalSeconds {
		http.Error(w, fmt.Sprintf("interval_seconds must be between %d and %d", minSensorIntervalSeconds, maxSensorIntervalSeconds), http.StatusBadRequest)
		return
	}
	if !sensorNamePattern.MatchString(req.Sensor) {
		http.Error(w, "unknown sensor", http.StatusBadRequest)
		return
	}
	agentID := r.PathValue("id")
	if err := s.auditStrict(r.Context(), auditEvent{
		Action: "agent.sensor_interval", Actor: auth.CurrentUser(r.Context()).Username,
		Target: req.Sensor, AgentID: agentID, Severity: "notice",
		Detail: map[string]any{"interval_seconds": req.IntervalSeconds},
	}); err != nil {
		http.Error(w, "the change could not be recorded in the audit log, so it was not sent", http.StatusServiceUnavailable)
		return
	}
	cmd := proto.AgentCommand{Cmd: "set_sensor_interval", Sensor: proto.SensorKind(req.Sensor), IntervalSeconds: req.IntervalSeconds}
	payload, err := json.Marshal(cmd)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	rctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	msg, err := s.nc.RequestWithContext(rctx, bnats.Cmd(agentID), payload)
	if err != nil {
		http.Error(w, "agent did not respond (offline, or NATS command subject unreachable): "+err.Error(), http.StatusGatewayTimeout)
		return
	}
	var result proto.AgentCommandResult
	if err := json.Unmarshal(msg.Data, &result); err != nil {
		http.Error(w, "malformed response from agent: "+err.Error(), http.StatusBadGateway)
		return
	}
	if !result.OK {
		http.Error(w, "agent rejected the command: "+result.Error, http.StatusBadRequest)
		return
	}
	writeJSONResponse(w, result)
}

func setSSEHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
}

func writeSSE(w http.ResponseWriter, payload []byte) {
	w.Write([]byte("data: "))
	w.Write(payload)
	w.Write([]byte("\n\n"))
}

// handleHealthz is the readiness probe. It checks Postgres because that is
// the dependency whose loss makes every other route fail: NATS going away
// degrades the fleet but leaves the console readable, while a dead database
// means nothing works. Plain text and a status code, so `wget --spider` in
// a healthcheck is enough to read it.
func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		http.Error(w, "not ready", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	if err := s.store.Ping(ctx); err != nil {
		http.Error(w, "database unreachable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}
