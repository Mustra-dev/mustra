package server

import (
	"github.com/mustra-dev/mustra/internal/deploylog"
	"github.com/mustra-dev/mustra/internal/impact"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/store"
)

// routeDoc describes what a route accepts and returns, for the OpenAPI
// spec. Types are given as zero values; the spec reflects on them. A
// route without one is described generically (any JSON object in and
// out), so declarations can be added a few routes at a time; the drift
// test (openapi_drift_test.go) checks each one against its handler's
// source and counts the routes still missing one.
type routeDoc struct {
	Body any // JSON request body type, e.g. setSensorIntervalRequest{}
	// BodyOptional: a request without the body is accepted (a fleet-wide
	// rescan sends none; a restore by ?id= uploads nothing).
	BodyOptional bool
	// Required are body fields this route requires on top of those its
	// type tags api:"required": for a type shared with routes that do not
	// (a sensor's save requires a name, its test run does not).
	Required []string
	NoBody   bool         // POST/PUT/PATCH that reads no body (run, refresh, revoke…)
	Upload   []formField  // multipart/form-data fields instead of a JSON body
	Raw      string       // media type of a body read as raw bytes instead of JSON
	Query    []queryParam // query parameters the handler reads
	Resp     any          // JSON success response type; nil with Status 204
	// RespAlt are other JSON bodies the success answer can be, when the
	// handler answers differently by case (a plan or a started run).
	RespAlt []any
	Status  int    // success status when not 200 (204, 201, 202)
	Also    []int  // other success statuses, e.g. 202 when an approval policy parks the request
	Content string // non-JSON success body: "text/event-stream", "text/csv", …
	Errors  []int  // error statuses the handler returns (text/plain)
	// ErrorBody is the JSON body of an error status the handler answers
	// with JSON rather than text, e.g. 422 with validation details.
	ErrorBody map[int]any
	DriftOK   string // why the drift test skips this route; expected to be rare
}

type queryParam struct {
	Name     string
	Type     string // "string" (the default), "integer" or "boolean"; a flag compared to "1" is Enum: ["1"]
	Enum     []string
	Required bool
	Desc     string
}

type formField struct {
	Name     string
	File     bool // a file part, rather than a text value
	Required bool
	Desc     string
}

// flag is a query parameter that is on when it is "1".
func flag(name, desc string) queryParam {
	return queryParam{Name: name, Enum: []string{"1"}, Desc: desc}
}

// routeDocs is keyed by the exact pattern registered in httpapi.go, and
// grouped by the spec's tags. A handler that serves several routes is
// declared for all of them or none: the drift test checks its source
// against every declaration at once.
var routeDocs = map[string]routeDoc{
	// about
	"GET /api/about": {Resp: aboutResponse{}},

	// access
	"GET /api/access/me": {Resp: myAccessResponse{}, Errors: []int{500}},

	// action-groups
	"GET /api/action-groups":             {Resp: listActionGroupsResponse{}, Errors: []int{500}},
	"POST /api/action-groups":            {Body: store.ActionGroup{}, Resp: store.ActionGroup{}, Errors: []int{400, 500}},
	"DELETE /api/action-groups/{module}": {Status: 204, Errors: []int{500}},

	// agent-identities
	"GET /api/agent-identities": {Resp: listAgentIdentitiesResponse{}, Errors: []int{500}},

	// agent-trust
	"GET /api/agent-trust": {Resp: agentTrustSettings{}},
	"PUT /api/agent-trust": {Body: putAgentTrustRequest{}, Resp: agentTrustSettings{}, Errors: []int{400, 403, 409, 500}},

	// agent-versions
	"GET /api/agent-versions": {Resp: recentAgentVersionsResponse{}, Errors: []int{500}},

	// agents
	"GET /api/agents":                         {Resp: agentsPayload{}, Errors: []int{500}},
	"GET /api/agents/stream":                  {Content: "text/event-stream", Errors: []int{500}},
	"POST /api/agents/update-outdated":        {NoBody: true, Resp: updateAgentsResponse{}, Errors: []int{404, 500}},
	"DELETE /api/agents/{id}":                 {Status: 204, Errors: []int{400, 404, 500}},
	"GET /api/agents/{id}/actions":            {Resp: agentActionsResponse{}, Errors: []int{500}},
	"POST /api/agents/{id}/apply-patches":     {Body: applyPatchesRequest{}, BodyOptional: true, Resp: applyPatchesResponse{}, Errors: []int{400, 403, 404, 409, 500, 502}},
	"GET /api/agents/{id}/attributes":         {Resp: agentAttributesView{}, Errors: []int{500}},
	"PUT /api/agents/{id}/attributes":         {Body: map[string]string{}, Resp: agentAttributesResponse{}, Errors: []int{400, 500}},
	"POST /api/agents/{id}/intune/{action}":   {NoBody: true, Resp: intuneActionResponse{}, Errors: []int{400, 404, 409, 422, 500}},
	"POST /api/agents/{id}/kill-process":      {Body: killProcessRequest{}, Resp: killProcessResponse{}, Errors: []int{400, 404, 500, 502, 504}},
	"POST /api/agents/{id}/managed":           {Body: setAgentManagedRequest{}, Resp: setAgentManagedResponse{}, Errors: []int{400, 500}},
	"POST /api/agents/{id}/revoke-credential": {NoBody: true, Resp: revokeAgentCredentialResponse{}, Errors: []int{400, 404, 500}},
	"POST /api/agents/{id}/sensor-interval":   {Body: setSensorIntervalRequest{}, Resp: proto.AgentCommandResult{}, Errors: []int{400, 500, 502, 503, 504}},
	"GET /api/agents/{id}/sensor/{kind}":      {Resp: sensorDataResponse{}, Errors: []int{403, 404, 500}},
	"POST /api/agents/{id}/update":            {NoBody: true, Query: []queryParam{flag("allow_downgrade", "install the served build even when the endpoint runs a newer one")}, Resp: updateAgentsResponse{}, Errors: []int{404, 500}},
	"GET /api/agents/{id}/versions":           {Resp: agentVersionHistoryResponse{}, Errors: []int{500}},

	// approval-policies
	"GET /api/approval-policies":         {Resp: listApprovalPoliciesResponse{}, Errors: []int{500}},
	"POST /api/approval-policies":        {Body: saveApprovalPolicyRequest{}, Resp: store.ApprovalPolicy{}, Errors: []int{400, 404, 500}},
	"PUT /api/approval-policies/{id}":    {Body: saveApprovalPolicyRequest{}, Resp: store.ApprovalPolicy{}, Errors: []int{400, 404, 500}},
	"DELETE /api/approval-policies/{id}": {Status: 204, Errors: []int{404, 500}},

	// approvals
	"GET /api/approvals":              {Query: []queryParam{{Name: "state", Desc: "only requests in this state; all when empty"}}, Resp: listApprovalRequestsResponse{}, Errors: []int{500}},
	"POST /api/approvals/{id}/decide": {Body: decideApprovalRequest{}, Resp: decideApprovalResponse{}, Errors: []int{400, 403, 404, 409, 500}},

	// approve-info
	"GET /api/approve-info": {Query: []queryParam{{Name: "id", Required: true, Desc: "the request's ID"}, {Name: "kind", Required: true, Enum: []string{"jump", "approval", "playbook", "cert"}}}, Resp: approveInfo{}, Errors: []int{400, 403, 404}},

	// asset-attributes
	"GET /api/asset-attributes":                   {Resp: listAssetAttributesResponse{}, Errors: []int{500}},
	"POST /api/asset-attributes":                  {Body: store.AssetAttribute{}, Resp: store.AssetAttribute{}, Errors: []int{400, 404, 409, 500}},
	"POST /api/asset-attributes/lifecycle-preset": {NoBody: true, Resp: lifecyclePresetResponse{}, Errors: []int{500}},
	"PUT /api/asset-attributes/{id}":              {Body: store.AssetAttribute{}, Resp: store.AssetAttribute{}, Errors: []int{400, 404, 409, 500}},
	"DELETE /api/asset-attributes/{id}":           {Status: 204, Errors: []int{404, 500}},

	// assets
	"POST /api/assets/purge-after": {Body: setPurgeAfterRequest{}, Resp: setPurgeAfterResponse{}, Errors: []int{400, 500}},

	// audit
	"GET /api/audit": {Query: []queryParam{{Name: "action", Desc: "only actions starting with this, e.g. agent."}, {Name: "actor", Desc: "only this user"}, {Name: "limit", Type: "integer", Desc: "at most this many, 1–5000 (300 when absent)"}, {Name: "since", Desc: "only events after this time (RFC 3339), for incremental export"}}, Resp: auditEventsResponse{}, Errors: []int{500}},

	// backup-status
	"GET /api/backup-status":           {Query: []queryParam{{Name: "agent_id", Desc: "only this endpoint"}}, Resp: backupsResponse{}, RespAlt: []any{backupGuestsResponse{}}, Errors: []int{500}},
	"POST /api/backup-status/settings": {Body: backupSettingsRequest{}, Status: 204, Errors: []int{400, 500}},

	// threats
	"GET /api/threats":         {Resp: threatsResponse{}, Errors: []int{500}},
	"POST /api/threats":        {Body: saveThreatRequest{}, Resp: store.ThreatBrief{}, Errors: []int{400, 500}},
	"GET /api/threats/{id}":    {Resp: threatDetail{}, Errors: []int{404, 500}},
	"PUT /api/threats/{id}":    {Body: saveThreatRequest{}, Resp: store.ThreatBrief{}, Errors: []int{400, 404, 500}},
	"DELETE /api/threats/{id}": {Resp: deleteThreatResponse{}, Errors: []int{404, 500}},
	"GET /api/threat-settings": {Resp: threatSettingsResponse{}},
	"PUT /api/threat-settings": {Body: threatAutoRemediation{}, Resp: threatSettingsResponse{}, Errors: []int{400, 500}},

	"GET /api/telemetry":       {Resp: telemetryResponse{}},
	"PUT /api/telemetry":       {Body: telemetrySettings{}, Resp: telemetryResponse{}, Errors: []int{400, 500}},
	"POST /api/telemetry/test": {NoBody: true, Resp: telemetryTestResponse{}, Errors: []int{400}},

	// backup-sources
	"GET /api/backup-sources":            {Resp: listBackupSourcesResponse{}, Errors: []int{500}},
	"POST /api/backup-sources":           {Body: saveBackupSourceRequest{}, Resp: backupSourceView{}, Errors: []int{400, 500}},
	"PUT /api/backup-sources/{id}":       {Body: saveBackupSourceRequest{}, Resp: backupSourceView{}, Errors: []int{400, 404, 500}},
	"DELETE /api/backup-sources/{id}":    {Resp: deleteBackupSourceResponse{}, Errors: []int{404, 500}},
	"POST /api/backup-sources/{id}/poll": {NoBody: true, Resp: backupSourceView{}, Errors: []int{404, 500}},

	// backups
	"GET /api/backups":  {Resp: listBackupsResponse{}, Errors: []int{500}},
	"POST /api/backups": {Body: createBackupRequest{}, BodyOptional: true, Resp: BackupRecord{}, Errors: []int{500}},
	"POST /api/backups/restore": {Upload: []formField{{Name: "file", File: true, Desc: "a backup archive (.tar.gz), when not restoring one on the server by id"}}, BodyOptional: true,
		Query: []queryParam{
			{Name: "confirm", Required: true, Enum: []string{"replace-everything"}, Desc: "a restore replaces the whole database"},
			{Name: "id", Desc: "restore this backup, already on the server, instead of an upload"},
			flag("external", "the archive was not made by this server (administrators only)"),
		}, Resp: RestoreResult{}, Errors: []int{400, 403, 422, 428, 500, 503}},
	"PUT /api/backups/settings":      {Body: BackupSettings{}, Resp: BackupSettings{}, Errors: []int{400, 500}},
	"DELETE /api/backups/{id}":       {Resp: deleteBackupResponse{}, Errors: []int{404, 500}},
	"GET /api/backups/{id}/download": {Content: "application/gzip", Errors: []int{404}},

	// branding
	"POST /api/admin/branding": {Body: updateBrandingRequest{}, Resp: updateBrandingResponse{}, Errors: []int{400, 500}},

	// catalog
	"GET /api/catalog/requests":              {Resp: []store.CatalogRequest{}, Errors: []int{500}},
	"POST /api/catalog/requests/{id}/decide": {Body: decideCatalogRequestRequest{}, Resp: decideCatalogRequestResponse{}, Errors: []int{400, 404, 409, 500}},

	// cert-authorities
	"POST /api/admin/cert-authorities": {Body: saveCertAuthoritiesRequest{}, Resp: listManagedCertsResponse{}, Errors: []int{400, 403, 500}},

	// containers
	"GET /api/containers": {Query: []queryParam{{Name: "agent_id", Desc: "only this endpoint"}, {Name: "update", Enum: []string{proto.ContainerUpdateAvailable, proto.ContainerUpToDate, proto.ContainerNotChecked, proto.ContainerCheckFailed}, Desc: "only containers with this update status"}}, Resp: containersResponse{}, Errors: []int{400, 500}},

	// certificates
	"GET /api/certificates":                                {Resp: certificatesResponse{}, Errors: []int{500}},
	"GET /api/certificates/alerts":                         {Resp: getExpiryAlertsResponse{}},
	"POST /api/certificates/alerts":                        {Body: saveExpiryAlertsRequest{}, Resp: saveExpiryAlertsResponse{}, Errors: []int{400, 500}},
	"POST /api/certificates/alerts/test":                   {NoBody: true, Resp: testExpiryAlertResponse{}},
	"GET /api/certificates/apps":                           {Resp: listAppCredsResponse{}, Errors: []int{500}},
	"POST /api/certificates/apps/connections":              {Required: []string{"kind", "secret"}, Body: connBody{}, Resp: saveAppCredConnectionResponse{}, Errors: []int{400, 404, 500}},
	"PUT /api/certificates/apps/connections/{id}":          {Body: connBody{}, Resp: saveAppCredConnectionResponse{}, Errors: []int{400, 404, 500}},
	"DELETE /api/certificates/apps/connections/{id}":       {Status: 204, Errors: []int{500}},
	"GET /api/certificates/apps/connections/{id}/discover": {Resp: discoverAppCredsResponse{}, Errors: []int{422, 502}},
	"POST /api/certificates/apps/credentials":              {Required: []string{"cred_type", "app_name"}, Body: credBody{}, Resp: store.AppCredential{}, Errors: []int{400, 404, 500}},
	"PUT /api/certificates/apps/credentials/{id}":          {Body: credBody{}, Resp: store.AppCredential{}, Errors: []int{400, 404, 500}},
	"DELETE /api/certificates/apps/credentials/{id}":       {Status: 204, Errors: []int{500}},
	"GET /api/certificates/apps/credentials/{id}/download": {Content: "application/octet-stream", Errors: []int{404, 410, 500}},
	"POST /api/certificates/apps/credentials/{id}/renew":   {NoBody: true, Resp: store.AppCredential{}, Errors: []int{422}},
	"GET /api/certificates/ca.crt":                         {Content: "application/x-x509-ca-cert", Errors: []int{500}},
	"GET /api/certificates/coverage":                       {Resp: certificateCoverageResponse{}, Errors: []int{500}},
	"GET /api/certificates/issued":                         {Resp: listIssuedResponse{}, Errors: []int{500}},
	"POST /api/certificates/issued/{id}/revoke":            {Body: revokeRequest{}, Resp: revokeIssuedResponse{}, Errors: []int{400, 404, 422, 500}},
	"GET /api/certificates/managed":                        {Resp: listManagedCertsResponse{}, Errors: []int{500}},
	"POST /api/certificates/managed":                       {Body: store.ManagedCert{}, Query: []queryParam{flag("issue", "also issue the certificate now")}, Resp: store.ManagedCert{}, Errors: []int{400, 404, 409, 500}},
	"PUT /api/certificates/managed/{id}":                   {Body: store.ManagedCert{}, Query: []queryParam{flag("issue", "also issue the certificate now")}, Resp: store.ManagedCert{}, Errors: []int{400, 404, 409, 500}},
	"DELETE /api/certificates/managed/{id}":                {Status: 204, Errors: []int{500}},
	"POST /api/certificates/managed/{id}/renew":            {NoBody: true, Resp: store.ManagedCert{}, Errors: []int{422}},
	"POST /api/certificates/managed/{id}/upload":           {Body: uploadBody{}, Resp: store.ManagedCert{}, Errors: []int{400, 404, 409, 422}},
	"GET /api/certificates/trust":                          {Resp: listTrustRootsResponse{}, Errors: []int{500}},
	"POST /api/certificates/trust/{id}":                    {Body: setTrustRootRequest{}, Resp: listTrustRootsResponse{}, Errors: []int{400, 404, 500}},
	"POST /api/certificates/upload/preview":                {Body: uploadBody{}, Resp: previewUploadResponse{}, Errors: []int{400}},
	"GET /api/certificates/{fingerprint}":                  {Resp: certificateResponse{}, Errors: []int{404, 500}},

	// clients
	"GET /api/clients/health":           {Query: []queryParam{{Name: "group", Desc: "only endpoints in this computer group"}}, Resp: clientHealthResponse{}, Errors: []int{500}},
	"GET /api/clients/profiles":         {Resp: listClientProfilesResponse{}, Errors: []int{500}},
	"POST /api/clients/profiles":        {Body: store.ClientProfile{}, Resp: saveClientProfileResponse{}, Errors: []int{400, 404, 500}},
	"POST /api/clients/profiles/apply":  {NoBody: true, Query: []queryParam{{Name: "profile", Desc: "apply only this profile; all when empty"}}, Resp: applyClientProfilesResponse{}},
	"PUT /api/clients/profiles/{id}":    {Body: store.ClientProfile{}, Resp: saveClientProfileResponse{}, Errors: []int{400, 404, 500}},
	"DELETE /api/clients/profiles/{id}": {Status: 204, Errors: []int{500}},
	"GET /api/clients/status":           {Query: []queryParam{{Name: "format", Enum: []string{"csv"}, Desc: "csv for a CSV download instead of JSON"}}, Resp: clientStatusResponse{}, Content: "text/csv", Errors: []int{500}},
	"POST /api/clients/upgrade":         {Body: upgradeRingRequest{}, BodyOptional: true, Resp: upgradeRingResponse{}, Errors: []int{500}},

	// compliance
	"GET /api/compliance/exceptions":         {Resp: listComplianceExceptionsResponse{}, Errors: []int{500}},
	"POST /api/compliance/exceptions":        {Body: createComplianceExceptionRequest{}, Resp: store.ComplianceException{}, Errors: []int{400, 500}},
	"DELETE /api/compliance/exceptions/{id}": {Status: 204, Errors: []int{404, 500}},
	"POST /api/compliance/import": {
		Raw: "application/yaml",
		Query: []queryParam{
			{Name: "name", Desc: "the policy's name; \"Imported policy\" when empty"},
			{Name: "os", Desc: "linux, windows or darwin; inferred from the policy when empty"},
		},
		Resp:   importPolicyResponse{},
		Errors: []int{400, 500},
	},
	"GET /api/compliance/policies":           {Resp: listPoliciesResponse{}, Errors: []int{500}},
	"DELETE /api/compliance/policies/{id}":   {Status: 204, Errors: []int{400, 500}},
	"POST /api/compliance/policies/{id}/run": {NoBody: true, Resp: runComplianceResponse{}, Errors: []int{400, 404, 500}},
	"GET /api/compliance/report.csv":         {Query: []queryParam{{Name: "agent_id", Desc: "only this endpoint"}, {Name: "policy_id", Desc: "only this policy"}}, Content: "text/csv", Errors: []int{500}},
	"GET /api/compliance/results":            {Resp: complianceResultsResponse{}, Errors: []int{500}},
	"GET /api/compliance/controls":           {Query: controlsQueryParams, Resp: complianceControlsResponse{}, Errors: []int{500}},
	"GET /api/compliance/controls.csv":       {Query: controlsQueryParams, Content: "text/csv", Errors: []int{500}},
	"POST /api/compliance/scan":              {Body: scanBenchmarksRequest{}, BodyOptional: true, Resp: scanBenchmarksResponse{}, Errors: []int{500}},
	"GET /api/compliance/scores":             {Query: []queryParam{{Name: "agent_id", Desc: "only this endpoint"}}, Resp: complianceScoresResponse{}, Errors: []int{500}},
	"POST /api/compliance/settings":          {Body: complianceSettingsRequest{}, Status: 204, Errors: []int{400, 500}},

	// confidence
	"GET /api/confidence":         {Resp: confidenceResponse{}, Errors: []int{500}},
	"GET /api/confidence/patches": {Resp: confidence{}, Errors: []int{500}},

	// connect
	"GET /api/connect/exports":           {Resp: listExportsResponse{}, Errors: []int{500}},
	"POST /api/connect/exports":          {Body: exportBody{}, Resp: exportView{}, Errors: []int{400, 404, 500}},
	"PUT /api/connect/exports/{id}":      {Body: exportBody{}, Resp: exportView{}, Errors: []int{400, 404, 500}},
	"DELETE /api/connect/exports/{id}":   {Status: 204, Errors: []int{500}},
	"POST /api/connect/exports/{id}/run": {NoBody: true, Resp: runExportResponse{}, Errors: []int{404, 500}},

	// content-sets
	"GET /api/content-sets":         {Resp: listContentSetsResponse{}, Errors: []int{500}},
	"POST /api/content-sets":        {Body: store.ContentSet{}, Resp: store.ContentSet{}, Errors: []int{400, 404, 500}},
	"PUT /api/content-sets/{id}":    {Body: store.ContentSet{}, Resp: store.ContentSet{}, Errors: []int{400, 404, 500}},
	"DELETE /api/content-sets/{id}": {Status: 204, Errors: []int{404, 500}},

	// dashboard-alerts
	"GET /api/dashboard-alerts":           {Resp: dashboardAlertsResponse{}, Errors: []int{500}},
	"POST /api/dashboard-alerts":          {Body: saveDashboardAlertRequest{}, Resp: store.DashboardAlert{}, Errors: []int{400, 404, 500}},
	"POST /api/dashboard-alerts/evaluate": {NoBody: true, Resp: dashboardAlertsResponse{}, Errors: []int{500}},
	"PUT /api/dashboard-alerts/{id}":      {Body: saveDashboardAlertRequest{}, Resp: store.DashboardAlert{}, Errors: []int{400, 404, 500}},
	"DELETE /api/dashboard-alerts/{id}":   {Status: 204, Errors: []int{404, 500}},

	// dashboards
	"GET /api/dashboards":             {Resp: listDashboardsResponse{}, Errors: []int{500}},
	"POST /api/dashboards":            {Body: dashboardBody{}, Resp: store.Dashboard{}, Errors: []int{400, 403, 404, 500}},
	"GET /api/dashboards/columns":     {Query: []queryParam{{Name: "question", Desc: "a saved question's ID, for source=question"}, {Name: "source", Desc: "the data source to list columns for"}}, Resp: dashboardColumnsResponse{}, Errors: []int{400}},
	"POST /api/dashboards/preview":    {Body: dashboardPanel{}, Resp: panelData{}, Errors: []int{400}},
	"GET /api/dashboards/{id}":        {Resp: getDashboardResponse{}, Errors: []int{403, 404, 500}},
	"PUT /api/dashboards/{id}":        {Body: dashboardBody{}, Resp: store.Dashboard{}, Errors: []int{400, 403, 404, 500}},
	"DELETE /api/dashboards/{id}":     {Status: 204, Errors: []int{403, 404, 500}},
	"POST /api/dashboards/{id}/clone": {NoBody: true, Resp: store.Dashboard{}, Errors: []int{403, 404, 500}},
	"GET /api/dashboards/{id}/data":   {Query: []queryParam{{Name: "groups", Desc: "comma-separated computer group IDs to narrow the data to"}, flag("highlights", "only the highlight panels"), {Name: "range", Enum: []string{"24h", "7d", "30d", "90d"}, Desc: "the time window; 30d otherwise"}}, Resp: dashboardDataResponse{}, Errors: []int{403, 404, 500}},

	// deploy
	"POST /api/deploy/autoscan":                        {NoBody: true, Resp: deployAutoScanResponse{}, Errors: []int{400, 500}},
	"GET /api/deploy/credentials":                      {Resp: listCredentialsResponse{}, Errors: []int{500, 503}},
	"POST /api/deploy/credentials":                     {Body: createCredentialRequest{}, Resp: store.DeployCredential{}, Errors: []int{400, 500, 503}},
	"DELETE /api/deploy/credentials/{id}":              {Status: 204, Errors: []int{500, 503}},
	"GET /api/deploy/credentials/{id}/public-key":      {Resp: credentialPublicKeyResponse{}, Errors: []int{400, 503}},
	"GET /api/deploy/deployments":                      {Resp: listAgentDeploymentsResponse{}, Errors: []int{500}},
	"GET /api/deploy/jobs":                             {Query: []queryParam{{Name: "run_id", Desc: "only jobs of this deployment run"}}, Resp: deployJobsResponse{}, Errors: []int{500}},
	"POST /api/deploy/jobs/{job}/cancel":               {Body: cancelDeployRequest{}, Status: 204, Errors: []int{400, 404, 500}},
	"GET /api/deploy/jobs/{job}/log-sensor":            {Resp: deploylog.Result{}, Errors: []int{404, 500, 502, 503, 504}},
	"GET /api/deploy/jobs/{job}/logs":                  {Query: []queryParam{{Name: "before", Desc: "only lines before this time (RFC 3339), to page back"}, flag("download", "the logs as a zip file instead of JSON"), {Name: "search", Desc: "only lines containing this text"}}, Resp: deploylog.Result{}, Content: "application/zip", Errors: []int{400, 404, 500}},
	"PUT /api/deploy/packages/{id}":                    {Body: deployPackageMetadataRequest{}, Resp: store.SoftwarePackage{}, Errors: []int{400, 404, 500}},
	"POST /api/deploy/packages/{id}/convert-action":    {NoBody: true, Resp: convertActionResponse{}, Errors: []int{400, 500}},
	"POST /api/deploy/packages/{id}/import":            {Body: importDeployFileRequest{}, Resp: store.PackageFile{}, Errors: []int{400, 403, 404, 500, 502, 503}},
	"GET /api/deploy/packages/{id}/revisions":          {Resp: deployRevisionsResponse{}, Errors: []int{500}},
	"POST /api/deploy/packages/{id}/revisions":         {Body: deployRevisionsRequest{}, Resp: proto.DeployRevision{}, Errors: []int{400, 404, 500}, ErrorBody: map[int]any{400: map[string]any{}}},
	"POST /api/deploy/preview":                         {Body: deployRequest{}, Resp: deployPreviewResponse{}, Errors: []int{400, 401, 403, 404, 500}, ErrorBody: map[int]any{400: map[string]any{}}},
	"POST /api/deploy/push":                            {Body: pushRequest{}, Resp: pushResponse{}, Errors: []int{400, 404, 500, 503}, ErrorBody: map[int]any{409: map[string]any{}, 502: pushResponse{}}},
	"DELETE /api/deploy/revisions/{revision}":          {Resp: deleteDeployDraftResponse{}, Errors: []int{400, 404, 500}},
	"POST /api/deploy/revisions/{revision}/publish":    {Body: publishDeployRequest{}, BodyOptional: true, Resp: publishDeployResponse{}, Errors: []int{400, 404, 409, 500}, ErrorBody: map[int]any{400: map[string]any{}}},
	"GET /api/deploy/revisions/{revision}/references":  {Query: []queryParam{{Name: "replacement", Desc: "a published version of the package to check each reference against"}}, Resp: deployReferenceList{}, Errors: []int{400, 500}},
	"POST /api/deploy/revisions/{revision}/references": {Body: deployReferencesRequest{}, Resp: deployReferencesResponse{}, Errors: []int{400, 409, 500}},
	"POST /api/deploy/revisions/{revision}/retire":     {Body: retireDeployRequest{}, Status: 204, Errors: []int{400, 404, 409, 500}},
	"POST /api/deploy/run":                             {Body: deployRequest{}, Resp: deployRunResponse{}, Also: []int{202}, Errors: []int{400, 401, 403, 404, 500, 503}, ErrorBody: map[int]any{400: map[string]any{}}},
	"POST /api/deploy/scan":                            {Body: scanRequest{}, Resp: deployScanResponse{}, Errors: []int{400}},
	"GET /api/deploy/settings":                         {Resp: proto.DeploySettings{}, Errors: []int{500}},
	"PUT /api/deploy/settings":                         {Body: proto.DeploySettings{}, Resp: proto.DeploySettings{}, Errors: []int{400, 500}},
	"GET /api/deploy/templates":                        {Resp: listDeploymentTemplatesResponse{}, Errors: []int{500}},
	"POST /api/deploy/templates":                       {Body: store.DeploymentTemplate{}, Resp: saveDeploymentTemplateResponse{}, Errors: []int{400, 403, 404, 500}},
	"PUT /api/deploy/templates/{id}":                   {Body: store.DeploymentTemplate{}, Resp: saveDeploymentTemplateResponse{}, Errors: []int{400, 403, 404, 500}},
	"DELETE /api/deploy/templates/{id}":                {Status: 204, Errors: []int{500}},
	"POST /api/deploy/test":                            {Body: deployRequest{}, Resp: deployRunResponse{}, Also: []int{202}, Errors: []int{400, 401, 403, 404, 500, 503}, ErrorBody: map[int]any{400: map[string]any{}}},

	// deployment-plans
	"GET /api/deployment-plans":         {Resp: listPlansResponse{}, Errors: []int{500}},
	"POST /api/deployment-plans":        {Body: store.DeploymentPlan{}, Resp: store.DeploymentPlan{}, Errors: []int{400, 404, 500}},
	"PUT /api/deployment-plans/{id}":    {Body: store.DeploymentPlan{}, Resp: store.DeploymentPlan{}, Errors: []int{400, 404, 500}},
	"DELETE /api/deployment-plans/{id}": {Status: 204, Errors: []int{500}},

	// directory
	"GET /api/directory":       {Resp: directoryView{}, Errors: []int{500}},
	"POST /api/directory":      {Body: directoryUpdate{}, Resp: directoryView{}, Errors: []int{400, 500}},
	"POST /api/directory/sync": {NoBody: true, Resp: directoryView{}, Errors: []int{500, 502}},
	"POST /api/directory/test": {Body: directoryUpdate{}, Resp: directoryTestResponse{}, RespAlt: []any{directoryTestFailure{}}, Errors: []int{400, 500}},

	// discover
	"GET /api/discover":               {Resp: discoverResponse{}, Errors: []int{500}},
	"PUT /api/discover/devices/{mac}": {Body: updateNetworkDeviceRequest{}, Status: 204, Errors: []int{400, 404, 500}},
	"POST /api/discover/settings":     {Body: discoverSettingsRequest{}, Status: 204, Errors: []int{400, 500}},

	// enforce
	"POST /api/enforce/compile":                            {Body: enforceCompileRequest{}, Resp: enforceCompileResponse{}, Errors: []int{400}},
	"GET /api/enforce/coverage":                            {Resp: enforceCoverageResponse{}, Errors: []int{500}},
	"GET /api/enforce/kinds":                               {Resp: enforceKindsResponse{}},
	"GET /api/enforce/policies":                            {Resp: listEnforcePoliciesResponse{}, Errors: []int{500}},
	"POST /api/enforce/policies":                           {Body: enforcePolicyRequest{}, Resp: saveEnforcePolicyResponse{}, Errors: []int{400, 500}},
	"GET /api/enforce/policies/{id}":                       {Resp: getEnforcePolicyResponse{}, Errors: []int{404, 500}},
	"PUT /api/enforce/policies/{id}":                       {Body: enforcePolicyRequest{}, Resp: saveEnforcePolicyResponse{}, Errors: []int{400, 500}},
	"DELETE /api/enforce/policies/{id}":                    {Resp: deleteEnforcePolicyResponse{}, Errors: []int{404, 500}},
	"POST /api/enforce/policies/{id}/reset":                {NoBody: true, Resp: resetEnforcePolicyResponse{}, Errors: []int{404, 500}},
	"POST /api/enforce/policies/{id}/run":                  {Body: runEnforcePolicyRequest{}, BodyOptional: true, Resp: enforceRunSummary{}, Errors: []int{400, 404, 409, 500}},
	"GET /api/enforce/recovery-keys":                       {Query: []queryParam{{Name: "agent", Desc: "only this endpoint"}}, Resp: listRecoveryKeysResponse{}, Errors: []int{500}},
	"POST /api/enforce/recovery-keys/{agent}/{key}/reveal": {NoBody: true, Resp: revealRecoveryKeyResponse{}, Errors: []int{404, 500, 503}},
	"GET /api/enforce/results":                             {Query: []queryParam{{Name: "policy", Desc: "only this policy"}}, Resp: listEnforceResultsResponse{}, Errors: []int{500}},

	// enrollment-tokens
	"GET /api/enrollment-tokens":         {Resp: listEnrollTokensResponse{}, Errors: []int{500}},
	"POST /api/enrollment-tokens":        {Body: createEnrollTokenRequest{}, Resp: createEnrollTokenResponse{}, Errors: []int{400, 500}},
	"DELETE /api/enrollment-tokens/{id}": {Resp: revokeEnrollTokenResponse{}, Errors: []int{404, 500}},

	// entra
	"GET /api/admin/entra":       {Resp: entraConfigResponse{}},
	"POST /api/admin/entra":      {Body: saveEntraConfigRequest{}, Resp: entraConfigResponse{}, Errors: []int{400, 403, 500}},
	"POST /api/admin/entra/sync": {NoBody: true, Resp: entraSyncCounts{}, Errors: []int{422}},
	"GET /api/entra/devices":     {Query: []queryParam{{Name: "agent_id", Desc: "only this endpoint"}}, Resp: entraDevicesResponse{}, Errors: []int{500}},

	// eun
	"GET /api/eun":            {Resp: listEUNResponse{}, Errors: []int{500}},
	"POST /api/eun":           {Body: store.EUNMessage{}, Resp: store.EUNMessage{}, Errors: []int{400, 500}},
	"PUT /api/eun/{id}":       {Body: store.EUNMessage{}, Resp: store.EUNMessage{}, Errors: []int{400, 404, 500}},
	"DELETE /api/eun/{id}":    {Status: 204, Errors: []int{500}},
	"POST /api/eun/{id}/send": {Body: eunSendRequest{}, BodyOptional: true, Resp: sendEUNResponse{}, Errors: []int{400, 404, 500}},

	// file-events
	"GET /api/file-events": {Query: []queryParam{{Name: "agent", Desc: "only this endpoint"}, {Name: "limit", Type: "integer", Desc: "at most this many"}, {Name: "matched", Desc: "any value: only events that matched a rule"}}, Resp: listFileEventsResponse{}, Errors: []int{500}},

	// groups
	"GET /api/admin/groups":                           {Resp: listGroupsResponse{}, Errors: []int{500}},
	"POST /api/admin/groups":                          {Body: createGroupRequest{}, Resp: adminGroupView{}, Errors: []int{400, 500, 503}},
	"DELETE /api/admin/groups/{id}":                   {Status: 204, Errors: []int{500, 503}},
	"POST /api/admin/groups/{id}/members":             {Body: userIDRequest{}, Status: 204, Errors: []int{400, 403, 404, 500, 503}},
	"DELETE /api/admin/groups/{id}/members/{user_id}": {Status: 204, Errors: []int{403, 500, 503}},
	"POST /api/admin/groups/{id}/roles":               {Body: roleIDRequest{}, Status: 204, Errors: []int{400, 403, 500, 503}},
	"DELETE /api/admin/groups/{id}/roles/{role_id}":   {Status: 204, Errors: []int{500, 503}},
	"GET /api/groups":                                 {Resp: listComputerGroupsResponse{}, Errors: []int{500}},
	"POST /api/groups":                                {Body: upsertGroupRequest{}, Resp: store.ComputerGroup{}, Errors: []int{400, 403, 500}},
	"POST /api/groups/preview":                        {Body: previewGroupRequest{}, Resp: previewComputerGroupResponse{}, Errors: []int{400, 403, 500}},
	"PUT /api/groups/{id}":                            {Body: upsertGroupRequest{}, Resp: store.ComputerGroup{}, Errors: []int{400, 403, 500}},
	"DELETE /api/groups/{id}":                         {Resp: deleteComputerGroupResponse{}, Errors: []int{500}},
	"GET /api/groups/{id}/members":                    {Resp: getComputerGroupMembersResponse{}, Errors: []int{404, 500}},

	// guide
	"GET /api/help":                  {Resp: helpIndexResponse{}},
	"GET /api/help/{slug}":           {Resp: helpGuideResponse{}, Errors: []int{404}},
	"GET /api/guide":                 {Query: []queryParam{flag("all", "the last 30 days, resolved and dismissed items included")}, Resp: guideResponse{}, Errors: []int{500}},
	"POST /api/guide/refresh":        {NoBody: true, Query: []queryParam{flag("all", "the last 30 days, resolved and dismissed items included")}, Resp: guideResponse{}, Errors: []int{500}},
	"POST /api/guide/{id}/dismiss":   {NoBody: true, Status: 204, Errors: []int{404, 500}},
	"POST /api/guide/{id}/undismiss": {NoBody: true, Status: 204, Errors: []int{404, 500}},

	// health
	"GET /api/health": {Resp: healthResponse{}, Errors: []int{500}},

	// hunt
	"GET /api/hunt/findings":                  {Resp: listIOCFindingsResponse{}, Errors: []int{500}},
	"POST /api/hunt/findings/{id}/ack":        {Body: ackIOCFindingRequest{}, BodyOptional: true, Status: 204, Errors: []int{400, 500}},
	"GET /api/hunt/iocs":                      {Resp: listIOCsResponse{}, Errors: []int{500}},
	"POST /api/hunt/iocs":                     {Body: upsertIOCRequest{}, Resp: store.IOC{}, Errors: []int{400, 500}},
	"PUT /api/hunt/iocs/{id}":                 {Body: upsertIOCRequest{}, Resp: store.IOC{}, Errors: []int{400, 500}},
	"DELETE /api/hunt/iocs/{id}":              {Status: 204, Errors: []int{500}},
	"POST /api/hunt/run":                      {NoBody: true, Resp: runHuntResponse{}},
	"GET /api/hunt/signal-findings":           {Query: []queryParam{{Name: "limit", Type: "integer", Desc: "at most this many"}}, Resp: listSignalFindingsResponse{}, Errors: []int{500}},
	"POST /api/hunt/signal-findings/{id}/ack": {Body: ackSignalFindingRequest{}, BodyOptional: true, Status: 204, Errors: []int{400, 500}},
	"GET /api/hunt/signals":                   {Resp: listSignalsResponse{}, Errors: []int{500}},
	"POST /api/hunt/signals":                  {Body: store.Signal{}, Resp: saveSignalResponse{}, Errors: []int{400, 500}},
	"POST /api/hunt/signals/test":             {Body: testSignalRequest{}, Resp: testSignalResponse{}, Errors: []int{400}},
	"PUT /api/hunt/signals/{id}":              {Body: store.Signal{}, Resp: saveSignalResponse{}, Errors: []int{400, 500}},
	"DELETE /api/hunt/signals/{id}":           {Status: 204, Errors: []int{500}},

	// idnums
	"GET /api/idnums": {Resp: listIDNumbersResponse{}, Errors: []int{500}},

	// impact
	"GET /api/impact/object/{id}": {Resp: impact.Detail{}, Errors: []int{404, 500}},
	"GET /api/impact/overview":    {Query: []queryParam{flag("refresh", "recompute instead of using the cached analysis")}, Resp: impactOverviewResponse{}, Errors: []int{500}},
	"GET /api/impact/path":        {Query: []queryParam{{Name: "from", Required: true, Desc: "the starting node"}, {Name: "to", Required: true, Desc: "the target node"}}, Resp: impactPathResponse{}, Errors: []int{400, 500}},
	"POST /api/impact/recompute":  {NoBody: true, Status: 204, Errors: []int{500}},
	"GET /api/impact/search":      {Query: []queryParam{{Name: "q", Desc: "search text"}}, Resp: impactSearchResponse{}, Errors: []int{500}},
	"GET /api/impact/{kind}":      {Resp: impactRatingsResponse{}, RespAlt: []any{impactFindingsResponse{}}, Errors: []int{404, 500}},

	// integrations
	"GET /api/admin/integrations":            {Resp: listIntegrationsResponse{}, Errors: []int{500}},
	"POST /api/admin/integrations":           {Body: saveIntegrationRequest{}, Resp: listIntegrationsResponse{}, Errors: []int{400, 403, 500}},
	"PUT /api/admin/integrations/{id}":       {Body: saveIntegrationRequest{}, Resp: listIntegrationsResponse{}, Errors: []int{400, 403, 500}},
	"DELETE /api/admin/integrations/{id}":    {Status: 204, Errors: []int{403, 500}},
	"POST /api/admin/integrations/{id}/test": {NoBody: true, Resp: testIntegrationResponse{}, Errors: []int{404, 422, 500}},

	// integrity
	"GET /api/integrity":                     {Resp: integrityResponse{}, Errors: []int{500}},
	"POST /api/integrity/changes/{id}/ack":   {NoBody: true, Resp: ackIntegrityChangeResponse{}, Errors: []int{400, 500}},
	"GET /api/integrity/labels":              {Resp: listIntegrityLabelsResponse{}, Errors: []int{500}},
	"POST /api/integrity/labels":             {Required: []string{"name"}, Body: store.IntegrityLabel{}, Resp: store.IntegrityLabel{}, Errors: []int{400, 404, 500}},
	"POST /api/integrity/labels/test":        {Body: store.IntegrityLabel{}, Resp: testIntegrityLabelResponse{}, Errors: []int{400, 500}},
	"PUT /api/integrity/labels/{id}":         {Required: []string{"name"}, Body: store.IntegrityLabel{}, Resp: store.IntegrityLabel{}, Errors: []int{400, 404, 500}},
	"DELETE /api/integrity/labels/{id}":      {Status: 204, Errors: []int{404, 500}},
	"GET /api/integrity/monitors":            {Resp: listIntegrityMonitorsResponse{}, Errors: []int{500}},
	"POST /api/integrity/monitors":           {Body: store.IntegrityMonitor{}, Resp: store.IntegrityMonitor{}, Errors: []int{400, 404, 500}},
	"PUT /api/integrity/monitors/{id}":       {Body: store.IntegrityMonitor{}, Resp: store.IntegrityMonitor{}, Errors: []int{400, 404, 500}},
	"DELETE /api/integrity/monitors/{id}":    {Status: 204, Errors: []int{404, 500}},
	"GET /api/integrity/watch-status":        {Resp: watchStatusResponse{}, Errors: []int{500}},
	"POST /api/integrity/watch-status/apply": {NoBody: true, Resp: watchApplyResponse{}},

	// interact
	"POST /api/interact/ask":          {Body: questionRequest{}, Resp: questionResult{}, Errors: []int{400, 403, 500}},
	"GET /api/interact/history":       {Resp: questionHistoryResponse{}, Errors: []int{500}},
	"GET /api/interact/saved":         {Resp: listSavedQuestionsResponse{}, Errors: []int{500}},
	"POST /api/interact/saved":        {Body: store.SavedQuestion{}, Resp: store.SavedQuestion{}, Errors: []int{400, 403, 404, 500}},
	"DELETE /api/interact/saved/{id}": {Status: 204, Errors: []int{403, 404, 500}},

	// jump
	"GET /api/jump/grants":              {Query: []queryParam{{Name: "state", Desc: "only requests in this state; all when empty"}}, Resp: listJumpGrantsResponse{}, Errors: []int{500}},
	"POST /api/jump/grants/{id}/decide": {Body: decideJumpGrantRequest{}, Resp: decideJumpGrantResponse{}, Errors: []int{400, 403, 404, 409, 500}},
	"POST /api/jump/grants/{id}/revoke": {NoBody: true, Resp: revokeJumpGrantResponse{}, Errors: []int{404, 409, 500}},
	"GET /api/jump/policies":            {Resp: listJumpPoliciesResponse{}, Errors: []int{500}},
	"POST /api/jump/policies":           {Body: store.JumpPolicy{}, Resp: store.JumpPolicy{}, Errors: []int{400, 404, 500}},
	"PUT /api/jump/policies/{id}":       {Body: store.JumpPolicy{}, Resp: store.JumpPolicy{}, Errors: []int{400, 404, 500}},
	"DELETE /api/jump/policies/{id}":    {Status: 204, Errors: []int{404, 500}},
	"POST /api/jump/requests":           {Body: requestJumpAccessRequest{}, Resp: requestJumpAccessResponse{}, RespAlt: []any{jumpAlreadyGrantedResponse{}}, Errors: []int{400, 403, 404, 500}},

	// lifecycle
	"GET /api/lifecycle":     {Resp: lifecycleResponse{}, Errors: []int{500}},
	"GET /api/lifecycle.csv": {Content: "text/csv", Errors: []int{500}},

	// logging
	"GET /api/admin/logging":  {Resp: loggingSettings{}},
	"POST /api/admin/logging": {Body: updateLoggingRequest{}, Resp: loggingSettings{}, Errors: []int{400}},

	// maintenance-windows
	"GET /api/maintenance-windows":         {Resp: listMaintenanceWindowsResponse{}, Errors: []int{500}},
	"POST /api/maintenance-windows":        {Body: store.MaintenanceWindow{}, Resp: saveMaintenanceWindowResponse{}, Errors: []int{400, 404, 500}},
	"POST /api/maintenance-windows/check":  {Body: maintenanceWindowCheckRequest{}, Resp: maintenanceWindowCheckResponse{}, Errors: []int{400}},
	"PUT /api/maintenance-windows/{id}":    {Body: store.MaintenanceWindow{}, Resp: saveMaintenanceWindowResponse{}, Errors: []int{400, 404, 500}},
	"DELETE /api/maintenance-windows/{id}": {Status: 204, Errors: []int{404, 500}},

	// me
	"GET /api/me": {Resp: meResponse{}, Errors: []int{401, 500}},

	// notifications
	"GET /api/notifications":            {Resp: listNotificationsResponse{}, Errors: []int{401, 500}},
	"GET /api/notifications/count":      {Resp: notificationCountResponse{}, Errors: []int{401, 500}},
	"POST /api/notifications/{id}/read": {NoBody: true, Status: 204, Errors: []int{401, 500}},

	// oidc-providers
	"GET /api/admin/oidc-providers":               {Resp: listOIDCProvidersResponse{}, Errors: []int{500}},
	"POST /api/admin/oidc-providers":              {Required: []string{"id"}, Body: upsertOIDCProviderRequest{}, Resp: oidcProviderView{}, Errors: []int{400, 403, 500, 503}},
	"PUT /api/admin/oidc-providers/{id}":          {Body: upsertOIDCProviderRequest{}, Resp: oidcProviderView{}, Errors: []int{400, 403, 500, 503}},
	"DELETE /api/admin/oidc-providers/{id}":       {Status: 204, Errors: []int{403, 500, 503}},
	"POST /api/admin/oidc-providers/{id}/enabled": {Body: setOIDCProviderEnabledRequest{}, Status: 204, Errors: []int{400, 403, 500, 503}},

	// openapi
	"GET /api/openapi.json": {Resp: map[string]any{}, Errors: []int{500}},
	"GET /api/openapi.yaml": {Content: "application/yaml", Errors: []int{500}},

	// patch-policies
	"GET /api/patch-policies":         {Resp: listPatchPoliciesResponse{}, Errors: []int{500}},
	"POST /api/patch-policies":        {Body: store.PatchPolicy{}, Resp: savePatchPolicyResponse{}, Errors: []int{400, 404, 500}},
	"GET /api/patch-policies/export":  {Resp: exportPatchPoliciesResponse{}, Errors: []int{500}},
	"POST /api/patch-policies/import": {Body: importPatchPoliciesRequest{}, Resp: importPatchPoliciesResponse{}, Errors: []int{400, 500}},
	"PUT /api/patch-policies/{id}":    {Body: store.PatchPolicy{}, Resp: savePatchPolicyResponse{}, Errors: []int{400, 404, 500}},
	"DELETE /api/patch-policies/{id}": {Status: 204, Errors: []int{404, 500}},

	// patches
	"GET /api/patches":                          {Resp: patchesSummaryResponse{}, Errors: []int{500}},
	"POST /api/patches/deploy":                  {Body: deployPatchesRequest{}, BodyOptional: true, Resp: deployPatchesResponse{}, Also: []int{202}, Errors: []int{400, 403, 500}},
	"POST /api/patches/deploy/preview":          {Body: deployPatchesRequest{}, Resp: patchDeployPreviewResponse{}, Errors: []int{400, 500}},
	"GET /api/patches/deployments":              {Resp: listDeploymentsResponse{}, Errors: []int{500}},
	"GET /api/patches/deployments/{id}":         {Resp: getDeploymentResponse{}, Errors: []int{404, 500}},
	"GET /api/patches/history":                  {Resp: listPatchHistoryResponse{}, Errors: []int{500}},
	"GET /api/patches/list-assignments":         {Resp: listPatchListAssignmentsResponse{}, Errors: []int{500}},
	"POST /api/patches/list-assignments":        {Body: createPatchListAssignmentRequest{}, Resp: store.PatchListAssignment{}, Errors: []int{400, 500}},
	"DELETE /api/patches/list-assignments/{id}": {Status: 204, Errors: []int{404, 500}},
	"GET /api/patches/lists":                    {Resp: listPatchListsResponse{}, Errors: []int{500}},
	"POST /api/patches/lists":                   {Body: createPatchListRequest{}, Resp: store.PatchList{}, Errors: []int{400, 500}},
	"DELETE /api/patches/lists/{id}":            {Status: 204, Errors: []int{404, 500}},
	"POST /api/patches/rescan":                  {Body: patchRescanRequest{}, BodyOptional: true, Resp: patchRescanResponse{}, Errors: []int{400, 500}},
	"GET /api/patches/schedules":                {Resp: listPatchSchedulesResponse{}, Errors: []int{500}},
	"POST /api/patches/schedules":               {Body: createPatchScheduleRequest{}, Resp: store.PatchSchedule{}, Errors: []int{400, 500}},
	"DELETE /api/patches/schedules/{id}":        {Status: 204, Errors: []int{404, 500}},
	"POST /api/patches/schedules/{id}/enabled":  {Body: setScheduleEnabledRequest{}, Status: 204, Errors: []int{400, 404, 500}},

	// playbook-approvals
	"GET /api/playbook-approvals":       {Query: []queryParam{{Name: "state", Desc: "only requests in this state; all when empty"}}, Resp: listPlaybookPausesResponse{}, Errors: []int{500}},
	"POST /api/playbook-approvals/{id}": {Body: decidePlaybookPauseRequest{}, Resp: decidePlaybookPauseResponse{}, Errors: []int{400, 403, 404, 409, 500}},

	// playbook-triggers
	"GET /api/playbook-triggers":         {Resp: listPlaybookTriggersResponse{}, Errors: []int{500}},
	"POST /api/playbook-triggers":        {Body: store.PlaybookTrigger{}, Resp: store.PlaybookTrigger{}, Errors: []int{400, 404, 500}},
	"PUT /api/playbook-triggers/{id}":    {Body: store.PlaybookTrigger{}, Resp: store.PlaybookTrigger{}, Errors: []int{400, 404, 500}},
	"DELETE /api/playbook-triggers/{id}": {Status: 204, Errors: []int{500}},

	// playbooks
	"GET /api/playbooks":           {Resp: listPlaybooksResponse{}, Errors: []int{500}},
	"POST /api/playbooks":          {Body: playbookRequest{}, Resp: playbookResponse{}, Errors: []int{400, 500}},
	"GET /api/playbooks/runs":      {Query: []queryParam{{Name: "limit", Type: "integer", Desc: "at most this many"}}, Resp: listPlaybookRunsResponse{}, Errors: []int{500}},
	"GET /api/playbooks/runs/{id}": {Resp: getPlaybookRunResponse{}, Errors: []int{404, 500}},
	"GET /api/playbooks/{id}":      {Resp: playbookResponse{}, Errors: []int{404}},
	"PUT /api/playbooks/{id}":      {Body: playbookRequest{}, Resp: playbookResponse{}, Errors: []int{400, 500}},
	"DELETE /api/playbooks/{id}":   {Resp: deletePlaybookResponse{}, Errors: []int{404, 500}},
	"POST /api/playbooks/{id}/run": {NoBody: true, Resp: runPlaybookResponse{}, Also: []int{202}, Errors: []int{400, 403, 404, 500}},

	// preferences
	"GET /api/preferences": {Resp: store.UserPreferences{}, Errors: []int{401, 500}},
	"PUT /api/preferences": {Body: store.UserPreferences{}, Resp: store.UserPreferences{}, Errors: []int{400, 401, 500}},

	// mfa (two-step sign-in for the signed-in local account)
	"GET /api/me/mfa":                 {Resp: mfaStatus{}, Errors: []int{500}},
	"POST /api/me/mfa/setup":          {NoBody: true, Resp: mfaSetupResponse{}, Errors: []int{409, 500, 503}},
	"POST /api/me/mfa/enable":         {Body: mfaCodeRequest{}, Resp: mfaRecoveryCodesResponse{}, Errors: []int{400, 409, 500, 503}},
	"POST /api/me/mfa/recovery-codes": {Body: mfaCodeRequest{}, Resp: mfaRecoveryCodesResponse{}, Errors: []int{400, 409, 500, 503}},
	"POST /api/me/mfa/disable":        {Body: mfaCodeRequest{}, Resp: mfaStatus{}, Errors: []int{400, 409, 500, 503}},

	// process-events
	"GET /api/process-events": {Query: []queryParam{{Name: "agent", Desc: "only this endpoint"}, {Name: "limit", Type: "integer", Desc: "at most this many"}, {Name: "matched", Desc: "any value: only events that matched a rule"}, {Name: "q", Desc: "search text"}}, Resp: listProcessEventsResponse{}, Errors: []int{500}},

	// query
	"POST /api/query":            {Body: startQueryRequest{}, BodyOptional: true, Resp: startQueryResponse{}, Errors: []int{400, 403, 500}},
	"GET /api/query/{id}/stream": {Content: "text/event-stream", Errors: []int{404, 500}},

	// recorder-events
	"GET /api/recorder-events": {Query: []queryParam{{Name: "agent", Desc: "only this endpoint"}, {Name: "kind", Desc: "only events of this kind"}, {Name: "limit", Type: "integer", Desc: "at most this many"}, {Name: "matched", Desc: "any value: only events that matched a rule"}, {Name: "q", Desc: "search text"}}, Resp: listRecorderEventsResponse{}, Errors: []int{500}},

	// remote
	"POST /api/admin/remote":                  {Body: saveRemoteConfigRequest{}, Resp: remoteConfigResponse{}, Errors: []int{400, 403, 500}},
	"GET /api/remote/config":                  {Resp: remoteConfigResponse{}},
	"GET /api/remote/sessions":                {Resp: []remoteSessionRow{}, Errors: []int{500}},
	"POST /api/remote/sessions":               {Body: openRemoteRequest{}, Resp: openRemoteResponse{}, Errors: []int{400, 403, 404, 409, 422, 500}, ErrorBody: map[int]any{400: map[string]any{}, 403: map[string]any{}}},
	"GET /api/remote/sessions/{id}/recording": {Query: []queryParam{{Name: "kind", Enum: []string{"screen", "typescript"}, Desc: "the screen recording (the default) or a text session's typescript"}}, Content: "application/octet-stream", Errors: []int{400, 404, 500}},

	// reports
	"GET /api/reports":           {Resp: listReportsResponse{}, Errors: []int{500}},
	"POST /api/reports":          {Body: reportRequest{}, Resp: saveReportResponse{}, Errors: []int{400, 500}},
	"GET /api/reports/runs":      {Query: []queryParam{{Name: "limit", Type: "integer", Desc: "at most this many"}, {Name: "report", Desc: "only runs of this report"}}, Resp: listReportRunsResponse{}, Errors: []int{500}},
	"GET /api/reports/runs/{id}": {Query: []queryParam{{Name: "download", Desc: "any value: the report as an HTML file instead of JSON"}}, Resp: reportRunResponse{}, Content: "text/html", Errors: []int{404}},
	"GET /api/reports/{id}":      {Resp: getReportResponse{}, Errors: []int{404, 500}},
	"PUT /api/reports/{id}":      {Body: reportRequest{}, Resp: saveReportResponse{}, Errors: []int{400, 500}},
	"DELETE /api/reports/{id}":   {Resp: deleteReportResponse{}, Errors: []int{404, 500}},
	"POST /api/reports/{id}/run": {NoBody: true, Query: []queryParam{{Name: "deliver", Type: "boolean", Desc: "true to also send the report to its destination"}}, Resp: reportRunResponse{}, Errors: []int{400, 404}},

	// reveal
	"GET /api/reveal/overview":          {Resp: revealOverviewResponse{}, Errors: []int{500}},
	"GET /api/reveal/patterns":          {Resp: revealPatternsResponse{}},
	"GET /api/reveal/results":           {Query: []queryParam{{Name: "agent", Desc: "only this endpoint"}, flag("confirmed", "only confirmed findings"), {Name: "pattern", Desc: "only this pattern"}, {Name: "rule", Desc: "only this rule"}}, Resp: revealResultsResponse{}, Errors: []int{500}},
	"GET /api/reveal/rule-sets":         {Resp: listRevealRuleSetsResponse{}, Errors: []int{500}},
	"POST /api/reveal/rule-sets":        {Body: store.RevealRuleSet{}, Resp: saveRevealRuleSetResponse{}, Errors: []int{400, 404, 500}},
	"PUT /api/reveal/rule-sets/{id}":    {Body: store.RevealRuleSet{}, Resp: saveRevealRuleSetResponse{}, Errors: []int{400, 404, 500}},
	"DELETE /api/reveal/rule-sets/{id}": {Status: 204, Errors: []int{404, 500}},
	"GET /api/reveal/rules":             {Resp: revealRulesResponse{}, Errors: []int{500}},
	"POST /api/reveal/rules":            {Body: store.RevealRule{}, Resp: store.RevealRule{}, Errors: []int{400, 500}},
	"DELETE /api/reveal/rules/{id}":     {Status: 204, Errors: []int{500}},
	"POST /api/reveal/rules/{id}/run":   {Body: runRevealRuleRequest{}, BodyOptional: true, Resp: runRevealRuleResponse{}, Errors: []int{404, 500}},
	"GET /api/reveal/scans":             {Query: []queryParam{{Name: "rule", Desc: "only this rule"}}, Resp: revealScansResponse{}, Errors: []int{500}},
	"POST /api/reveal/search":           {Body: revealSearchRequest{}, Resp: revealSearchResponse{}, Errors: []int{400, 500}},
	"GET /api/reveal/templates":         {Resp: revealTemplatesResponse{}},

	// risk
	"GET /api/risk":                {Resp: riskSummaryResponse{}, Errors: []int{500}},
	"POST /api/risk/criticality":   {Body: setCriticalityRequest{}, Resp: setCriticalityResponse{}, Errors: []int{400, 404, 500}},
	"GET /api/risk/exploitability": {Resp: exploitabilityResponse{}, Errors: []int{500}},
	"POST /api/risk/intel/refresh": {NoBody: true, Resp: exploitIntelFeeds{}},
	"GET /api/risk/levels":         {Resp: vulnLevelsResponse{}, Errors: []int{500}},
	"GET /api/risk/remediation":    {Resp: remediationResponse{}, Errors: []int{500}},
	"POST /api/risk/scan":          {NoBody: true, Resp: riskScanNowResponse{}, Errors: []int{500}},
	"GET /api/risk/scores":         {Resp: riskScoresResponse{}, Errors: []int{500}},

	// roles
	"GET /api/admin/roles":         {Resp: listRolesResponse{}, Errors: []int{500}},
	"POST /api/admin/roles":        {Body: roleRequest{}, Resp: store.Role{}, Errors: []int{400, 403, 500, 503}},
	"PUT /api/admin/roles/{id}":    {Body: roleRequest{}, Resp: store.Role{}, Errors: []int{400, 403, 404, 500, 503}},
	"DELETE /api/admin/roles/{id}": {Status: 204, Errors: []int{403, 500, 503}},

	// schedules
	"GET /api/schedules":           {Resp: listScheduledActionsResponse{}, Errors: []int{500}},
	"POST /api/schedules":          {Body: store.ScheduledAction{}, Resp: store.ScheduledAction{}, Errors: []int{400, 403, 404, 500}},
	"PUT /api/schedules/{id}":      {Body: store.ScheduledAction{}, Resp: store.ScheduledAction{}, Errors: []int{400, 403, 404, 500}},
	"DELETE /api/schedules/{id}":   {Status: 204, Errors: []int{500}},
	"POST /api/schedules/{id}/run": {NoBody: true, Resp: runScheduledActionNowResponse{}, Errors: []int{400, 404, 500}},

	// selfservice
	"GET /api/selfservice/branding": {Resp: selfServiceBrandingResponse{}},
	"PUT /api/selfservice/branding": {Body: proto.SelfServiceBranding{}, Resp: selfServiceBrandingResponse{}, Errors: []int{400, 500}},

	// sensors
	"GET /api/sensors":                       {Resp: listSensorsResponse{}},
	"GET /api/sensors/builtin/{kind}/source": {Resp: sensorSourceResponse{}, Errors: []int{404, 500}},
	"GET /api/sensors/custom":                {Resp: listCustomSensorsResponse{}, Errors: []int{500}},
	"POST /api/sensors/custom":               {Required: []string{"name", "commands"}, Body: store.CustomSensor{}, Resp: store.CustomSensor{}, Errors: []int{400, 409, 500, 503}, ErrorBody: map[int]any{422: scriptValidation{}}},
	"POST /api/sensors/custom/complete":      {Body: completeCustomSensorScriptRequest{}, Resp: completeCustomSensorScriptResponse{}, Errors: []int{400, 503}},
	"POST /api/sensors/custom/parse":         {Body: parseCustomOutputRequest{}, Resp: parseCustomOutputResponse{}, Errors: []int{400, 422}},
	"POST /api/sensors/custom/test":          {Body: testCustomSensorRequest{}, Resp: testCustomSensorResponse{}, Errors: []int{400, 409, 422, 500, 502, 503}},
	"POST /api/sensors/custom/validate":      {Body: validateCustomSensorScriptsRequest{}, Resp: scriptValidation{}, Errors: []int{400, 503}},
	"PUT /api/sensors/custom/{id}":           {Required: []string{"name", "commands"}, Body: store.CustomSensor{}, Resp: store.CustomSensor{}, Errors: []int{400, 409, 500, 503}, ErrorBody: map[int]any{422: scriptValidation{}}},
	"DELETE /api/sensors/custom/{id}":        {Status: 204, Errors: []int{409}},
	"GET /api/sensors/custom/{id}/results":   {Resp: customSensorResultsResponse{}, Errors: []int{403, 404, 500}},

	// sessions
	"GET /api/sessions":      {Resp: listTranscriptsResponse{}, Errors: []int{500}},
	"GET /api/sessions/{id}": {Resp: store.SessionTranscript{}, Errors: []int{404, 500}},

	// settings
	"GET /api/admin/settings":                        {Resp: settingsView{}},
	"POST /api/admin/settings":                       {Body: updateSettingsRequest{}, Resp: settingsView{}, Errors: []int{400, 403, 409, 500, 503}},
	"POST /api/admin/mail-test":                      {Body: mailTestRequest{}, Resp: mailTestResponse{}, Errors: []int{400, 422}},
	"GET /api/admin/email-templates":                 {Resp: emailTemplatesResponse{}},
	"PUT /api/admin/email-templates/{kind}":          {Body: store.EmailTemplate{}, Resp: emailTemplatesResponse{}, Errors: []int{400, 404, 500}},
	"POST /api/admin/email-templates/{kind}/preview": {Body: store.EmailTemplate{}, Resp: emailPreviewResponse{}, Errors: []int{400, 404}},
	"POST /api/admin/email-templates/{kind}/test":    {Body: emailSendTestRequest{}, Resp: mailTestResponse{}, Errors: []int{400, 422}},
	"PUT /api/admin/email-shared":                    {Body: emailShared{}, Resp: emailTemplatesResponse{}, Errors: []int{400, 500}},
	"POST /api/admin/settings/fleet-test":            {NoBody: true, Resp: testFleetResponse{}, Errors: []int{400, 422, 500}},

	// shell
	"GET /api/shell/audit":               {Query: []queryParam{{Name: "session_id", Desc: "only this session"}}, Resp: shellAuditResponse{}, Errors: []int{500}},
	"GET /api/shell/sessions":            {Resp: listShellSessionsResponse{}, Errors: []int{500}},
	"POST /api/shell/sessions":           {Body: openShellRequest{}, Resp: openShellResponse{}, Errors: []int{400, 403, 404, 409, 500}, ErrorBody: map[int]any{400: map[string]any{}, 403: map[string]any{}}},
	"DELETE /api/shell/sessions/{id}":    {Query: []queryParam{flag("takeover", "close another operator's session")}, Status: 204, Errors: []int{403, 404, 500, 503}},
	"POST /api/shell/sessions/{id}/exec": {Body: shellExecRequest{}, Resp: proto.ShellReply{}, Errors: []int{400, 403, 404, 409, 500, 502, 503}},

	// software
	"GET /api/software":                    {Resp: listSoftwareResponse{}, Errors: []int{500}},
	"GET /api/software-library":            {Resp: libraryResponse{}},
	"POST /api/software-library/{id}":      {NoBody: true, Resp: libraryAddResponse{}, Errors: []int{404, 409, 500}},
	"POST /api/software":                   {Body: store.SoftwarePackage{}, Resp: store.SoftwarePackage{}, Errors: []int{400, 500}},
	"POST /api/software/adopt":             {Body: adoptSoftwareRequest{}, Resp: store.SoftwarePackage{}, Errors: []int{400, 500}},
	"POST /api/software/deploy":            {Body: softwareDeployRequest{}, Resp: deploySoftwareResponse{}, RespAlt: []any{deployRunResponse{}}, Also: []int{202}, Errors: []int{400, 401, 403, 404, 409, 500, 503}, ErrorBody: map[int]any{400: map[string]any{}}},
	"GET /api/software/discover":           {Query: []queryParam{{Name: "min_devices", Type: "integer", Desc: "only software on at least this many endpoints (1)"}}, Resp: discoverSoftwareResponse{}, Errors: []int{500}},
	"DELETE /api/software/files/{fileID}":  {Status: 204, Errors: []int{404, 500}},
	"PUT /api/software/{id}":               {Body: store.SoftwarePackage{}, Resp: store.SoftwarePackage{}, Errors: []int{400, 500}},
	"DELETE /api/software/{id}":            {Status: 204, Errors: []int{409, 500}},
	"GET /api/software/{id}/applicability": {Resp: softwareApplicabilityResponse{}, Errors: []int{404, 500}},
	"GET /api/software/{id}/files":         {Resp: listPackageFilesResponse{}, Errors: []int{500}},
	"POST /api/software/{id}/files":        {Upload: []formField{{Name: "file", File: true, Required: true}}, Resp: store.PackageFile{}, Errors: []int{400, 404, 500}},

	// software-inventory
	"GET /api/software-inventory":                              {Query: []queryParam{{Name: "days", Type: "integer", Desc: "the usage window in days"}, {Name: "filter", Enum: []string{"apps", "tracked", "unused"}}, {Name: "format", Enum: []string{"csv"}, Desc: "csv for a CSV download instead of JSON"}, {Name: "q", Desc: "search text"}}, Resp: softwareInventoryResponse{}, Content: "text/csv", Errors: []int{500}},
	"GET /api/software-inventory/product/{key}":                {Query: []queryParam{{Name: "agent", Desc: "only this endpoint"}, {Name: "days", Type: "integer", Desc: "the usage window in days"}}, Resp: softwareInventoryProductResponse{}, Errors: []int{404, 500}},
	"POST /api/software-inventory/product/{key}/remove-unused": {Body: removeUnusedSoftwareRequest{}, Resp: deploySoftwareResponse{}, RespAlt: []any{deployRunResponse{}, removeUnusedSoftwareResponse{}}, Also: []int{202}, Errors: []int{400, 401, 403, 404, 409, 500, 503}, ErrorBody: map[int]any{400: map[string]any{}}},
	"POST /api/software-inventory/refresh":                     {NoBody: true, Resp: softwareInventoryRefreshResponse{}, Errors: []int{500}},

	// surveys
	"GET /api/surveys":            {Resp: listSurveysResponse{}, Errors: []int{500}},
	"POST /api/surveys":           {Body: store.Survey{}, Resp: store.Survey{}, Errors: []int{400, 500}},
	"GET /api/surveys/{id}":       {Resp: surveyDetailResponse{}, Errors: []int{404, 500}},
	"PUT /api/surveys/{id}":       {Body: store.Survey{}, Resp: store.Survey{}, Errors: []int{400, 404, 409, 500}},
	"DELETE /api/surveys/{id}":    {Status: 204, Errors: []int{500}},
	"POST /api/surveys/{id}/send": {Body: sendSurveyRequest{}, BodyOptional: true, Resp: sendSurveyResponse{}, Errors: []int{400, 404, 500}},

	// tokens
	"GET /api/admin/tokens":              {Resp: listAPITokensResponse{}, Errors: []int{500}},
	"POST /api/admin/tokens":             {Body: createAPITokenRequest{}, Resp: createAPITokenResponse{}, Errors: []int{400, 403, 500, 503}},
	"DELETE /api/admin/tokens/{id}":      {Status: 204, Errors: []int{500, 503}},
	"PUT /api/admin/tokens/{id}":         {Body: updateAPITokenRequest{}, Resp: store.APIToken{}, Errors: []int{400, 403, 404, 409, 500, 503}},
	"POST /api/admin/tokens/{id}/revoke": {NoBody: true, Status: 204, Errors: []int{500, 503}},

	// tracked-products
	"GET /api/tracked-products":         {Resp: listTrackedProductsResponse{}, Errors: []int{500}},
	"POST /api/tracked-products":        {Body: store.TrackedProduct{}, Resp: store.TrackedProduct{}, Errors: []int{400, 404, 500}},
	"PUT /api/tracked-products/{id}":    {Body: store.TrackedProduct{}, Resp: store.TrackedProduct{}, Errors: []int{400, 404, 500}},
	"DELETE /api/tracked-products/{id}": {Status: 204, Errors: []int{404, 500}},

	// update-check
	"POST /api/admin/update-check": {NoBody: true, Resp: updateCheckResponse{}, Errors: []int{500}},

	// users
	"GET /api/admin/users":                         {Resp: listUsersResponse{}, Errors: []int{500}},
	"POST /api/admin/users":                        {Body: createLocalUserRequest{}, Resp: adminUserView{}, Errors: []int{400, 500, 503}},
	"DELETE /api/admin/users/{id}":                 {Status: 204, Errors: []int{400, 403, 404, 500, 503}},
	"POST /api/admin/users/{id}/active":            {Body: setActiveRequest{}, Resp: adminUserView{}, Errors: []int{400, 403, 404, 500, 503}},
	"POST /api/admin/users/{id}/admin":             {Body: setAdminRequest{}, Resp: adminUserView{}, Errors: []int{400, 403, 404, 500, 503}},
	"POST /api/admin/users/{id}/mfa/reset":         {NoBody: true, Status: 204, Errors: []int{403, 404, 500, 503}},
	"POST /api/admin/users/{id}/roles":             {Body: roleIDRequest{}, Status: 204, Errors: []int{400, 403, 404, 500, 503}},
	"DELETE /api/admin/users/{id}/roles/{role_id}": {Status: 204, Errors: []int{403, 500, 503}},

	// version
	"GET /api/version": {Resp: versionResponse{}},

	// watchlists
	"GET /api/watchlists":         {Resp: listWatchlistsResponse{}, Errors: []int{500}},
	"POST /api/watchlists":        {Body: store.Watchlist{}, Resp: store.Watchlist{}, Errors: []int{400, 404, 500}},
	"PUT /api/watchlists/{id}":    {Body: store.Watchlist{}, Resp: store.Watchlist{}, Errors: []int{400, 404, 500}},
	"DELETE /api/watchlists/{id}": {Status: 204, Errors: []int{404, 500}},
}

// controlsQueryParams select the compliance-by-control report.
var controlsQueryParams = []queryParam{
	{Name: "framework", Desc: "framework key from the benchmark's mappings: nist_800_53 (default), nist_800_171, cmmc, hipaa…"},
	{Name: "policy_id", Desc: "only this policy"},
}
