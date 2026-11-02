package server

import (
	"strings"

	"github.com/mustra-dev/mustra/internal/store"
)

// How a CISA KEV entry's product shows up on an endpoint.
//
// KEV names a vendor and a product ("Plex", "Media Server"), not a package,
// so finding it in the fleet needs a rule per product. Fuzzy matching is
// what this replaces: "plex" matches libmplex, and BIND's client tools
// (bind9-dnsutils, on nearly every Debian host) are not the name server
// the advisories are about. A product without a rule is reported as not
// checked, rather than guessed at.
//
// App patterns are regular expressions matched case-insensitively against
// the whole installed application or package name. Keys are
// "vendor|product", lower-case; "vendor|*" covers a vendor's products not
// listed on their own.
var kevProductRules = map[string]store.ThreatRule{
	// Operating systems: every endpoint on the OS is exposed until the
	// vendor's update is installed.
	"microsoft|windows":           {Label: "Microsoft Windows", OS: []string{"windows"}, Note: "Every Windows endpoint, until the update that fixes it is installed: see the Patch page."},
	"microsoft|win32k":            {Label: "Microsoft Windows", OS: []string{"windows"}},
	"microsoft|windows server":    {Label: "Microsoft Windows Server", OS: []string{"windows"}},
	"apple|multiple products":     {Label: "Apple macOS", OS: []string{"darwin"}, Note: "Covers macOS here; iPhones and iPads are not endpoints mustra manages."},
	"apple|macos":                 {Label: "Apple macOS", OS: []string{"darwin"}},
	"linux|kernel":                {Label: "Linux kernel", OS: []string{"linux"}, Apps: []string{`linux-image-.*`, `kernel(-core)?`}},
	"microsoft|exchange server":   {Label: "Microsoft Exchange Server", Apps: []string{`microsoft exchange server.*`}, Services: []string{"MSExchangeTransport"}},
	"microsoft|sharepoint":        {Label: "Microsoft SharePoint Server", Apps: []string{`microsoft sharepoint server.*`}},
	"microsoft|sharepoint server": {Label: "Microsoft SharePoint Server", Apps: []string{`microsoft sharepoint server.*`}},
	"microsoft|office":            {Label: "Microsoft Office", Apps: []string{`microsoft (office|365).*`, `microsoft (word|excel|powerpoint|outlook).*`}},
	"microsoft|.net framework":    {Label: "Microsoft .NET", Apps: []string{`microsoft \.net.*`}},
	"microsoft|edge":              {Label: "Microsoft Edge", Apps: []string{`microsoft edge`}, Processes: []string{"msedge.exe"}},
	"google|chromium v8":          {Label: "Chromium browsers", Apps: []string{`google chrome`, `chromium(-browser)?`, `microsoft edge`, `brave( browser)?`}, Processes: []string{"chrome", "chrome.exe", "msedge.exe"}},
	"google|chromium":             {Label: "Chromium browsers", Apps: []string{`google chrome`, `chromium(-browser)?`, `microsoft edge`, `brave( browser)?`}, Processes: []string{"chrome", "chrome.exe", "msedge.exe"}},
	"google|chrome":               {Label: "Google Chrome", Apps: []string{`google chrome`, `google-chrome-stable`}, Processes: []string{"chrome", "chrome.exe"}},
	"mozilla|firefox":             {Label: "Mozilla Firefox", Apps: []string{`(mozilla )?firefox.*`, `firefox-esr`}, Processes: []string{"firefox", "firefox.exe"}},
	"mozilla|thunderbird":         {Label: "Mozilla Thunderbird", Apps: []string{`(mozilla )?thunderbird.*`}},
	"oracle|java se":              {Label: "Java", Apps: []string{`java( \d+)?( update \d+)?`, `openjdk-\d+-(jre|jdk)(-headless)?`, `java-\d+-openjdk.*`}},
	"adobe|acrobat and reader":    {Label: "Adobe Acrobat / Reader", Apps: []string{`adobe acrobat.*`}},
	"adobe|acrobat":               {Label: "Adobe Acrobat / Reader", Apps: []string{`adobe acrobat.*`}},
	"adobe|coldfusion":            {Label: "Adobe ColdFusion", Apps: []string{`adobe coldfusion.*`, `coldfusion.*`}},
	"7-zip|7-zip":                 {Label: "7-Zip", Apps: []string{`7-zip.*`, `p7zip.*`, `7zip`}},
	"rarlab|winrar":               {Label: "WinRAR", Apps: []string{`winrar.*`}},
	"winrar|winrar":               {Label: "WinRAR", Apps: []string{`winrar.*`}},
	"notepad++|notepad++":         {Label: "Notepad++", Apps: []string{`notepad\+\+.*`}},
	"vmware|tools":                {Label: "VMware Tools", Apps: []string{`vmware tools`, `open-vm-tools`}},
	"vmware|workstation":          {Label: "VMware Workstation", Apps: []string{`vmware workstation.*`}},
	"citrix|workspace":            {Label: "Citrix Workspace app", Apps: []string{`citrix workspace.*`}},
	"zoom|zoom":                   {Label: "Zoom", Apps: []string{`zoom( workplace)?.*`}},
	"teamviewer|teamviewer":       {Label: "TeamViewer", Apps: []string{`teamviewer.*`}, Processes: []string{"TeamViewer.exe", "teamviewerd"}},
	"anydesk|anydesk":             {Label: "AnyDesk", Apps: []string{`anydesk.*`}, Processes: []string{"AnyDesk.exe", "anydesk"}},
	"connectwise|screenconnect":   {Label: "ConnectWise ScreenConnect", Apps: []string{`screenconnect.*`, `connectwise control.*`}},
	"beyondtrust|remote support":  {Label: "BeyondTrust Remote Support", Apps: []string{`beyondtrust.*`, `bomgar.*`}},
	"veeam|backup & replication":  {Label: "Veeam Backup & Replication", Apps: []string{`veeam backup & replication.*`}},
	"plex|media server":           {Label: "Plex Media Server", Apps: []string{`plex media server`, `plexmediaserver`}, Processes: []string{"Plex Media Server", "Plex Media Server.exe"}, Services: []string{"plexmediaserver"}},
	"isc|bind":                    {Label: "ISC BIND name server", Apps: []string{`bind9`, `bind`, `bind-chroot`}, Processes: []string{"named"}, Services: []string{"named", "bind9"}, Note: "The name server (bind9 / named). BIND's client tools and libraries (bind9-dnsutils, bind9-libs) are not counted."},
	"proftpd|proftpd":             {Label: "ProFTPD", Apps: []string{`proftpd(-basic|-core)?`}, Processes: []string{"proftpd"}, Services: []string{"proftpd"}},
	"apache|http server":          {Label: "Apache HTTP Server", Apps: []string{`apache2`, `httpd`, `apache http server.*`}, Processes: []string{"apache2", "httpd", "httpd.exe"}, Services: []string{"apache2", "httpd"}},
	"apache|tomcat":               {Label: "Apache Tomcat", Apps: []string{`tomcat\d*`, `apache tomcat.*`}, Processes: []string{"tomcat", "tomcat9.exe"}},
	"apache|activemq":             {Label: "Apache ActiveMQ", Apps: []string{`activemq`, `apache activemq.*`}},
	"apache|struts":               {Label: "Apache Struts", Note: "A Java library packed inside applications: no installed package shows it. Look for struts2-core jars (Hunt, or Reveal)."},
	"apache|log4j2":               {Label: "Apache Log4j", Apps: []string{`liblog4j2-java`, `log4j`}, Note: "Only the packaged library is seen; copies inside applications need a file search."},
	"openssh|openssh":             {Label: "OpenSSH", Apps: []string{`openssh-server`, `openssh`, `openssh for windows`}, Processes: []string{"sshd"}},
	"openssl|openssl":             {Label: "OpenSSL", Apps: []string{`openssl`, `libssl\d.*`}},
	"php|php":                     {Label: "PHP", Apps: []string{`php\d*(\.\d+)?(-cli|-fpm|-cgi|-common)?`, `php( \d.*)?`}, Processes: []string{"php", "php-fpm", "php-cgi", "php.exe"}},
	"nginx|nginx":                 {Label: "nginx", Apps: []string{`nginx(-core|-full|-light|-extras)?`}, Processes: []string{"nginx"}},
	"exim|exim":                   {Label: "Exim", Apps: []string{`exim4(-daemon-light|-daemon-heavy)?`, `exim`}, Processes: []string{"exim4", "exim"}},
	"sudo|sudo":                   {Label: "sudo", Apps: []string{`sudo`}},
	"gitlab|gitlab":               {Label: "GitLab", Apps: []string{`gitlab-(ce|ee)`}},
	"jenkins|jenkins":             {Label: "Jenkins", Apps: []string{`jenkins`}},
	"atlassian|confluence":        {Label: "Atlassian Confluence", Apps: []string{`atlassian-confluence.*`, `confluence`}},
	"atlassian|jira":              {Label: "Atlassian Jira", Apps: []string{`atlassian-jira.*`, `jira.*`}},
	"atlassian|multiple products": {Label: "Atlassian Confluence / Jira", Apps: []string{`atlassian-(confluence|jira).*`}},
	"collabora|collabora online – built-in code server": {Label: "Collabora Online server", Apps: []string{`coolwsd`, `collabora-online.*`, `richdocumentscode.*`}, Processes: []string{"coolwsd"}, Note: "The online server (coolwsd, CODE). Collabora Office on a desktop is not counted."},
	"onlyoffice|docs":                              {Label: "ONLYOFFICE Docs server", Apps: []string{`onlyoffice-documentserver.*`}},
	"zammad gmbh|zammad":                           {Label: "Zammad", Apps: []string{`zammad`}},
	"zimbra|collaboration":                         {Label: "Zimbra Collaboration", Apps: []string{`zimbra.*`}},
	"roundcube|webmail":                            {Label: "Roundcube", Apps: []string{`roundcube(-core)?`}},
	"craft cms|craft cms":                          {Label: "Craft CMS", Note: "A PHP application, not a package: no installed package shows it."},
	"strapi|strapi":                                {Label: "Strapi", Note: "A Node.js application, not a package: no installed package shows it."},
	"siemens|software center":                      {Label: "Siemens Software Center", Apps: []string{`siemens software center.*`}},
	"ahsay|ahsaycbs":                               {Label: "AhsayCBS", Apps: []string{`ahsaycbs.*`, `ahsay.*`}},
	"eg secure solutions|siteguard server edition": {Label: "SiteGuard Server Edition", Apps: []string{`siteguard.*`}},

	// Network appliances and vendor-hosted services: no endpoint agent
	// sees them.
	"fortinet|*":                 {Label: "Fortinet appliance", Appliance: true},
	"cisco|*":                    {Label: "Cisco appliance or service", Appliance: true},
	"palo alto networks|*":       {Label: "Palo Alto Networks appliance", Appliance: true},
	"citrix|netscaler":           {Label: "Citrix NetScaler", Appliance: true},
	"citrix|adc":                 {Label: "Citrix NetScaler ADC", Appliance: true},
	"ivanti|connect secure":      {Label: "Ivanti Connect Secure", Appliance: true},
	"ivanti|policy secure":       {Label: "Ivanti Policy Secure", Appliance: true},
	"sonicwall|*":                {Label: "SonicWall appliance", Appliance: true},
	"juniper|*":                  {Label: "Juniper appliance", Appliance: true},
	"f5|*":                       {Label: "F5 appliance", Appliance: true},
	"arista|*":                   {Label: "Arista appliance or service", Appliance: true},
	"zyxel|*":                    {Label: "Zyxel device", Appliance: true},
	"d-link|*":                   {Label: "D-Link device", Appliance: true},
	"tp-link|*":                  {Label: "TP-Link device", Appliance: true},
	"netgear|*":                  {Label: "NETGEAR device", Appliance: true},
	"cisco|secure email gateway": {Label: "Cisco Secure Email Gateway", Appliance: true},
	"sap|netweaver":              {Label: "SAP NetWeaver", Appliance: true, Note: "An application server mustra does not inventory."},
	"oracle|e-business suite":    {Label: "Oracle E-Business Suite", Appliance: true, Note: "An application server mustra does not inventory."},
}

// kevRule finds the rule for a KEV entry's vendor and product.
func kevRule(vendor, product string) (store.ThreatRule, bool) {
	v, p := strings.ToLower(strings.TrimSpace(vendor)), strings.ToLower(strings.TrimSpace(product))
	if r, ok := kevProductRules[v+"|"+p]; ok {
		return r, true
	}
	if r, ok := kevProductRules[v+"|*"]; ok {
		return r, true
	}
	return store.ThreatRule{}, false
}
