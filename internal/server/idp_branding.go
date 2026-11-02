package server

import "html/template"

// Brand marks for the login page's per-provider buttons. These are simple
// geometric marks drawn in each vendor's characteristic colors — enough for
// someone to recognize which button is which at a glance — rather than
// copies of the vendors' actual trademarked logo files, which come with
// their own usage rules and would have to be vendored as binary assets.

type idpBrand struct {
	// Accent is the color of the button's left edge and its mark.
	Accent string
	SVG    template.HTML
}

var idpBrands = map[string]idpBrand{
	// Four squares, the shape everyone reads as "Microsoft".
	"azure": {Accent: "#0078d4", SVG: template.HTML(`
<svg viewBox="0 0 16 16" width="16" height="16" aria-hidden="true">
  <rect x="0" y="0" width="7" height="7" fill="#f25022"/>
  <rect x="9" y="0" width="7" height="7" fill="#7fba00"/>
  <rect x="0" y="9" width="7" height="7" fill="#00a4ef"/>
  <rect x="9" y="9" width="7" height="7" fill="#ffb900"/>
</svg>`)},

	// A ring drawn in Google's four colors with the G's crossbar.
	"google": {Accent: "#4285f4", SVG: template.HTML(`
<svg viewBox="0 0 16 16" width="16" height="16" aria-hidden="true" fill="none" stroke-width="2.4">
  <path d="M8 1.5a6.5 6.5 0 0 1 4.6 1.9" stroke="#ea4335"/>
  <path d="M14.5 8A6.5 6.5 0 0 1 12.6 12.6" stroke="#fbbc05"/>
  <path d="M12.6 12.6A6.5 6.5 0 0 1 3.4 3.4" stroke="#34a853"/>
  <path d="M8 8h6.5" stroke="#4285f4"/>
</svg>`)},

	// Discord's rounded face silhouette, simplified to a capsule and eyes.
	"discord": {Accent: "#5865f2", SVG: template.HTML(`
<svg viewBox="0 0 16 16" width="16" height="16" aria-hidden="true">
  <rect x="1" y="3.5" width="14" height="9" rx="4.5" fill="#5865f2"/>
  <circle cx="5.8" cy="8" r="1.5" fill="#fff"/>
  <circle cx="10.2" cy="8" r="1.5" fill="#fff"/>
</svg>`)},

	"authentik": {Accent: "#fd4b2d", SVG: template.HTML(`
<svg viewBox="0 0 16 16" width="16" height="16" aria-hidden="true">
  <path d="M8 1.5 14.5 8 8 14.5 1.5 8Z" fill="#fd4b2d"/>
  <circle cx="8" cy="8" r="2.1" fill="#fff"/>
</svg>`)},

	"okta": {Accent: "#007dc1", SVG: template.HTML(`
<svg viewBox="0 0 16 16" width="16" height="16" aria-hidden="true">
  <circle cx="8" cy="8" r="6.2" fill="none" stroke="#007dc1" stroke-width="3.2"/>
</svg>`)},

	"github": {Accent: "#8b93a3", SVG: template.HTML(`
<svg viewBox="0 0 16 16" width="16" height="16" aria-hidden="true">
  <circle cx="8" cy="8" r="6.5" fill="currentColor"/>
  <path d="M6 13.4v-2c0-.6.2-1 .5-1.3-1.8-.2-3.2-.9-3.2-3.4 0-.8.3-1.4.7-1.9-.1-.2-.3-.9.05-1.9 0 0 .6-.2 1.9.7a6.3 6.3 0 0 1 3.4 0c1.3-.9 1.9-.7 1.9-.7.35 1 .15 1.7.05 1.9.45.5.7 1.1.7 1.9 0 2.5-1.4 3.2-3.2 3.4.25.25.5.7.5 1.4v1.9" fill="none" stroke="#14161d" stroke-width="1.1" stroke-linecap="round"/>
</svg>`)},

	"keycloak": {Accent: "#4d4d4d", SVG: template.HTML(`
<svg viewBox="0 0 16 16" width="16" height="16" aria-hidden="true">
  <path d="M8 1.5 13.8 4v4.5c0 3.2-2.3 5.4-5.8 6.4-3.5-1-5.8-3.2-5.8-6.4V4Z" fill="#008aaa"/>
  <circle cx="8" cy="7" r="1.8" fill="#fff"/>
  <rect x="7.2" y="7.6" width="1.6" height="3.4" fill="#fff"/>
</svg>`)},

	"generic": {Accent: "#6f96ff", SVG: template.HTML(`
<svg viewBox="0 0 16 16" width="16" height="16" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round">
  <circle cx="6" cy="8" r="3"/>
  <path d="M9 8h5.5M12.5 8v2.4M14.5 8v1.6"/>
</svg>`)},
}

func brandFor(kind string) idpBrand {
	if b, ok := idpBrands[kind]; ok {
		return b
	}
	return idpBrands["generic"]
}
