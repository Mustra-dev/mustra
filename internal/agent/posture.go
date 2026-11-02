package agent

import (
	"context"

	"github.com/mustra-dev/mustra/internal/proto"
)

// collectSecurityPosture reports the endpoint's own protective controls:
// firewall, disk encryption, antimalware, application control. Each OS
// answers with what it has; a control the platform does not model reports
// engine "none" rather than a guess, and a probe that fails lands in
// Errors rather than reading as "off".
//
// Published as a one-row list so group rules and Interact can address the
// fields directly (security_posture.firewall_enabled), the same shape the
// hardware sensor uses.
func collectSecurityPosture(ctx context.Context) ([]proto.SecurityPosture, error) {
	return []proto.SecurityPosture{collectPosturePlatform(ctx)}, nil
}

// shadowModes are the values of the RDS Shadow setting.
var shadowModes = map[int]string{
	0: "off", 1: "control_with_consent", 2: "control_without_consent",
	3: "view_with_consent", 4: "view_without_consent",
}

// shadowState reads the Shadow value and its surroundings into whether a
// shadow request can reach the signed-in session. The firewall rule is
// needed unless the firewall is off on every profile (firewallActive is
// false only then).
func shadowState(value int, source string, firewallRule, service, firewallActive bool) *proto.RemoteShadowState {
	st := &proto.RemoteShadowState{Mode: shadowModes[value], Source: source, FirewallRule: firewallRule, Service: service}
	if st.Mode == "" {
		st.Mode = "off"
	}
	switch {
	case st.Mode == "off":
		st.Reason = "shadowing is turned off (Shadow = 0)"
	case !service:
		st.Reason = "the Remote Desktop service (TermService) is not running"
	case firewallActive && !firewallRule:
		st.Reason = "the Remote Desktop - Shadow (TCP-In) firewall rule is off"
	default:
		st.Ready = true
	}
	return st
}
