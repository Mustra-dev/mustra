package server

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/mustra-dev/mustra/internal/store"
)

// Parameterized packages: a package declares typed
// inputs, and their values are substituted into its command at deploy time.
// The point is that "restart in N seconds" is one package rather than one
// package per value of N.
//
// On trust: a parameter value ends up inside a shell command, so supplying
// one is as privileged as authoring the command in the first place. That is
// why filling them in requires deploy.manage, the same permission that lets
// someone write the command outright — the parameter adds no authority
// nobody already had. What validation buys is not a security boundary but a
// correctness one: it stops a typo reaching a thousand endpoints. A package
// with parameters is therefore deliberately NOT offerable through Self
// Service, where the person clicking has no such permission.

var paramNameRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

const (
	paramText     = "text"
	paramNumeric  = "numeric"
	paramSelect   = "select"
	paramCheckbox = "checkbox"
)

// validateParameters checks a package's parameter declarations at author
// time, so a broken parameter is caught by the person writing it rather than
// by a deployment that fails on every endpoint at once.
func validateParameters(params []store.SoftwareParameter) error {
	seen := map[string]bool{}
	for i, p := range params {
		name := strings.TrimSpace(p.Name)
		if !paramNameRe.MatchString(name) {
			return fmt.Errorf("parameter %d: name %q must be lower-case letters, digits and underscores, starting with a letter", i+1, p.Name)
		}
		if seen[name] {
			return fmt.Errorf("parameter %q is declared twice", name)
		}
		seen[name] = true

		switch p.Type {
		case paramText, paramNumeric, paramSelect, paramCheckbox:
		default:
			return fmt.Errorf("parameter %q: type must be one of text, numeric, select, checkbox", name)
		}
		if p.Type == paramSelect && len(p.Options) == 0 {
			return fmt.Errorf("parameter %q: a select needs at least one option", name)
		}
		if p.Min != nil && p.Max != nil && *p.Min > *p.Max {
			return fmt.Errorf("parameter %q: min is greater than max", name)
		}
		if p.Validate != "" {
			if _, err := regexp.Compile(p.Validate); err != nil {
				return fmt.Errorf("parameter %q: validation pattern does not compile: %w", name, err)
			}
		}
	}
	return nil
}

// resolveParameters merges supplied values over the declared defaults and
// checks each one, returning the values to substitute. It refuses the whole
// deployment on the first bad value rather than substituting a partial set:
// a command built from half-resolved parameters is worse than no deployment.
func resolveParameters(params []store.SoftwareParameter, supplied map[string]string) (map[string]string, error) {
	out := make(map[string]string, len(params))
	for _, p := range params {
		val, given := supplied[p.Name]
		if !given || strings.TrimSpace(val) == "" {
			val = p.Default
		}
		if strings.TrimSpace(val) == "" {
			if p.Required {
				return nil, fmt.Errorf("%q is required", paramLabel(p))
			}
			out[p.Name] = ""
			continue
		}
		switch p.Type {
		case paramNumeric:
			n, err := strconv.ParseFloat(val, 64)
			if err != nil {
				return nil, fmt.Errorf("%q must be a number, got %q", paramLabel(p), val)
			}
			if p.Min != nil && n < *p.Min {
				return nil, fmt.Errorf("%q must be at least %v", paramLabel(p), *p.Min)
			}
			if p.Max != nil && n > *p.Max {
				return nil, fmt.Errorf("%q must be at most %v", paramLabel(p), *p.Max)
			}
		case paramSelect:
			ok := false
			for _, o := range p.Options {
				if o == val {
					ok = true
					break
				}
			}
			if !ok {
				return nil, fmt.Errorf("%q must be one of: %s", paramLabel(p), strings.Join(p.Options, ", "))
			}
		case paramCheckbox:
			if val != "true" && val != "false" {
				return nil, fmt.Errorf("%q must be true or false", paramLabel(p))
			}
		}
		if p.Validate != "" {
			re, err := regexp.Compile(p.Validate)
			if err != nil {
				return nil, fmt.Errorf("%q: validation pattern does not compile: %w", paramLabel(p), err)
			}
			if !re.MatchString(val) {
				return nil, fmt.Errorf("%q does not match the allowed format", paramLabel(p))
			}
		}
		out[p.Name] = val
	}
	return out, nil
}

// substituteParameters replaces $(name) in a command with the resolved
// value. Only declared names are substituted, so a command containing a
// literal $(something) that isn't a parameter is left exactly as written
// rather than being silently blanked.
func substituteParameters(command string, values map[string]string) string {
	for name, val := range values {
		command = strings.ReplaceAll(command, "$("+name+")", val)
	}
	return command
}

func paramLabel(p store.SoftwareParameter) string {
	if strings.TrimSpace(p.Label) != "" {
		return p.Label
	}
	return p.Name
}
