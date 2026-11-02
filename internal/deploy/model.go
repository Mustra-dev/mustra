// Package deploy validates and evaluates the immutable software execution contract.
// Both server planning and endpoint execution use these rules.
package deploy

import (
	"fmt"
	"math"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/mustra-dev/mustra/internal/proto"
)

var identifier = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,63}$`)
var pathID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,96}$`)
var hash = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)
var versionParts = regexp.MustCompile(`[0-9]+|[A-Za-z]+`)

func CompareVersion(a, b string) int {
	aa, bb := versionParts.FindAllString(strings.TrimPrefix(a, "v"), -1), versionParts.FindAllString(strings.TrimPrefix(b, "v"), -1)
	for i := 0; i < max(len(aa), len(bb)); i++ {
		x, y := "0", "0"
		if i < len(aa) {
			x = aa[i]
		}
		if i < len(bb) {
			y = bb[i]
		}
		nx, ex := strconv.ParseUint(x, 10, 64)
		ny, ey := strconv.ParseUint(y, 10, 64)
		if ex == nil && ey == nil {
			if nx < ny {
				return -1
			}
			if nx > ny {
				return 1
			}
		} else if c := strings.Compare(strings.ToLower(x), strings.ToLower(y)); c != 0 {
			return c
		}
	}
	return 0
}

func VersionMatches(actual, constraint string) (bool, error) {
	if constraint == "" {
		return true, nil
	}
	if actual == "" {
		return false, fmt.Errorf("version is unavailable")
	}
	for _, part := range strings.Split(constraint, ",") {
		part = strings.TrimSpace(part)
		op := "eq"
		for _, prefix := range []string{">=", "<=", "!=", ">", "<", "="} {
			if strings.HasPrefix(part, prefix) {
				op = map[string]string{">=": "gte", "<=": "lte", "!=": "ne", ">": "gt", "<": "lt", "=": "eq"}[prefix]
				part = strings.TrimSpace(strings.TrimPrefix(part, prefix))
				break
			}
		}
		if len(versionParts.FindAllString(part, -1)) == 0 {
			return false, fmt.Errorf("invalid version constraint %q", constraint)
		}
		if !ordered(CompareVersion(actual, part), op) {
			return false, nil
		}
	}
	return true, nil
}
func ordered(c int, op string) bool {
	switch op {
	case "", "eq":
		return c == 0
	case "ne":
		return c != 0
	case "gt":
		return c > 0
	case "gte":
		return c >= 0
	case "lt":
		return c < 0
	case "lte":
		return c <= 0
	}
	return false
}
func Compare(actual any, op, want string) (bool, error) {
	if actual == nil {
		return false, fmt.Errorf("field value is unavailable")
	}
	switch op {
	case "contains":
		return strings.Contains(fmt.Sprint(actual), want), nil
	case "matches":
		r, e := regexp.Compile(want)
		if e != nil {
			return false, e
		}
		return r.MatchString(fmt.Sprint(actual)), nil
	case "version":
		return VersionMatches(fmt.Sprint(actual), want)
	case "", "eq", "ne", "gt", "gte", "lt", "lte":
	default:
		return false, fmt.Errorf("unknown comparison %q", op)
	}
	switch n := actual.(type) {
	case float64:
		v, e := strconv.ParseFloat(want, 64)
		if e != nil || math.IsNaN(v) || math.IsInf(v, 0) {
			return false, fmt.Errorf("expected a finite number")
		}
		c := 0
		if n < v {
			c = -1
		} else if n > v {
			c = 1
		}
		return ordered(c, op), nil
	case bool:
		v, e := strconv.ParseBool(want)
		if e != nil {
			return false, e
		}
		if op != "" && op != "eq" && op != "ne" {
			return false, fmt.Errorf("boolean requires eq or ne")
		}
		return (n == v) != (op == "ne"), nil
	default:
		return ordered(strings.Compare(fmt.Sprint(actual), want), op), nil
	}
}
func Rows(rows []map[string]any, c proto.DeployCheck, params map[string]string) (bool, error) {
	matched := 0
	for _, row := range rows {
		ok := true
		for _, p := range c.Rows {
			v, exists := row[p.Field]
			if !exists {
				return false, fmt.Errorf("sensor field %q missing", p.Field)
			}
			want := p.Value
			if p.Parameter != "" {
				var found bool
				want, found = params[p.Parameter]
				if !found {
					return false, fmt.Errorf("missing parameter %s", p.Parameter)
				}
			}
			yes, e := Compare(v, p.Operator, want)
			if e != nil {
				return false, e
			}
			ok = ok && yes
		}
		if ok {
			matched++
		}
	}
	switch c.Quantifier {
	case "", "any":
		return matched > 0, nil
	case "none":
		return matched == 0, nil
	case "all":
		return (len(rows) > 0 || c.AllowEmpty) && matched == len(rows), nil
	case "count":
		return Compare(float64(matched), c.Operator, c.Value)
	}
	return false, fmt.Errorf("invalid row quantifier %q", c.Quantifier)
}
func Parameters(defs []proto.DeployParameter, inputs map[string]string) (map[string]string, error) {
	out := map[string]string{}
	known := map[string]bool{}
	names := map[string]bool{}
	for _, d := range defs {
		if !identifier.MatchString(d.Name) {
			return nil, fmt.Errorf("invalid parameter name %q", d.Name)
		}
		if names[strings.ToLower(d.Name)] {
			return nil, fmt.Errorf("parameter names collide ignoring case")
		}
		names[strings.ToLower(d.Name)] = true
		known[d.Name] = true
		v := d.Default
		if x, ok := inputs[d.Name]; ok {
			v = x
		}
		if len(v) > 32768 || strings.ContainsRune(v, 0) {
			return nil, fmt.Errorf("parameter %s exceeds input limits or contains NUL", d.Name)
		}
		if d.Required && v == "" {
			return nil, fmt.Errorf("parameter %s is required", d.Name)
		}
		switch d.Type {
		case "text", "":
		case "numeric":
			if v != "" {
				n, e := strconv.ParseFloat(v, 64)
				if e != nil || math.IsNaN(n) || math.IsInf(n, 0) || (d.Min != nil && n < *d.Min) || (d.Max != nil && n > *d.Max) {
					return nil, fmt.Errorf("parameter %s is outside its numeric constraints", d.Name)
				}
			}
		case "select":
			if v != "" && !slices.Contains(d.Options, v) {
				return nil, fmt.Errorf("invalid choice for %s", d.Name)
			}
		case "checkbox":
			if v == "" {
				v = "false"
			}
			if v != "true" && v != "false" {
				return nil, fmt.Errorf("parameter %s must be true or false", d.Name)
			}
		default:
			return nil, fmt.Errorf("invalid parameter type %s", d.Type)
		}
		out[d.Name] = v
	}
	for name := range inputs {
		if !known[name] {
			return nil, fmt.Errorf("unknown parameter %s", name)
		}
	}
	return out, nil
}
func MergeParameters(groups ...[]proto.DeployParameter) []proto.DeployParameter {
	out := []proto.DeployParameter{}
	indexes := map[string]int{}
	for _, group := range groups {
		for _, p := range group {
			if i, ok := indexes[p.Name]; ok {
				out[i] = p
			} else {
				indexes[p.Name] = len(out)
				out = append(out, p)
			}
		}
	}
	return out
}
func Bind(bindings map[string]proto.DeployBinding, params map[string]string) (map[string]string, error) {
	out := map[string]string{}
	for name, b := range bindings {
		v := b.Value
		if b.Parameter != "" {
			var ok bool
			v, ok = params[b.Parameter]
			if !ok {
				return nil, fmt.Errorf("binding %s references missing parameter %s", name, b.Parameter)
			}
		}
		out[name] = v
	}
	return out, nil
}
func SelectVariant(def proto.DeployDefinition, os, arch, distribution, version string) (*proto.DeployVariant, error) {
	var found *proto.DeployVariant
	for _, v := range def.Variants {
		if v.OS != os || (len(v.Arch) > 0 && !slices.Contains(v.Arch, arch)) || (len(v.Distribution) > 0 && !slices.Contains(v.Distribution, distribution)) {
			continue
		}
		ok, e := VersionMatches(version, v.OSVersion)
		if e != nil {
			return nil, e
		}
		if !ok {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("ambiguous variants %s and %s", found.ID, v.ID)
		}
		copy := v
		found = &copy
	}
	if found == nil {
		return nil, fmt.Errorf("no configuration for %s/%s %s %s", os, arch, distribution, version)
	}
	return found, nil
}

// DefinitionError is a validation failure that belongs to one place in a
// definition: a platform variant, optionally one of its operations, and the
// section of the editor that holds the fix. The console uses the location to
// open that platform and operation and highlight the section; the message is
// written for the person reading it, naming the platform rather than the
// variant's internal ID.
type DefinitionError struct {
	VariantID string `json:"variant_id"`
	OS        string `json:"os"`
	Operation string `json:"operation,omitempty"`
	// Section is the editor area: details, requirements, detection,
	// actions, action_requirements, validation, steps or files.
	Section string `json:"section"`
	Message string `json:"message"`
}

func (e *DefinitionError) Error() string {
	if e.OS == "" {
		return e.Message
	}
	where := osLabel(e.OS)
	if e.Operation != "" {
		where += " · " + operationLabel(e.Operation)
	}
	return where + ": " + e.Message
}

func osLabel(os string) string {
	switch os {
	case "windows":
		return "Windows"
	case "darwin":
		return "macOS"
	case "linux":
		return "Linux"
	}
	return os
}

func operationLabel(op string) string {
	switch op {
	case "install":
		return "Install"
	case "update":
		return "Update"
	case "remove":
		return "Uninstall"
	case "run":
		return "Run"
	}
	return op
}

func located(v proto.DeployVariant, op, section, format string, args ...any) error {
	return &DefinitionError{VariantID: v.ID, OS: v.OS, Operation: op, Section: section, Message: fmt.Sprintf(format, args...)}
}

// inSection places an error from a nested check (ValidateCheck) at its
// variant, operation and section.
func inSection(v proto.DeployVariant, op, section string, e error) error {
	if e == nil {
		return nil
	}
	return located(v, op, section, "%s", e.Error())
}

func ValidateDefinition(d proto.DeployDefinition, published bool) error {
	if published && d.ReviewRequired {
		return fmt.Errorf("review converted commands, parameter bindings, and file scopes before publishing")
	}
	if d.Version < 1 || d.Version > proto.DeployVersion {
		return fmt.Errorf("unsupported Deploy definition version")
	}
	if len(d.Variants) == 0 || len(d.Variants) > 64 {
		return fmt.Errorf("define between 1 and 64 platform variants")
	}
	if e := ValidateParameters(d.Parameters); e != nil {
		return e
	}
	if d.Kind != "" && d.Kind != "software" && d.Kind != "action" {
		return fmt.Errorf("invalid package kind")
	}
	if d.Kind == "action" && d.Version < 2 {
		return fmt.Errorf("action packages require Deploy version 2")
	}
	if d.Kind != "action" && len(d.Files) > 0 {
		return fmt.Errorf("shared files require an action package")
	}
	parameterTypes := map[string]string{}
	for _, v := range d.Variants {
		for _, p := range MergeParameters(d.Parameters, v.Parameters, v.Actions["run"].Parameters) {
			typ := p.Type
			if typ == "" {
				typ = "text"
			}
			if previous, ok := parameterTypes[strings.ToLower(p.Name)]; d.Kind == "action" && ok && previous != typ {
				return fmt.Errorf("parameter %s must have the same type on every platform", p.Name)
			}
			parameterTypes[strings.ToLower(p.Name)] = typ
		}
		for _, p := range append(append([]proto.DeployParameter{}, d.Parameters...), v.Parameters...) {
			typ := p.Type
			if typ == "" {
				typ = "text"
			}
			if previous, ok := parameterTypes[strings.ToLower(p.Name)]; d.Kind == "action" && ok && previous != typ {
				return fmt.Errorf("parameter %s cannot override its shared type", p.Name)
			}
		}
	}
	seen := map[string]bool{}
	for _, v := range d.Variants {
		if e := ValidateParameters(v.Parameters); e != nil {
			return e
		}
		if !pathID.MatchString(v.ID) || seen[v.ID] {
			return fmt.Errorf("variant IDs must be unique and nonempty")
		}
		seen[v.ID] = true
		if !slices.Contains([]string{"linux", "darwin", "windows"}, v.OS) {
			return fmt.Errorf("invalid platform %s", v.OS)
		}
		for _, a := range v.Arch {
			if a != "amd64" && a != "arm64" {
				return fmt.Errorf("invalid architecture %s", a)
			}
		}
		if published && d.Kind != "action" && v.Detection == nil {
			return located(v, "", "detection", "add an installed-software detection check before publishing, so endpoints can tell whether it is already installed")
		}
		if published {
			if e := ValidateCheck(v.Requirements, 0); e != nil {
				return inSection(v, "", "requirements", e)
			}
			if e := ValidateCheck(v.Detection, 0); e != nil {
				return inSection(v, "", "detection", e)
			}
		}
		if published && len(v.Actions) == 0 {
			return located(v, "", "actions", "configure at least one operation (Install, Update or Uninstall) before publishing")
		}
		if d.Kind == "action" && (v.Detection != nil || v.Requirements != nil) {
			return fmt.Errorf("action variants do not have detection or requirements")
		}
		for op, a := range v.Actions {
			if d.Kind == "action" {
				for _, step := range a.Steps {
					if step.Script != nil {
						for _, p := range MergeParameters(d.Parameters, v.Parameters, a.Parameters) {
							if strings.Contains(step.Script.Source, "$("+p.Name+")") {
								return fmt.Errorf("parameter %s must use MUSTRA_PARAM_%s environment binding instead of legacy substitution", p.Name, p.Name)
							}
						}
					}
				}
				if op != "run" || a.Requirements != nil || len(a.Dependencies) > 0 || a.ValidateAfterReboot {
					return fmt.Errorf("action packages support Run only, without requirements, dependencies or reboot workflows")
				}
				if !slices.Contains([]string{"", "exit_code", "sensor", "both"}, a.SuccessMode) {
					return fmt.Errorf("invalid success mode")
				}
				if (a.SuccessMode == "sensor" || a.SuccessMode == "both") != (a.Validation != nil) {
					return fmt.Errorf("select a sensor condition for sensor or both success mode only")
				}
				if a.Validation != nil && !sensorCondition(a.Validation) {
					return fmt.Errorf("action verification must use sensor conditions")
				}
				if len(a.Steps) != 1 || a.Steps[0].If != nil || a.Steps[0].RetrySafe || a.Steps[0].Retries != 0 || a.Steps[0].ContinueOnError || len(a.Steps[0].RebootCodes) != 0 || len(a.Steps[0].Then)+len(a.Steps[0].Else) != 0 {
					return fmt.Errorf("action packages require one command without automatic retries or branches")
				}
				a.Files = append(append([]proto.DeployFile{}, d.Files...), a.Files...)
				a.RequireFiles = len(a.Files) > 0
			}
			if a.DownloadSeconds < 0 || a.DownloadSeconds > 86400 {
				return fmt.Errorf("download timeout must be 0 (30 minute default)–86400 seconds")
			}
			if e := ValidateParameters(a.Parameters); e != nil {
				return e
			}
			if d.Kind != "action" && !slices.Contains([]string{"install", "update", "remove"}, op) {
				return fmt.Errorf("invalid operation %s", op)
			}
			if published && d.Kind != "action" && a.Validation == nil {
				return located(v, op, "validation", "add a post-action validation check before publishing, so the endpoint can confirm the %s worked", strings.ToLower(operationLabel(op)))
			}
			if published {
				if e := ValidateCheck(a.Requirements, 0); e != nil {
					return inSection(v, op, "action_requirements", e)
				}
				if e := ValidateCheck(a.Validation, 0); e != nil {
					return inSection(v, op, "validation", e)
				}
			}
			if a.Identity != "" && a.Identity != "administrator" && a.Identity != "user" {
				return fmt.Errorf("invalid execution identity")
			}
			if a.ValidationSeconds < 0 || a.ValidationSeconds > 3600 {
				return fmt.Errorf("validation wait must be 0–3600 seconds")
			}
			files := map[string]bool{}
			names := map[string]bool{}
			for _, f := range a.Files {
				if f.ID == "" || files[f.ID] || f.Name == "" || strings.ContainsAny(f.Name, "/\\") || f.Name == "." || f.Name == ".." || names[f.Name] {
					return fmt.Errorf("invalid or duplicate action file")
				}
				files[f.ID] = true
				names[f.Name] = true
				if !hash.MatchString(f.SHA256) {
					return fmt.Errorf("file %s requires SHA-256", f.Name)
				}
				if f.URL != "" {
					u, e := url.Parse(f.URL)
					if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
						return fmt.Errorf("direct downloads require HTTPS without embedded credentials")
					}
				}
			}
			if published && a.RequireFiles && len(files) == 0 {
				return fmt.Errorf("require files is enabled but no files are selected")
			}
			ids := map[string]bool{}
			count := 0
			if e := validateSteps(a.Steps, v.OS, a.RequireFiles, files, ids, 0, &count); published && e != nil {
				return e
			}
			if published && len(a.Steps) == 0 {
				return fmt.Errorf("%s/%s needs at least one step", v.ID, op)
			}
			for _, dep := range a.Dependencies {
				if published && (dep.PackageID == "" || dep.RevisionID == "") {
					return fmt.Errorf("dependency needs a package and pinned revision")
				}
			}
		}
	}
	return nil
}
func validateSteps(steps []proto.DeployStep, os string, required bool, files, ids map[string]bool, depth int, count *int) error {
	if depth > 8 {
		return fmt.Errorf("branches exceed 8 levels")
	}
	for _, s := range steps {
		*count++
		if *count > 256 {
			return fmt.Errorf("action exceeds 256 steps")
		}
		if !pathID.MatchString(s.ID) || ids[s.ID] {
			return fmt.Errorf("step IDs must be unique and nonempty")
		}
		ids[s.ID] = true
		for _, code := range append(append([]int{}, s.SuccessCodes...), s.RebootCodes...) {
			if code < 0 || code > 65535 {
				return fmt.Errorf("exit codes must be 0–65535")
			}
		}
		if s.Retries < 0 || s.Retries > 5 || s.Retries > 0 && !s.RetrySafe {
			return fmt.Errorf("retries require retry-safe steps and a maximum of 5")
		}
		if s.If != nil {
			if s.Script != nil {
				return fmt.Errorf("a step cannot be both branch and script")
			}
			if e := ValidateCheck(s.If, 0); e != nil {
				return e
			}
			for _, branch := range [][]proto.DeployStep{s.Then, s.Else} {
				if e := validateSteps(branch, os, required, files, ids, depth+1, count); e != nil {
					return e
				}
			}
		} else {
			if s.Script == nil {
				return fmt.Errorf("step %s needs a script or condition", s.ID)
			}
			if e := ValidateScript(*s.Script, os); e != nil {
				return e
			}
		}
		for _, id := range s.Files {
			if !required || !files[id] {
				return fmt.Errorf("step %s refers to an unavailable file %s", s.ID, id)
			}
		}
	}
	return nil
}
func ValidateScript(s proto.DeployScript, os string) error {
	langs := []string{"python", "go"}
	if os == "windows" {
		langs = append(langs, "powershell", "batch")
	} else {
		langs = append(langs, "shell")
	}
	if !slices.Contains(langs, s.Language) || strings.TrimSpace(s.Source) == "" || len(s.Source) > 512<<10 {
		return fmt.Errorf("invalid or unsupported script for %s", os)
	}
	if s.TimeoutSeconds < 0 || s.TimeoutSeconds > 86400 {
		return fmt.Errorf("script timeout must be 0–86400 seconds")
	}
	return nil
}
func ValidateCheck(c *proto.DeployCheck, depth int) error {
	if c == nil {
		return nil
	}
	if depth > 8 {
		return fmt.Errorf("checks exceed 8 levels")
	}
	switch c.Kind {
	case "and", "or", "not":
		if len(c.Children) == 0 || len(c.Children) > 64 || c.Kind == "not" && len(c.Children) != 1 {
			return fmt.Errorf("invalid logical check")
		}
	case "file_exists", "directory_exists", "file_hash", "file_version", "disk_free", "registry":
		if c.Path == "" {
			return fmt.Errorf("%s needs a path", c.Kind)
		}
	case "sensor":
		if c.SensorID == "" {
			return fmt.Errorf("select a sensor")
		}
	case "script":
		if c.Script == nil {
			return fmt.Errorf("check needs a script")
		}
	case "app", "service", "process", "os", "arch", "ram":
	default:
		return fmt.Errorf("unsupported check %q", c.Kind)
	}
	if len(c.Rows) > 64 {
		return fmt.Errorf("sensor check exceeds 64 filters")
	}
	if !slices.Contains([]string{"", "any", "none", "all", "count"}, c.Quantifier) {
		return fmt.Errorf("invalid row quantifier")
	}
	for _, p := range append(append([]proto.DeployPredicate{}, c.Rows...), proto.DeployPredicate{Operator: c.Operator, Value: c.Value}) {
		if !slices.Contains([]string{"", "eq", "ne", "gt", "gte", "lt", "lte", "contains", "matches", "version"}, p.Operator) {
			return fmt.Errorf("invalid comparison %s", p.Operator)
		}
		if p.Operator == "matches" {
			if _, e := regexp.Compile(p.Value); e != nil {
				return e
			}
		}
	}
	for _, child := range c.Children {
		if e := ValidateCheck(&child, depth+1); e != nil {
			return e
		}
	}
	return nil
}
func Terminal(status string) bool {
	return slices.Contains([]string{"succeeded", "failed", "timed_out", "cancelled", "interrupted", "expired", "skipped", "unsupported"}, status)
}

func ValidateParameters(defs []proto.DeployParameter) error {
	seen := map[string]bool{}
	for _, p := range defs {
		key := strings.ToLower(p.Name)
		if !identifier.MatchString(p.Name) || seen[key] {
			return fmt.Errorf("parameter names must be valid and unique, ignoring case")
		}
		seen[key] = true
		if p.Secret && p.Default != "" {
			return fmt.Errorf("secret parameter %s must be supplied at invocation, not stored as a default", p.Name)
		}
		if p.Min != nil && (math.IsNaN(*p.Min) || math.IsInf(*p.Min, 0)) || p.Max != nil && (math.IsNaN(*p.Max) || math.IsInf(*p.Max, 0)) {
			return fmt.Errorf("parameter bounds must be finite")
		}
		if p.Min != nil && p.Max != nil && *p.Min > *p.Max {
			return fmt.Errorf("parameter minimum exceeds maximum")
		}
		optional := p
		optional.Required = false
		if _, e := Parameters([]proto.DeployParameter{optional}, nil); e != nil {
			return e
		}
	}
	return nil
}

// Action checks observe sensor rows; they never become software requirements.
func sensorCondition(c *proto.DeployCheck) bool {
	if c.Kind == "sensor" {
		return true
	}
	if c.Kind != "and" && c.Kind != "or" && c.Kind != "not" {
		return false
	}
	for i := range c.Children {
		if !sensorCondition(&c.Children[i]) {
			return false
		}
	}
	return len(c.Children) > 0
}

func RequiredVersion(j proto.DeployJob) int {
	for _, p := range j.Packages {
		if p.Operation == "run" {
			return 2
		}
	}
	return 1
}
