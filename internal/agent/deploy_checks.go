package agent

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/deploy"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/sensoroutput"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/mem"
)

func (r *deployRunner) check(ctx context.Context, p proto.DeployPackagePlan, c *proto.DeployCheck) (bool, error) {
	if c == nil {
		return true, nil
	}
	if e := deploy.ValidateCheck(c, 0); e != nil {
		return false, e
	}
	if c.Kind == "and" || c.Kind == "or" || c.Kind == "not" {
		result := c.Kind == "and"
		for _, child := range c.Children {
			ok, e := r.check(ctx, p, &child)
			if e != nil {
				return false, e
			}
			if c.Kind == "not" {
				return !ok, nil
			}
			if c.Kind == "and" {
				result = result && ok
			} else {
				result = result || ok
			}
		}
		return result, nil
	}
	want := c.Value
	if c.Parameter != "" {
		var ok bool
		want, ok = p.Parameters[c.Parameter]
		if !ok {
			return false, fmt.Errorf("missing parameter %s", c.Parameter)
		}
	}
	var value any
	switch c.Kind {
	case "file_exists", "directory_exists":
		st, e := os.Stat(c.Path)
		if os.IsNotExist(e) {
			return false, nil
		}
		if e != nil {
			return false, e
		}
		return (c.Kind == "directory_exists") == st.IsDir(), nil
	case "file_hash":
		f, e := os.Open(c.Path)
		if e != nil {
			return false, e
		}
		defer f.Close()
		h := sha256.New()
		if _, e = io.Copy(h, f); e != nil {
			return false, e
		}
		value = fmt.Sprintf("%x", h.Sum(nil))
	case "file_version":
		v, e := deployFileVersion(ctx, c.Path)
		if e != nil {
			return false, e
		}
		value = v
	case "registry":
		v, e := deployRegistryValue(c.Path, c.Name)
		if e != nil {
			return false, e
		}
		value = v
	case "os":
		value = runtime.GOOS
	case "arch":
		value = runtime.GOARCH
	case "ram":
		m, e := mem.VirtualMemoryWithContext(ctx)
		if e != nil {
			return false, e
		}
		value = float64(m.Total) / 1000000
	case "disk_free":
		d, e := disk.UsageWithContext(ctx, c.Path)
		if e != nil {
			return false, e
		}
		value = float64(d.Free) / 1000000000
	case "script":
		def := proto.CustomSensorDef{Command: c.Script.Source, Platform: proto.SensorPlatform{Language: c.Script.Language}, TimeoutSeconds: c.Script.TimeoutSeconds, Artifact: c.Script.Artifact, Inputs: p.Parameters}
		res := r.executeCheckSensor(ctx, p, def)
		if res.TimedOut || res.Truncated {
			return false, fmt.Errorf("check script timed out or exceeded output limits")
		}
		if res.ExitCode == 1 && res.Error != "" {
			return false, nil
		}
		if res.Error != "" {
			return false, fmt.Errorf("check script: %s", res.Error)
		}
		return true, nil
	case "app", "service", "process", "sensor":
		kind := c.SensorID
		if c.Kind != "sensor" {
			kind = map[string]string{"app": "installed_apps", "service": "services", "process": "processes"}[c.Kind]
		}
		var rows []map[string]any
		var e error
		if c.Sensor != nil {
			def, ok := c.Sensor.Definitions[runtime.GOOS]
			if !ok {
				return false, fmt.Errorf("sensor %s has no %s implementation", c.SensorID, runtime.GOOS)
			}
			inputs, e := deploy.Bind(c.Inputs, p.Parameters)
			if e != nil {
				return false, e
			}
			inputs, e = deploy.Parameters(c.Sensor.Parameters, inputs)
			if e != nil {
				return false, e
			}
			r.mu.Lock()
			for _, parameter := range c.Sensor.Parameters {
				if parameter.Secret {
					r.secrets = append(r.secrets, inputs[parameter.Name])
				}
			}
			r.mu.Unlock()
			def.Inputs = inputs
			res := r.executeCheckSensor(ctx, p, def)
			if res.Error != "" || res.TimedOut || res.Truncated {
				return false, fmt.Errorf("sensor %s failed: %s", c.SensorID, res.Error)
			}
			if res.Raw == nil {
				return false, fmt.Errorf("sensor output is missing")
			}
			rows, e = sensoroutput.Parse(*res.Raw, def.Platform.Output, c.Sensor.Fields)
		} else {
			if kind == "file_events" || kind == "process_events" {
				path := ""
				for _, filter := range c.Rows {
					if filter.Field == "path" && (filter.Operator == "eq" || filter.Operator == "") {
						path = filter.Value
						if filter.Parameter != "" {
							path = p.Parameters[filter.Parameter]
						}
					}
				}
				rows, e = r.a.deployHistoryRows(kind, c.LookbackSeconds, path)
			} else {
				rows, e = r.a.deploySensorRows(ctx, kind, c.LookbackSeconds)
			}
		}
		if e != nil {
			return false, e
		}
		predicate := *c
		if c.Kind != "sensor" {
			predicate.Quantifier = "any"
			predicate.Rows = []proto.DeployPredicate{{Field: "name", Operator: "eq", Value: c.Name}}
			if c.Field != "" {
				predicate.Rows = append(predicate.Rows, proto.DeployPredicate{Field: c.Field, Operator: c.Operator, Value: want})
			}
		}
		ok, e := deploy.Rows(rows, predicate, p.Parameters)
		if e == nil {
			raw, _ := json.Marshal(rows)
			if len(raw) > 16384 {
				raw = []byte("[evidence truncated after 16 KB]")
			}
			r.event(p.PackageID, "", "check", "running", fmt.Sprintf("sensor %s: agent=%s revision=%s match=%t rows=%s", kind, r.a.cfg.AgentVersion, func() string {
				if c.Sensor != nil {
					return c.Sensor.Definitions[runtime.GOOS].Revision
				}
				return "builtin"
			}(), ok, raw))
		}
		return ok, e
	default:
		return false, fmt.Errorf("unsupported check %s", c.Kind)
	}
	return deploy.Compare(value, c.Operator, want)
}
func (a *Agent) deploySensorRows(ctx context.Context, kind string, lookback int) ([]map[string]any, error) {
	cctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	var data any
	var e error
	switch proto.SensorKind(kind) {
	case proto.SensorProcesses:
		data, e = collectProcesses(cctx)
	case proto.SensorServices:
		data, e = collectServices(cctx)
	case proto.SensorInstalledApps:
		data, e = collectInstalledApps(cctx)
	case proto.SensorPatches:
		a.deployMu.Lock()
		nc := a.nc
		a.deployMu.Unlock()
		if nc == nil || !nc.IsConnected() {
			return nil, fmt.Errorf("patch sensor requires a server connection")
		}
		data, e = collectPatches(cctx, nc, a.agentID)
	case proto.SensorHardware:
		data, e = collectHardware(cctx)
	case proto.SensorDisks:
		data, e = collectDisks(cctx)
	case proto.SensorNetwork:
		data, e = collectNetworkInterfaces(cctx)
	case proto.SensorUsers:
		data, e = collectLoggedInUsers(cctx)
	case proto.SensorPrivileges:
		var v proto.PrivilegeInfo
		v, e = collectPrivileges(cctx)
		data = []proto.PrivilegeInfo{v}
	case proto.SensorNeighbors:
		data, e = collectNeighbors(cctx)
	case proto.SensorCertificates:
		data, e = collectCertificates(cctx)
	case proto.SensorPerformance:
		data, e = collectPerformance(cctx)
	case proto.SensorIntegrity:
		data, e = collectIntegrity(cctx)
	case proto.SensorLocalAdmins:
		data, e = collectLocalAdmins(cctx)
	case proto.SensorDirectory:
		data, e = collectDirectory(cctx)
	case proto.SensorBackups:
		data, e = collectBackups(cctx)
	case proto.SensorContainers:
		data, e = a.containers.collect(cctx)
	case proto.SensorSecurityPosture:
		data, e = collectSecurityPosture(cctx)
	default:
		if kind == "facts" {
			v, err := collectFacts(cctx, a.agentID, a.info, a.cfg.AgentVersion)
			data = []proto.Facts{v}
			e = err
		} else if strings.Contains(kind, "event") {
			return a.deployHistoryRows(kind, lookback, "")
		} else {
			return nil, fmt.Errorf("unsupported sensor %s", kind)
		}
	}
	if e != nil {
		return nil, e
	}
	raw, e := json.Marshal(data)
	if e != nil {
		return nil, e
	}
	var rows []map[string]any
	if e = json.Unmarshal(raw, &rows); e != nil {
		return nil, e
	}
	return rows, nil
}

func (r *deployRunner) executeCheckSensor(ctx context.Context, p proto.DeployPackagePlan, def proto.CustomSensorDef) proto.CustomSensorResult {
	if p.Operation == "run" {
		a := p.Variant.Actions[p.Operation]
		return executeCustomSensorAs(ctx, def, a.Identity, a.Username)
	}
	return executeCustomSensor(ctx, def)
}

func (r *deployRunner) verify(ctx context.Context, p proto.DeployPackagePlan, a proto.DeployAction) error {
	budget := a.ValidationSeconds
	if budget == 0 {
		budget = 600
	} // A single collection still has a hard deadline.
	if r.st.VerificationDeadline.IsZero() || p.Operation != "run" {
		r.st.VerificationDeadline = time.Now().Add(time.Duration(budget) * time.Second)
		if e := r.checkpoint(); e != nil {
			return e
		}
	}
	checkCtx, cancel := context.WithDeadline(ctx, r.st.VerificationDeadline)
	defer cancel()
	for {
		ok, e := r.check(checkCtx, p, a.Validation)
		if checkCtx.Err() != nil {
			return fmt.Errorf("verification phase: %w", checkCtx.Err())
		}
		if e != nil {
			r.event(p.PackageID, "", "verification_error", "running", e.Error())
			return fmt.Errorf("verification error: %w", e)
		}
		if ok {
			r.event(p.PackageID, "", "verification_result", "running", "Sensor verification passed")
			return nil
		}
		if a.ValidationSeconds == 0 {
			return fmt.Errorf("sensor verification did not pass for %s", p.Name)
		}
		select {
		case <-checkCtx.Done():
			return fmt.Errorf("verification phase: %w", checkCtx.Err())
		case <-time.After(3 * time.Second):
		}
	}
}
