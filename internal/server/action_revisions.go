package server

import (
	"context"
	"fmt"

	"github.com/mustra-dev/mustra/internal/deploy"
	"github.com/mustra-dev/mustra/internal/proto"
)

func validateRevisionInputs(d proto.DeployDefinition, operation, os string, inputs map[string]string) error {
	known := map[string]bool{}
	matched := false
	for _, v := range d.Variants {
		if os != "" && v.OS != os {
			continue
		}
		a, ok := v.Actions[operation]
		if !ok {
			continue
		}
		matched = true
		defs := deploy.MergeParameters(d.Parameters, v.Parameters, a.Parameters)
		values := map[string]string{}
		for _, p := range defs {
			known[p.Name] = true
			if value, ok := inputs[p.Name]; ok {
				values[p.Name] = value
			}
		}
		if _, e := deploy.Parameters(defs, values); e != nil {
			return fmt.Errorf("%s: %w", v.OS, e)
		}
	}
	if !matched {
		return fmt.Errorf("replacement has no %s configuration for the selected platforms", operation)
	}
	for key := range inputs {
		if !known[key] {
			return fmt.Errorf("unknown parameter %s", key)
		}
	}
	return nil
}

// Freeze follow-latest once per invocation and validate every package input
// before any playbook command runs. Historical runs keep the resolved IDs.
func (s *Server) freezePlaybookRevisions(ctx context.Context, steps []playbookStep, targetOS string) error {
	for i := range steps {
		st := &steps[i]
		if st.Kind != "package" {
			continue
		}
		pkg, e := s.store.GetSoftwarePackage(ctx, st.PackageID)
		if e != nil {
			return e
		}
		if pkg == nil {
			return fmt.Errorf("package no longer exists")
		}
		if pkg.DeployRevision == "" {
			continue
		}
		if st.RevisionID == "" || st.FollowLatest {
			st.RevisionID = pkg.DeployRevision
		}
		rev, e := s.store.GetDeployRevision(ctx, st.RevisionID)
		if e != nil {
			return e
		}
		if rev == nil || !rev.Published || rev.Retired || rev.PackageID != pkg.ID {
			return fmt.Errorf("%s: version unavailable or retired; update the playbook reference", st.label(i))
		}
		if st.Operation == "" {
			st.Operation = "install"
			if rev.Definition.Kind == "action" {
				st.Operation = "run"
			}
		}
		if e = validateRevisionInputs(rev.Definition, st.Operation, targetOS, st.Params); e != nil {
			return fmt.Errorf("%s: %w", st.label(i), e)
		}
		st.FollowLatest = false
	}
	return nil
}
