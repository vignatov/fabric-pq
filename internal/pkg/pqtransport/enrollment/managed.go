/*
SPDX-License-Identifier: Apache-2.0
*/

package enrollment

import (
	"crypto/mldsa"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

const managedEnvironment = "FABRIC_PQ_MANAGED_ENROLLMENT"

// Evidence identifies the operator-protected files used by the launcher and
// independently re-verified by the node it executes.
type Evidence struct {
	Authority string
	Manifest  string
	History   string
}

func (e Evidence) Load() (*Manifest, error) {
	paths := []string{e.Authority, e.Manifest, e.History}
	for _, path := range paths {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return nil, errors.New("provisioning paths must be absolute and clean")
		}
	}
	raw, err := os.ReadFile(e.Authority)
	if err != nil {
		return nil, fmt.Errorf("read provisioning authority: %w", err)
	}
	key, err := mldsa.NewPublicKey(mldsa.MLDSA65(), raw)
	if err != nil {
		return nil, fmt.Errorf("parse provisioning authority: %w", err)
	}
	manifest, err := os.ReadFile(e.Manifest)
	if err != nil {
		return nil, fmt.Errorf("read enrollment manifest: %w", err)
	}
	history, err := os.ReadFile(e.History)
	if err != nil {
		return nil, fmt.Errorf("read enrollment history: %w", err)
	}
	verified, err := Verify(manifest, history, key)
	if err != nil || verified.Mode != Protected {
		return verified, err
	}
	for _, dir := range []string{verified.StateDir, verified.LedgerDir} {
		root, err := filepath.EvalSymlinks(dir)
		if err != nil {
			return nil, fmt.Errorf("resolve protected state directory: %w", err)
		}
		for _, path := range append(paths, verified.Executable) {
			resolved, err := filepath.EvalSymlinks(path)
			if err != nil {
				return nil, fmt.Errorf("resolve provisioning evidence: %w", err)
			}
			rel, err := filepath.Rel(root, resolved)
			if err != nil {
				return nil, err
			}
			if rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				return nil, errors.New("provisioning evidence and executable must be outside runtime security state")
			}
		}
	}
	return verified, nil
}

// NodeKind restricts the managed protected service to the supported startup
// entry points. Administrative and offline subcommands cannot be launched.
func (m *Manifest) NodeKind() (string, error) {
	name := filepath.Base(m.Executable)
	switch name {
	case "peer":
		if slices.Equal(m.Arguments, []string{"node", "start"}) {
			return name, nil
		}
	case "orderer":
		if len(m.Arguments) == 0 || slices.Equal(m.Arguments, []string{"start"}) {
			return name, nil
		}
	}
	return "", errors.New("protected enrollment must start the managed peer or orderer")
}

// Environment replaces any inherited handoff. The authenticated paths, not
// ordinary Fabric settings, determine whether a managed child may serve.
func (e Evidence) Environment(env []string, protected bool) ([]string, error) {
	result := slices.DeleteFunc(slices.Clone(env), func(value string) bool {
		return strings.HasPrefix(value, managedEnvironment+"=")
	})
	if !protected {
		return result, nil
	}
	data, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}
	return append(result, managedEnvironment+"="+string(data)), nil
}

func LoadManaged(kind string) (*Registry, error) {
	value, present := os.LookupEnv(managedEnvironment)
	if !present {
		return nil, nil
	}
	var evidence Evidence
	if err := decodeCanonical([]byte(value), &evidence); err != nil {
		return nil, fmt.Errorf("read managed enrollment handoff: %w", err)
	}
	manifest, err := evidence.Load()
	if err != nil {
		return nil, err
	}
	nodeKind, err := manifest.NodeKind()
	if err != nil || manifest.Mode != Protected || nodeKind != kind || !slices.Equal(manifest.Arguments, os.Args[1:]) {
		return nil, errors.New("managed startup conflicts with the signed node command")
	}
	executable, err := os.Executable()
	if err != nil {
		return nil, err
	}
	if err := samePath(executable, manifest.Executable); err != nil {
		return nil, fmt.Errorf("managed executable: %w", err)
	}
	return OpenProtectedRegistry(manifest)
}

// CheckLedgerRoot rejects a configured ledger location outside the signed
// enrollment. Existing directories are resolved before comparison.
func (r *Registry) CheckLedgerRoot(configured string) error {
	return samePath(configured, r.root)
}

func samePath(actual, expected string) error {
	left, err := filepath.EvalSymlinks(actual)
	if err != nil {
		return err
	}
	right, err := filepath.EvalSymlinks(expected)
	if err != nil {
		return err
	}
	left, err = filepath.Abs(left)
	if err != nil {
		return err
	}
	right, err = filepath.Abs(right)
	if err != nil {
		return err
	}
	if left != right {
		return fmt.Errorf("path %q conflicts with signed path %q", left, right)
	}
	return nil
}
