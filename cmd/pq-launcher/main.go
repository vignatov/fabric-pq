/*
SPDX-License-Identifier: Apache-2.0
*/

// pq-launcher is intended for an operator-protected Linux service definition.
// Its arguments and provisioning files must not be writable by the service
// account; invoking a Fabric binary outside that service is not controlled here.
package main

import (
	"crypto/mldsa"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hyperledger/fabric/internal/pkg/pqtransport/enrollment"
)

func run(authorityPath, manifestPath, historyPath string) error {
	for _, path := range []string{authorityPath, manifestPath, historyPath} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return errors.New("provisioning paths must be absolute and clean")
		}
	}
	keyBytes, err := os.ReadFile(authorityPath)
	if err != nil {
		return fmt.Errorf("read provisioning authority: %w", err)
	}
	key, err := mldsa.NewPublicKey(mldsa.MLDSA65(), keyBytes)
	if err != nil {
		return fmt.Errorf("parse provisioning authority: %w", err)
	}
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("read enrollment manifest: %w", err)
	}
	historyBytes, err := os.ReadFile(historyPath)
	if err != nil {
		return fmt.Errorf("read enrollment history: %w", err)
	}
	manifest, err := enrollment.Verify(manifestBytes, historyBytes, key)
	if err != nil {
		return err
	}
	if manifest.Mode == enrollment.Protected {
		for _, directory := range []string{manifest.StateDir, manifest.LedgerDir} {
			stateDir, err := filepath.EvalSymlinks(directory)
			if err != nil {
				return fmt.Errorf("resolve protected state directory: %w", err)
			}
			for _, path := range []string{authorityPath, manifestPath, historyPath} {
				resolved, err := filepath.EvalSymlinks(path)
				if err != nil {
					return fmt.Errorf("resolve provisioning evidence: %w", err)
				}
				rel, err := filepath.Rel(stateDir, resolved)
				if err != nil {
					return err
				}
				if rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
					return errors.New("provisioning evidence must be outside runtime security state")
				}
			}
		}
		if err := enrollment.AuthenticateProtected(manifest); err != nil {
			return fmt.Errorf("authenticate protected runtime: %w", err)
		}
		// The peer and orderer do not yet enforce every required strict
		// transport and service boundary. Never start either in this mode.
		return errors.New("protected managed startup is blocked pending strict transport and admission integration")
	}
	return execute(manifest.Executable, append([]string{manifest.Executable}, manifest.Arguments...), os.Environ())
}

func main() {
	authority := flag.String("authority", "", "absolute path to the provisioner public key")
	manifest := flag.String("manifest", "", "absolute path to the signed enrollment manifest")
	history := flag.String("history", "", "absolute path to the signed protected enrollment history")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "unexpected launcher arguments")
		os.Exit(2)
	}
	if err := run(*authority, *manifest, *history); err != nil {
		fmt.Fprintln(os.Stderr, "managed startup rejected:", err)
		os.Exit(1)
	}
}
