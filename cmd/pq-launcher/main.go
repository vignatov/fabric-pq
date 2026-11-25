/*
SPDX-License-Identifier: Apache-2.0
*/

// pq-launcher is intended for an operator-protected Linux service definition.
// Its arguments and provisioning files must not be writable by the service
// account; invoking a Fabric binary outside that service is not controlled here.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/hyperledger/fabric/internal/pkg/pqtransport/enrollment"
)

func run(authorityPath, manifestPath, historyPath string) error {
	evidence := enrollment.Evidence{Authority: authorityPath, Manifest: manifestPath, History: historyPath}
	manifest, err := evidence.Load()
	if err != nil {
		return err
	}
	if manifest.Mode == enrollment.Protected {
		if err := enrollment.AuthenticateProtected(manifest); err != nil {
			return fmt.Errorf("authenticate protected runtime: %w", err)
		}
		if _, err := manifest.NodeKind(); err != nil {
			return err
		}
	}
	env, err := evidence.Environment(os.Environ(), manifest.Mode == enrollment.Protected)
	if err != nil {
		return err
	}
	return execute(manifest.Executable, append([]string{manifest.Executable}, manifest.Arguments...), env)
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
