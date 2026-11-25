//go:build linux

/*
SPDX-License-Identifier: Apache-2.0
*/

package main

import "syscall"

func execute(path string, args, env []string) error {
	return syscall.Exec(path, args, env)
}
