//go:build !linux

/*
SPDX-License-Identifier: Apache-2.0
*/

package main

import "errors"

func execute(string, []string, []string) error {
	return errors.New("managed launcher is supported only on Linux")
}
