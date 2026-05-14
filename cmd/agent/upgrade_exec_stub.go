//go:build !windows

package main

import "fmt"

// upgradeExecMode stub — only called on Windows.
func upgradeExecMode(oldPath, newPath string) error {
	return fmt.Errorf("upgrade-exec is Windows-only")
}
