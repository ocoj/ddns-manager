//go:build !windows

package main

import "github.com/kk/ddns-manager/internal/model"

func runWindowsService(cfg *model.AgentConfig) {
	// never called on non-Windows
}
