//go:build !windows

package main

import "github.com/ocoj/ddns-manager/internal/model"

func runWindowsService(cfg *model.AgentConfig) {
	// never called on non-Windows
}
