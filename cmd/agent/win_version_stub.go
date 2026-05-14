//go:build !windows

package main

func useModernPFX() bool { return false }
func isIISInstalled() bool { return false }
