//go:build windows

package main

import (
	"log/slog"
	"os/exec"
)

func executeSystemReboot(logger *slog.Logger) {
	cmd := exec.Command("shutdown", "/r", "/t", "0")
	if err := cmd.Run(); err != nil {
		logger.Error("Failed to reboot Windows host", "error", err)
	}
}
