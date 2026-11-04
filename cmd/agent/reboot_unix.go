//go:build !windows

package main

import (
	"log/slog"
	"os/exec"
	"syscall"
)

func executeSystemReboot(logger *slog.Logger) {
	syscall.Sync()
	cmd := exec.Command("systemctl", "reboot")
	if err := cmd.Run(); err != nil {
		logger.Error("Failed to reboot via systemctl; attempting shutdown -r now", "error", err)
		_ = exec.Command("shutdown", "-r", "now").Run()
	}
}
