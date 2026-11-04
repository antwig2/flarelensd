//go:build !windows

package system

import "os"

// IsRebootRequired checks if the operating system has pending kernel/security updates requiring a reboot.
// On Debian/Ubuntu, /var/run/reboot-required is created by unattended-upgrades or apt.
func IsRebootRequired() bool {
	_, err := os.Stat("/var/run/reboot-required")
	return err == nil
}
