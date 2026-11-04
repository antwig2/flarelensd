//go:build windows

package system

// IsRebootRequired checks if Windows has pending updates requiring a reboot.
func IsRebootRequired() bool {
	return false
}
