package system

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"time"
)

// CommandExecutor executes a host binary without a shell and returns combined stdout/stderr.
type CommandExecutor func(ctx context.Context, name string, args ...string) ([]byte, error)

// DefaultCommandExecutor executes commands directly via os/exec without invoking a shell.
func DefaultCommandExecutor(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

// UnitRetireResult reports the retirement status of a single systemd unit.
type UnitRetireResult struct {
	Unit   string `json:"unit"`
	Status string `json:"status"` // "retired", "not_present", "failed"
	Detail string `json:"detail,omitempty"`
}

var validSystemdUnitRe = regexp.MustCompile(`^[a-zA-Z0-9_.@-]+\.(timer|service)$`)

var protectedUnitPrefixes = []string{
	"flarelens",
	"docker",
	"containerd",
	"ssh.",
	"ssh@",
	"sshd",
	"wg-quick",
	"wireguard",
	"systemd",
	"dbus",
	"network",
	"ufw",
	"nftables",
	"iptables",
	"cloud-init",
	"cloudflared",
	"cron",
	"rsyslog",
	"journald",
}

// ValidateRetirableSystemdUnit enforces strict allowlist rules so host maintenance can never disable core OS/agent services or inject shell arguments.
func ValidateRetirableSystemdUnit(name string) error {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return errors.New("systemd unit name cannot be empty")
	}
	if strings.HasPrefix(trimmed, "-") || !validSystemdUnitRe.MatchString(trimmed) {
		return fmt.Errorf("invalid systemd unit name %q: must match ^[a-zA-Z0-9_.@-]+\\.(timer|service)$", trimmed)
	}
	lower := strings.ToLower(trimmed)
	for _, prefix := range protectedUnitPrefixes {
		if strings.HasPrefix(lower, prefix) {
			return fmt.Errorf("refusing to retire protected host unit %q", trimmed)
		}
	}
	return nil
}

// RetireSystemdUnits stops and disables legacy polling timers/services safely without SSH or shell invocation.
func RetireSystemdUnits(ctx context.Context, units []string, execFn CommandExecutor) ([]UnitRetireResult, error) {
	if execFn == nil {
		execFn = DefaultCommandExecutor
	}
	cleaned := make([]string, 0, len(units))
	for _, u := range units {
		trimmed := strings.TrimSpace(u)
		if trimmed == "" || slices.Contains(cleaned, trimmed) {
			continue
		}
		if err := ValidateRetirableSystemdUnit(trimmed); err != nil {
			return nil, err
		}
		cleaned = append(cleaned, trimmed)
	}
	if len(cleaned) == 0 {
		return nil, errors.New("no systemd units specified")
	}

	results := make([]UnitRetireResult, 0, len(cleaned))
	var errs []error

	for _, unit := range cleaned {
		loadOut, loadErr := execFn(ctx, "systemctl", "show", "--property=LoadState", "--value", unit)
		loadState := strings.TrimSpace(string(loadOut))
		if loadErr == nil && (loadState == "not-found" || loadState == "") {
			results = append(results, UnitRetireResult{
				Unit:   unit,
				Status: "not_present",
			})
			continue
		}

		stopOut, stopErr := execFn(ctx, "systemctl", "stop", unit)
		stopMsg := strings.TrimSpace(string(stopOut))
		if stopErr != nil && isSystemdUnitMissingOutput(stopMsg) {
			results = append(results, UnitRetireResult{
				Unit:   unit,
				Status: "not_present",
			})
			continue
		}

		disOut, disErr := execFn(ctx, "systemctl", "disable", unit)
		disMsg := strings.TrimSpace(string(disOut))
		if disErr != nil && !isSystemdUnitMissingOutput(disMsg) {
			err := fmt.Errorf("%s: disable failed (%v: %s)", unit, disErr, disMsg)
			errs = append(errs, err)
			results = append(results, UnitRetireResult{
				Unit:   unit,
				Status: "failed",
				Detail: disMsg,
			})
			continue
		}
		if stopErr != nil && !isSystemdUnitMissingOutput(stopMsg) {
			err := fmt.Errorf("%s: stop failed (%v: %s)", unit, stopErr, stopMsg)
			errs = append(errs, err)
			results = append(results, UnitRetireResult{
				Unit:   unit,
				Status: "failed",
				Detail: stopMsg,
			})
			continue
		}

		results = append(results, UnitRetireResult{
			Unit:   unit,
			Status: "retired",
		})
	}

	if len(errs) == 0 {
		_, _ = execFn(ctx, "systemctl", "daemon-reload")
	}

	return results, errors.Join(errs...)
}

func isSystemdUnitMissingOutput(msg string) bool {
	lower := strings.ToLower(msg)
	return strings.Contains(lower, "not loaded") ||
		strings.Contains(lower, "no such file") ||
		strings.Contains(lower, "does not exist") ||
		strings.Contains(lower, "not-found")
}

// WaitForDrainLock blocks until isIdle returns true or the timeout/context expires.
func WaitForDrainLock(ctx context.Context, isIdle func() bool, timeout, pollInterval time.Duration) error {
	if isIdle == nil || isIdle() {
		return nil
	}
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	if pollInterval <= 0 {
		pollInterval = 500 * time.Millisecond
	}

	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		if isIdle() {
			return nil
		}
		select {
		case <-waitCtx.Done():
			return fmt.Errorf("timed out waiting for active operations to drain: %w", waitCtx.Err())
		case <-ticker.C:
		}
	}
}
