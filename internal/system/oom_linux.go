//go:build !windows

package system

import (
	"log/slog"
	"os"
)

// ProtectFromOOM configures the Linux kernel OOM killer to treat the FlareLens agent
// as immune by writing -1000 to /proc/self/oom_score_adj (Section 17.1).
func ProtectFromOOM(logger *slog.Logger) {
	err := os.WriteFile("/proc/self/oom_score_adj", []byte("-1000"), 0644)
	if err != nil {
		if logger != nil {
			logger.Debug("Could not adjust /proc/self/oom_score_adj (requires root or CAP_SYS_RESOURCE)", "error", err)
		}
	} else if logger != nil {
		logger.Info("Kernel OOM immunity configured", "oom_score_adj", -1000)
	}
}
