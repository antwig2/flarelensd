package system

import (
	"bufio"
	"cmp"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
)

// NodeSpecs represents the static hardware specifications of the host node
type NodeSpecs struct {
	CPUs           int    `json:"cpus"`
	RAMTotalBytes  uint64 `json:"ram_total_bytes"`
	DiskTotalBytes uint64 `json:"disk_total_bytes"`
	OS             string `json:"os"`
	Arch           string `json:"arch"`
	Kernel         string `json:"kernel,omitempty"`
}

// GetSpecs queries host hardware specifications
func GetSpecs() NodeSpecs {
	specs := NodeSpecs{
		CPUs: runtime.NumCPU(),
		OS:   runtime.GOOS,
		Arch: runtime.GOARCH,
	}

	// 1. RAM Total
	specs.RAMTotalBytes = getRAMTotal()

	// 2. Disk Total
	specs.DiskTotalBytes = getDiskTotal("/")

	// 3. Kernel version
	if data, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		specs.Kernel = strings.TrimSpace(string(data))
	}

	return specs
}

func getRAMTotal() uint64 {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				kb, _ := strconv.ParseUint(fields[1], 10, 64)
				return kb * 1024 // Return bytes
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return 0
	}
	return 0
}

func getDiskTotal(path string) uint64 {
	total, _, err := getDiskStats(path)
	if err != nil {
		return 0
	}
	return total
}

// GetHostname returns the local machine hostname
func GetHostname() string {
	name, _ := os.Hostname()
	return cmp.Or(name, "unknown-host")
}

// FormatBytes formats byte count to human-readable string (e.g. 8.00 GB)
func FormatBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}
