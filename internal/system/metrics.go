package system

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// MetricsSnapshot represents the periodic telemetry state of the host
type MetricsSnapshot struct {
	Timestamp      time.Time `json:"timestamp"`
	CPUUsagePct    float64   `json:"cpu_usage_pct"`
	RAMUsedBytes   uint64    `json:"ram_used_bytes"`
	RAMTotalBytes  uint64    `json:"ram_total_bytes"`
	RAMUsagePct    float64   `json:"ram_usage_pct"`
	DiskUsedBytes  uint64    `json:"disk_used_bytes"`
	DiskTotalBytes uint64    `json:"disk_total_bytes"`
	DiskUsagePct   float64   `json:"disk_usage_pct"`
	LoadAvg1       float64   `json:"load_avg_1"`
	LoadAvg5       float64   `json:"load_avg_5"`
	LoadAvg15      float64   `json:"load_avg_15"`
	UptimeSeconds  uint64    `json:"uptime_seconds"`
	RebootRequired bool      `json:"reboot_required"`
}

// Sampler maintains previous CPU ticks to calculate accurate CPU usage percentages
type Sampler struct {
	mu           sync.Mutex
	prevIdleTick uint64
	prevTotTick  uint64
}

// NewSampler initializes a new real-time metrics sampler
func NewSampler() *Sampler {
	s := &Sampler{}
	idle, total := readCPUTicks()
	s.prevIdleTick = idle
	s.prevTotTick = total
	return s
}

// Sample collects a fresh snapshot of host metrics
func (s *Sampler) Sample() MetricsSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	m := MetricsSnapshot{
		Timestamp: now,
	}

	// 1. CPU Usage Calculation
	idle, total := readCPUTicks()
	if s.prevTotTick > 0 && total > s.prevTotTick {
		idleDelta := float64(idle - s.prevIdleTick)
		totDelta := float64(total - s.prevTotTick)
		m.CPUUsagePct = min(max(((totDelta-idleDelta)/totDelta)*100.0, 0), 100)
	}
	s.prevIdleTick = idle
	s.prevTotTick = total

	// 2. RAM Usage
	m.RAMTotalBytes, m.RAMUsedBytes = readRAMUsage()
	if m.RAMTotalBytes > 0 {
		m.RAMUsagePct = (float64(m.RAMUsedBytes) / float64(m.RAMTotalBytes)) * 100.0
	}

	// 3. Disk Usage
	m.DiskTotalBytes, m.DiskUsedBytes = readDiskUsage("/")
	if m.DiskTotalBytes > 0 {
		m.DiskUsagePct = (float64(m.DiskUsedBytes) / float64(m.DiskTotalBytes)) * 100.0
	}

	// 4. Load Averages
	m.LoadAvg1, m.LoadAvg5, m.LoadAvg15 = readLoadAvg()

	// 5. Uptime & Pending OS Reboot
	m.UptimeSeconds = readUptime()
	m.RebootRequired = IsRebootRequired()

	return m
}

func readCPUTicks() (idle uint64, total uint64) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return 0, 0
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	if scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) > 4 && fields[0] == "cpu" {
			var sum uint64
			for i := 1; i < len(fields); i++ {
				val, _ := strconv.ParseUint(fields[i], 10, 64)
				sum += val
				if i == 4 { // idle is the 4th numeric field (index 4)
					idle = val
				}
			}
			total = sum
		}
	}
	return idle, total
}

func readRAMUsage() (total uint64, used uint64) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0
	}
	defer f.Close()

	var memTotal, memAvailable uint64
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				memTotal, _ = strconv.ParseUint(fields[1], 10, 64)
				memTotal *= 1024
			}
		} else if strings.HasPrefix(line, "MemAvailable:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				memAvailable, _ = strconv.ParseUint(fields[1], 10, 64)
				memAvailable *= 1024
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, 0
	}

	if memTotal > 0 && memAvailable <= memTotal {
		used = memTotal - memAvailable
	}
	return memTotal, used
}

func readDiskUsage(path string) (total uint64, used uint64) {
	total, used, err := getDiskStats(path)
	if err != nil {
		return 0, 0
	}
	return total, used
}

func readLoadAvg() (l1, l5, l15 float64) {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, 0, 0
	}
	fields := strings.Fields(string(data))
	if len(fields) >= 3 {
		l1, _ = strconv.ParseFloat(fields[0], 64)
		l5, _ = strconv.ParseFloat(fields[1], 64)
		l15, _ = strconv.ParseFloat(fields[2], 64)
	}
	return l1, l5, l15
}

func readUptime() uint64 {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(data))
	if len(fields) >= 1 {
		sec, _ := strconv.ParseFloat(fields[0], 64)
		return uint64(sec)
	}
	return 0
}
