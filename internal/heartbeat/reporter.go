package heartbeat

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/antwig2/flarelens/internal/config"
	"github.com/antwig2/flarelens/internal/docker"
	"github.com/antwig2/flarelens/internal/system"
	"github.com/antwig2/flarelens/internal/transport"
)

// NodeRegistrationPayload represents the initial node enrollment spec
type NodeRegistrationPayload struct {
	NodeID        string           `json:"node_id"`
	Hostname      string           `json:"hostname"`
	Provider      string           `json:"provider"`
	Region        string           `json:"region"`
	Tags          []string         `json:"tags"`
	Specs         system.NodeSpecs `json:"specs"`
	Status        string           `json:"status"`
	Version       string           `json:"version"`
	LastHeartbeat int64            `json:"last_heartbeat"`
}

// NodeTelemetryHeartbeat represents the 15-second heartbeat payload
type NodeTelemetryHeartbeat struct {
	Timestamp     time.Time                 `json:"timestamp"`
	NodeID        string                    `json:"node_id"`
	Status        string                    `json:"status"`
	DockerHealthy bool                      `json:"docker_healthy"`
	Metrics       system.MetricsSnapshot    `json:"metrics"`
	Containers    []docker.ContainerSummary `json:"containers"`
}

// SyncResponse represents the piggybacked control-plane payload returned by POST /api/v1/ingest.
type SyncResponse struct {
	Status       string            `json:"status"`
	Count        int               `json:"count"`
	Commands     []json.RawMessage `json:"commands"`
	FlagsVersion *string           `json:"flags_version"`
}

// SyncHandler processes piggybacked commands and feature-flag version markers returned on each HTTP heartbeat.
// piggybacked is true when the control plane includes flags_version in its ingest response.
type SyncHandler func(ctx context.Context, commands []json.RawMessage, flagsVersion string, piggybacked bool)

// Reporter coordinates periodic heartbeats and initial node enrollment
type Reporter struct {
	cfg        *config.Config
	sampler    *system.Sampler
	inspector  *docker.Inspector
	natsClient *transport.NATSClient
	httpClient *http.Client
	logger     *slog.Logger
	version    string
	syncMu     sync.RWMutex
	onSync     SyncHandler
}

// SetSyncHandler registers a callback invoked with piggybacked commands and flags_version after each HTTP heartbeat.
func (r *Reporter) SetSyncHandler(fn SyncHandler) {
	r.syncMu.Lock()
	defer r.syncMu.Unlock()
	r.onSync = fn
}

// NewReporter creates a new telemetry reporter
func NewReporter(
	cfg *config.Config,
	sampler *system.Sampler,
	inspector *docker.Inspector,
	natsClient *transport.NATSClient,
	version string,
	logger *slog.Logger,
) *Reporter {
	if logger == nil {
		logger = slog.Default()
	}

	return &Reporter{
		cfg:        cfg,
		sampler:    sampler,
		inspector:  inspector,
		natsClient: natsClient,
		httpClient: &http.Client{Timeout: 10 * time.Second},
		logger:     logger,
		version:    version,
	}
}

// Enroll registers this node with the FlareLens Control Plane
func (r *Reporter) Enroll(ctx context.Context) error {
	specs := system.GetSpecs()

	payload := NodeRegistrationPayload{
		NodeID:        r.cfg.Identity.NodeID,
		Hostname:      r.cfg.Identity.Hostname,
		Provider:      r.cfg.Identity.Provider,
		Region:        r.cfg.Identity.Region,
		Tags:          r.cfg.Identity.Tags,
		Specs:         specs,
		Status:        "Healthy",
		Version:       r.version,
		LastHeartbeat: time.Now().Unix(),
	}

	r.logger.Info("Enrolling node with FlareLens Control Plane",
		"node_id", payload.NodeID,
		"cpus", specs.CPUs,
		"ram", system.FormatBytes(specs.RAMTotalBytes),
		"disk", system.FormatBytes(specs.DiskTotalBytes),
	)

	// 1. Try NATS enrollment topic if connected
	if r.natsClient != nil && r.natsClient.IsConnected() {
		subject := fmt.Sprintf("flarelens.node.%s.enroll", r.cfg.Identity.NodeID)
		if err := r.natsClient.PublishJSON(subject, payload); err == nil {
			r.logger.Info("Enrolled successfully via NATS", "subject", subject)
			return nil
		}
	}

	// 2. HTTP Fallback to Control Plane API
	endpoint := fmt.Sprintf("%s/api/v1/control/enroll", r.cfg.ControlPlane.Endpoint)
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if r.cfg.ControlPlane.EnrollToken != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", r.cfg.ControlPlane.EnrollToken))
	}

	resp, err := r.httpClient.Do(req)
	if err != nil {
		r.logger.Warn("Control plane HTTP enrollment request warning (will retry on next heartbeat)",
			"endpoint", endpoint,
			"error", err,
		)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		r.logger.Info("Node enrolled successfully via HTTP API", "status", resp.Status)
	} else {
		r.logger.Warn("Node enrollment API returned non-2xx status", "status", resp.Status)
	}

	return nil
}

// StartHeartbeatLoop runs the periodic 15-second telemetry heartbeat loop
func (r *Reporter) StartHeartbeatLoop(ctx context.Context) {
	interval := r.cfg.ControlPlane.HeartbeatInterval
	if interval <= 0 {
		interval = 15 * time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	r.logger.Info("Starting node telemetry heartbeat loop", "interval", interval)

	// Emit initial telemetry immediately
	r.sendHeartbeat(ctx)

	for {
		select {
		case <-ctx.Done():
			r.logger.Info("Telemetry heartbeat loop stopped")
			return
		case <-ticker.C:
			r.sendHeartbeat(ctx)
		}
	}
}

func (r *Reporter) sendHeartbeat(ctx context.Context) {
	var metrics system.MetricsSnapshot
	if r.sampler != nil {
		metrics = r.sampler.Sample()
	}

	// Check Docker health and inspect running containers
	dockerHealthy := false
	var containers []docker.ContainerSummary

	if r.inspector != nil {
		if err := r.inspector.Ping(ctx); err == nil {
			dockerHealthy = true
			if list, err := r.inspector.ListContainers(ctx, false); err == nil {
				containers = list
			}
		}
	}

	status := "Healthy"
	if !dockerHealthy {
		status = "Degraded"
	}
	if metrics.RAMUsagePct > 90 || metrics.DiskUsagePct > 90 {
		status = "Warning"
	}

	payload := NodeTelemetryHeartbeat{
		Timestamp:     time.Now().UTC(),
		NodeID:        r.cfg.Identity.NodeID,
		Status:        status,
		DockerHealthy: dockerHealthy,
		Metrics:       metrics,
		Containers:    containers,
	}

	// 1. Stream over NATS when connected (local or cluster event fabric)
	publishedViaNATS := false
	if r.natsClient != nil && r.natsClient.IsConnected() {
		subject := fmt.Sprintf("flarelens.node.%s.telemetry", r.cfg.Identity.NodeID)
		if err := r.natsClient.PublishJSON(subject, payload); err == nil {
			publishedViaNATS = true
		} else {
			r.logger.Warn("Failed to publish telemetry over NATS", "error", err)
		}
	}

	// 2. Always sync with HTTPS Control Plane when configured so piggybacked commands and flags_version arrive on the 15s heartbeat
	if r.cfg.ControlPlane.Endpoint != "" {
		r.sendHTTPTelemetry(ctx, payload)
	}

	r.logger.Debug("Heartbeat emitted",
		"node_id", payload.NodeID,
		"status", payload.Status,
		"cpu_pct", fmt.Sprintf("%.1f%%", metrics.CPUUsagePct),
		"ram_pct", fmt.Sprintf("%.1f%%", metrics.RAMUsagePct),
		"containers", len(containers),
		"nats_sent", publishedViaNATS,
	)
}

func (r *Reporter) sendHTTPTelemetry(ctx context.Context, payload NodeTelemetryHeartbeat) {
	url := fmt.Sprintf("%s/api/v1/ingest", strings.TrimRight(r.cfg.ControlPlane.Endpoint, "/"))

	data, err := json.Marshal([]any{payload})
	if err != nil {
		return
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if r.cfg.ControlPlane.EnrollToken != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", r.cfg.ControlPlane.EnrollToken))
	}

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return
	}

	r.syncMu.RLock()
	handler := r.onSync
	r.syncMu.RUnlock()
	if handler == nil {
		return
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil || len(body) == 0 {
		return
	}

	var syncResp SyncResponse
	if err := json.Unmarshal(body, &syncResp); err != nil {
		return
	}

	flagsVersion := ""
	piggybacked := syncResp.FlagsVersion != nil
	if piggybacked {
		flagsVersion = *syncResp.FlagsVersion
	}
	handler(ctx, syncResp.Commands, flagsVersion, piggybacked)
}
