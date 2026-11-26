package deploy

import "time"

// WorkerSpec defines a companion background worker container (like Kamal workers)
type WorkerSpec struct {
	Name       string   `json:"name"`                 // e.g. "job-drainer"
	Command    []string `json:"command,omitempty"`    // e.g. ["drainer", "start"]
	Entrypoint []string `json:"entrypoint,omitempty"` // e.g. ["/app", "worker", "start"]
	Volumes    []string `json:"volumes,omitempty"`    // host:container bind mounts
	Networks   []string `json:"networks,omitempty"`   // additional docker networks
	MemoryMB   int      `json:"memory_mb,omitzero"`   // optional worker RAM limit override (MB)
	CPUCores   float64  `json:"cpu_cores,omitzero"`   // optional worker CPU limit override (cores, e.g. 0.5)
}

// JobSpec defines a declarative scheduled CronJob or on-demand One-Off Job inside a service manifest
type JobSpec struct {
	Name              string   `json:"name"`                         // e.g. "nightly-reconciliation"
	Schedule          string   `json:"schedule,omitempty"`           // optional 5-field UTC cron expression
	Command           []string `json:"command,omitempty"`            // e.g. ["/app/server", "jobs", "reconcile"]
	Entrypoint        []string `json:"entrypoint,omitempty"`         // optional entrypoint override
	Volumes           []string `json:"volumes,omitempty"`            // optional volume bind mounts
	Networks          []string `json:"networks,omitempty"`           // optional docker networks override
	TimeoutSeconds    int      `json:"timeout_seconds,omitzero"`     // max execution duration in seconds
	ConcurrencyPolicy string   `json:"concurrency_policy,omitempty"` // "forbid" (default), "allow", or "replace"
	MemoryMB          int      `json:"memory_mb,omitzero"`           // optional job RAM limit override (MB)
	CPUCores          float64  `json:"cpu_cores,omitzero"`           // optional job CPU limit override (cores)
}

// JobRunRequest defines an isolated ephemeral container job execution request dispatched to a host node
type JobRunRequest struct {
	RunID          string            `json:"run_id"`
	JobName        string            `json:"job_name"`
	Service        string            `json:"service"`
	Env            string            `json:"env"`
	Image          string            `json:"image"`
	Command        []string          `json:"command,omitempty"`
	Entrypoint     []string          `json:"entrypoint,omitempty"`
	Volumes        []string          `json:"volumes,omitempty"`
	Networks       []string          `json:"networks,omitempty"`
	Network        string            `json:"network,omitempty"`
	Secrets        map[string]string `json:"secrets,omitempty"`
	ExtraHosts     []string          `json:"extra_hosts,omitempty"`
	TimeoutSeconds int               `json:"timeout_seconds,omitzero"`
	MemoryMB       int               `json:"memory_mb,omitzero"`
	CPUCores       float64           `json:"cpu_cores,omitzero"`
	Trigger        string            `json:"trigger,omitempty"` // "cron", "manual", "api"
	NodeID         string            `json:"node_id,omitempty"`
}

// JobRunResponse reports the terminal state, exit code, and bounded log tail of an executed job
type JobRunResponse struct {
	RunID       string `json:"run_id"`
	JobName     string `json:"job_name"`
	Service     string `json:"service"`
	Env         string `json:"env"`
	NodeID      string `json:"node_id"`
	ContainerID string `json:"container_id,omitempty"`
	Status      string `json:"status"` // "succeeded", "failed", "timed_out"
	ExitCode    int    `json:"exit_code"`
	Output      string `json:"output"`
	Error       string `json:"error,omitempty"`
	DurationMS  int64  `json:"duration_ms"`
}

// DeployRequest defines a declarative deployment trigger
type DeployRequest struct {
	DeploymentID      string            `json:"deployment_id"`
	Service           string            `json:"service"`         // e.g. "api-server"
	Image             string            `json:"image"`           // e.g. "ghcr.io/org/api-server:v1.0"
	Env               string            `json:"env"`              // "prod", "staging", "uat"
	Domain            string            `json:"domain"`           // e.g. "api.example.com"
	Domains           []string          `json:"domains,omitempty"` // optional multi-host routing rules, e.g. ["api.example.com", "auth.example.com"]
	ContainerPort     int               `json:"container_port"`   // internal port, e.g. 8081
	HostPortBlue      int               `json:"host_port_blue"`  // host port for blue slot
	HostPortGreen     int               `json:"host_port_green"` // host port for green slot
	HealthPath        string            `json:"health_path"`     // e.g. "/health"
	Command           []string          `json:"command,omitempty"`
	Entrypoint        []string          `json:"entrypoint,omitempty"`
	Volumes           []string          `json:"volumes,omitempty"`
	Networks          []string          `json:"networks,omitempty"` // e.g. ["flarelens-edge", "prod"]
	Aliases           []string          `json:"aliases,omitempty"`  // stable Docker DNS aliases promoted onto active slot
	Workers           []WorkerSpec      `json:"workers,omitempty"`  // companion background workers
	TimeoutSeconds    int               `json:"timeout_seconds"`
	DrainSeconds      int               `json:"drain_seconds"`
	Secrets           map[string]string `json:"secrets"`             // in-memory env secrets (zero disk write)
	Network           string            `json:"network"`             // primary network fallback
	TargetDB          string            `json:"target_db,omitempty"` // optional target database name for pre-deploy snapshots
	PreDeploySnapshot bool              `json:"pre_deploy_snapshot"`
	NodeID            string            `json:"node_id"`
	RunMigrations     bool              `json:"run_migrations"`
	MigrationCmd      string            `json:"migration_cmd"`
	CanaryWeight      int               `json:"canary_weight"`
	CanaryDuration    int               `json:"canary_duration"`
	IsPreview         bool              `json:"is_preview"`
	PRNumber          int               `json:"pr_number"`
	MeshPort          int               `json:"mesh_port,omitzero"`
	MemoryMB          int               `json:"memory_mb,omitzero"`
	CPUCores          float64           `json:"cpu_cores,omitzero"`
	ExtraHosts        []string          `json:"extra_hosts,omitempty"`
	RemoteUpstreams   []string          `json:"remote_upstreams,omitempty"`
}

// DecommissionRequest drains and removes stateless service replicas evicted from a node during scale-down or Node Drain.
type DecommissionRequest struct {
	DeploymentID        string   `json:"deployment_id,omitempty"`
	Service             string   `json:"service"`
	Env                 string   `json:"env,omitempty"`
	ContainerName       string   `json:"container_name,omitempty"`
	Domains             []string `json:"domains,omitempty"`
	HealthPath          string   `json:"health_path,omitempty"`
	RemoteUpstreams     []string `json:"remote_upstreams,omitempty"`
	DrainSeconds        int      `json:"drain_seconds,omitzero"`
	ForceRemoveStateful bool     `json:"force_remove_stateful,omitzero"`
}

// TeardownRequest defines parameters to tear down an ephemeral PR preview container and route
type TeardownRequest struct {
	Service  string `json:"service"`
	PRNumber int    `json:"pr_number"`
	NodeID   string `json:"node_id"`
}

// DeployProgress reports incremental status during rollout
type DeployProgress struct {
	DeploymentID string    `json:"deployment_id"`
	Service      string    `json:"service"`
	Stage        string    `json:"stage"` // "pulling", "starting", "probing", "flipping", "draining", "completed", "failed"
	Message      string    `json:"message"`
	Percent      int       `json:"percent"`
	Timestamp    time.Time `json:"timestamp"`
}

// DeployResponse represents the final result of a deployment operation
type DeployResponse struct {
	DeploymentID string `json:"deployment_id"`
	Service      string `json:"service"`
	Status       string `json:"status"`      // "success", "failed", "rolled_back"
	ActiveSlot   string `json:"active_slot"` // "blue" or "green"
	ActivePort   int    `json:"active_port"`
	Message      string `json:"message"`
	DurationMS   int64  `json:"duration_ms"`
}

// Slot represents Blue or Green deployment slot
type Slot string

const (
	SlotBlue  Slot = "blue"
	SlotGreen Slot = "green"
)

// Invert returns the alternate slot
func (s Slot) Invert() Slot {
	if s == SlotBlue {
		return SlotGreen
	}
	return SlotBlue
}
