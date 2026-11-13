package deploy

import "time"

// WorkerSpec defines a companion background worker container (like Kamal workers)
type WorkerSpec struct {
	Name       string   `json:"name"`                 // e.g. "job-drainer"
	Command    []string `json:"command,omitempty"`    // e.g. ["drainer", "start"]
	Entrypoint []string `json:"entrypoint,omitempty"` // e.g. ["/app", "worker", "start"]
	Volumes    []string `json:"volumes,omitempty"`    // host:container bind mounts
	Networks   []string `json:"networks,omitempty"`   // additional docker networks
}

// DeployRequest defines a declarative deployment trigger
type DeployRequest struct {
	DeploymentID      string            `json:"deployment_id"`
	Service           string            `json:"service"`         // e.g. "api-server"
	Image             string            `json:"image"`           // e.g. "ghcr.io/org/api-server:v1.0"
	Env               string            `json:"env"`             // "prod", "staging", "uat"
	Domain            string            `json:"domain"`          // e.g. "api.example.com"
	ContainerPort     int               `json:"container_port"`  // internal port, e.g. 8081
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
