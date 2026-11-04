package config

import (
	"cmp"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the master configuration schema for flarelensd
// Path: /etc/flarelens/agent.yaml (override with --config or FLARELENS_CONFIG)
type Config struct {
	Identity     IdentityConfig     `yaml:"identity"`
	ControlPlane ControlPlaneConfig `yaml:"control_plane"`
	NATS         NATSConfig         `yaml:"nats"`
	Docker       DockerConfig       `yaml:"docker"`
	Deployments  DeploymentsConfig  `yaml:"deployments"`
	Database     DatabaseConfig     `yaml:"database"`
	Telemetry    TelemetryConfig    `yaml:"telemetry"`
	Mesh         MeshConfig         `yaml:"mesh"`

	// Runtime / CLI metadata
	ConfigFile string `yaml:"-"`
	DevMode    bool   `yaml:"-"`
}

type IdentityConfig struct {
	NodeID   string   `yaml:"node_id"`
	Hostname string   `yaml:"hostname"`
	Provider string   `yaml:"provider"`
	Region   string   `yaml:"region"`
	Tags     []string `yaml:"tags"`
}

type ControlPlaneConfig struct {
	Endpoint          string        `yaml:"endpoint"`
	EnrollToken       string        `yaml:"enroll_token"`
	HeartbeatInterval time.Duration `yaml:"heartbeat_interval"`
}

type NATSConfig struct {
	Mode            string `yaml:"mode"`              // "client" or "embedded"
	URL             string `yaml:"url"`               // nats URL (e.g. nats://localhost:4222)
	EmbeddedPort    int    `yaml:"embedded_port"`     // WebSocket listener port (e.g. 8080)
	EmbeddedTCPPort int    `yaml:"embedded_tcp_port"` // Internal TCP port (e.g. 4222)
	AuthToken       string `yaml:"auth_token"`
}

type DockerConfig struct {
	Socket         string      `yaml:"socket"`
	DefaultNetwork string      `yaml:"default_network"`
	ExtraNetworks  []string    `yaml:"extra_networks"`
	Prune          PruneConfig `yaml:"prune"`
}

type PruneConfig struct {
	AutoPruneEnabled bool   `yaml:"auto_prune_enabled"`
	DiskThresholdPct int    `yaml:"disk_threshold_pct"`
	Schedule         string `yaml:"schedule"`
}

type DeploymentsConfig struct {
	HealthcheckTimeout  time.Duration `yaml:"healthcheck_timeout"`
	HealthcheckInterval time.Duration `yaml:"healthcheck_interval"`
	DrainGracePeriod    time.Duration `yaml:"drain_grace_period"`
	DefaultStrategy     string        `yaml:"default_strategy"`
}

type DatabaseConfig struct {
	Mode        string       `yaml:"mode"` // "host_native", "container", "external", "disabled"
	Host        string       `yaml:"host"`
	Port        int          `yaml:"port"`
	User        string       `yaml:"user"`
	Database    string       `yaml:"database"`
	SSLMode     string       `yaml:"ssl_mode"`
	ServiceName string       `yaml:"service_name"`
	Backup      BackupConfig `yaml:"backup"`
}

type BackupConfig struct {
	Enabled             bool   `yaml:"enabled"`
	Schedule            string `yaml:"schedule"`
	R2Bucket            string `yaml:"r2_bucket"`
	Prefix              string `yaml:"prefix"`
	PreDeploySnapshot   bool   `yaml:"pre_deploy_snapshot"`
	CrossCloudR2Enabled bool   `yaml:"cross_cloud_r2_enabled"`
	R2Endpoint          string `yaml:"r2_endpoint"`
	R2AccessKeyID       string `yaml:"r2_access_key_id"`
	R2SecretAccessKey   string `yaml:"r2_secret_access_key"`
}

type TelemetryConfig struct {
	LogLevel             string          `yaml:"log_level"`
	DockerTailingEnabled bool            `yaml:"docker_tailing_enabled"`
	NoiseFilterPatterns  []string        `yaml:"noise_filter_patterns"`
	WALBuffer            WALBufferConfig `yaml:"wal_buffer"`
}

type WALBufferConfig struct {
	Enabled   bool   `yaml:"enabled"`
	Path      string `yaml:"path"`
	MaxSizeMB int    `yaml:"max_size_mb"`
}
type MeshConfig struct {
	Enabled   bool   `yaml:"enabled"`
	Interface string `yaml:"interface"`
	Port      int    `yaml:"port"`
	KeyPath   string `yaml:"key_path"`
	Endpoint  string `yaml:"endpoint"`
}

// DefaultConfig provides production-ready fallback defaults
func DefaultConfig() *Config {
	hostname, _ := os.Hostname()
	hostname = cmp.Or(hostname, "flarelens-node")

	return &Config{
		Identity: IdentityConfig{
			NodeID:   fmt.Sprintf("node-%s", hostname),
			Hostname: hostname,
			Provider: "digitalocean",
			Region:   "lon1",
			Tags:     []string{"app", "prod"},
		},
		ControlPlane: ControlPlaneConfig{
			Endpoint:          "",
			HeartbeatInterval: 15 * time.Second,
		},
		NATS: NATSConfig{
			Mode:            "client",
			URL:             "nats://127.0.0.1:4222",
			EmbeddedPort:    8080,
			EmbeddedTCPPort: 4222,
		},
		Docker: DockerConfig{
			Socket:         "unix:///var/run/docker.sock",
			DefaultNetwork: "flarelens-edge",
			ExtraNetworks:  []string{"flarelens-prod", "flarelens-uat"},
			Prune: PruneConfig{
				AutoPruneEnabled: true,
				DiskThresholdPct: 85,
				Schedule:         "0 3 * * 0",
			},
		},
		Deployments: DeploymentsConfig{
			HealthcheckTimeout:  30 * time.Second,
			HealthcheckInterval: 2 * time.Second,
			DrainGracePeriod:    30 * time.Second,
			DefaultStrategy:     "blue-green",
		},
		Database: DatabaseConfig{
			Mode:        "host_native",
			Host:        "localhost",
			Port:        5432,
			SSLMode:     "prefer",
			ServiceName: "postgresql",
			Backup: BackupConfig{
				Enabled:             true,
				Schedule:            "0 2 * * *",
				R2Bucket:            "flarelens-backups",
				Prefix:              "postgres/prod",
				PreDeploySnapshot:   true,
				CrossCloudR2Enabled: true,
			},
		},
		Telemetry: TelemetryConfig{
			LogLevel:             "info",
			DockerTailingEnabled: true,
			NoiseFilterPatterns:  []string{"GET /healthz", "GET /metrics"},
			WALBuffer: WALBufferConfig{
				Enabled:   true,
				Path:      "/var/log/flarelens/wal",
				MaxSizeMB: 2048,
			},
		},
		Mesh: MeshConfig{
			Enabled:   true,
			Interface: "flarelens0",
			Port:      51820,
			KeyPath:   "/etc/flarelens/mesh.key",
			Endpoint:  "",
		},
	}
}

// Load compiles configuration respecting the precedence:
// 1. CLI Flags
// 2. Environment Variables
// 3. Local Config File (/etc/flarelens/agent.yaml)
// 4. Defaults
func Load(args []string) (*Config, error) {
	cfg := DefaultConfig()

	fs := flag.NewFlagSet("flarelens-agent", flag.ContinueOnError)

	// CLI Flags
	configPathFlag := fs.String("config", "", "Path to YAML configuration file")
	nodeIDFlag := fs.String("node-id", "", "Unique Node ID")
	controlURLFlag := fs.String("control-url", "", "FlareLens Control Plane URL")
	enrollTokenFlag := fs.String("enroll-token", "", "Bootstrap enrollment authentication token")
	logLevelFlag := fs.String("log-level", "", "Logging level (debug, info, warn, error)")
	natsURLFlag := fs.String("nats-url", "", "NATS server URL")
	devFlag := fs.Bool("dev", false, "Run in local development mode")
	meshFlag := fs.Bool("mesh", true, "Enable WireGuard Mesh overlay")
	meshPortFlag := fs.Int("mesh-port", 0, "WireGuard Mesh listen UDP port")
	meshIfaceFlag := fs.String("mesh-iface", "", "WireGuard Mesh network interface name")
	versionFlag := fs.Bool("version", false, "Print version information and exit")
	vFlag := fs.Bool("v", false, "Print version information and exit")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	if *versionFlag || *vFlag {
		return nil, flag.ErrHelp
	}

	// 1. Determine config file path
	configFile := cmp.Or(*configPathFlag, os.Getenv("FLARELENS_CONFIG"))
	if configFile == "" {
		candidates := []string{
			"/etc/flarelens/agent.yaml",
			"agent.yaml",
			"configs/agent.yaml",
		}
		for _, c := range candidates {
			if _, err := os.Stat(c); err == nil {
				configFile = c
				break
			}
		}
	}

	// 2. Read config file if present
	if configFile != "" {
		data, err := os.ReadFile(configFile)
		if err == nil {
			// Expand environment variables inside YAML (e.g. ${FLARELENS_ENROLL_TOKEN})
			expanded := os.ExpandEnv(string(data))
			if err := yaml.Unmarshal([]byte(expanded), cfg); err != nil {
				return nil, fmt.Errorf("error parsing config file %s: %w", configFile, err)
			}
			cfg.ConfigFile = configFile
		} else if *configPathFlag != "" {
			return nil, fmt.Errorf("specified config file not found: %s", configFile)
		}
	}

	// 3. Override with Environment Variables
	if val := os.Getenv("FLARELENS_NODE_ID"); val != "" {
		cfg.Identity.NodeID = val
	}
	if val := os.Getenv("FLARELENS_CONTROL_URL"); val != "" {
		cfg.ControlPlane.Endpoint = val
	}
	if val := os.Getenv("FLARELENS_ENROLL_TOKEN"); val != "" {
		cfg.ControlPlane.EnrollToken = val
	}
	if val := os.Getenv("FLARELENS_LOG_LEVEL"); val != "" {
		cfg.Telemetry.LogLevel = val
	}
	if val := os.Getenv("FLARELENS_NATS_URL"); val != "" {
		cfg.NATS.URL = val
	}
	if val := os.Getenv("FLARELENS_NATS_TOKEN"); val != "" {
		cfg.NATS.AuthToken = val
	}
	if val := os.Getenv("FLARELENS_PROVIDER"); val != "" {
		cfg.Identity.Provider = val
	}
	if val := os.Getenv("FLARELENS_REGION"); val != "" {
		cfg.Identity.Region = val
	}
	if val := os.Getenv("FLARELENS_TAGS"); val != "" {
		tags := strings.Split(val, ",")
		for i := range tags {
			tags[i] = strings.TrimSpace(tags[i])
		}
		cfg.Identity.Tags = tags
	}

	// Cloudflare R2 / S3 Backup Credentials
	if val := os.Getenv("R2_ENDPOINT"); val != "" {
		cfg.Database.Backup.R2Endpoint = val
	}
	if val := os.Getenv("R2_ACCESS_KEY_ID"); val != "" {
		cfg.Database.Backup.R2AccessKeyID = val
	} else if val := os.Getenv("AWS_ACCESS_KEY_ID"); val != "" {
		cfg.Database.Backup.R2AccessKeyID = val
	}
	if val := os.Getenv("R2_SECRET_ACCESS_KEY"); val != "" {
		cfg.Database.Backup.R2SecretAccessKey = val
	} else if val := os.Getenv("AWS_SECRET_ACCESS_KEY"); val != "" {
		cfg.Database.Backup.R2SecretAccessKey = val
	}
	if val := os.Getenv("R2_BUCKET"); val != "" {
		cfg.Database.Backup.R2Bucket = val
	}

	// WireGuard Mesh Overrides
	if val := os.Getenv("FLARELENS_MESH_ENABLED"); val != "" {
		cfg.Mesh.Enabled = val == "true" || val == "1"
	}
	if val := os.Getenv("FLARELENS_MESH_IFACE"); val != "" {
		cfg.Mesh.Interface = val
	}
	if val := os.Getenv("FLARELENS_MESH_ENDPOINT"); val != "" {
		cfg.Mesh.Endpoint = val
	}

	// 4. Override with CLI Flags (Highest Precedence)
	if *nodeIDFlag != "" {
		cfg.Identity.NodeID = *nodeIDFlag
	}
	if *controlURLFlag != "" {
		cfg.ControlPlane.Endpoint = *controlURLFlag
	}
	if *enrollTokenFlag != "" {
		cfg.ControlPlane.EnrollToken = *enrollTokenFlag
	}
	if *logLevelFlag != "" {
		cfg.Telemetry.LogLevel = *logLevelFlag
	}
	if *natsURLFlag != "" {
		cfg.NATS.URL = *natsURLFlag
	}
	if *meshIfaceFlag != "" {
		cfg.Mesh.Interface = *meshIfaceFlag
	}
	if *meshPortFlag > 0 {
		cfg.Mesh.Port = *meshPortFlag
	}
	if fs.Lookup("mesh") != nil && fs.Lookup("mesh").Value.String() != "" {
		cfg.Mesh.Enabled = *meshFlag
	}
	if *devFlag {
		cfg.DevMode = true
		cfg.Telemetry.LogLevel = "debug"
		if cfg.ControlPlane.Endpoint == "" {
			cfg.ControlPlane.Endpoint = "http://localhost:8787"
		}
	}

	// Ensure WAL directory directory exists when enabled
	if cfg.Telemetry.WALBuffer.Enabled && cfg.Telemetry.WALBuffer.Path != "" {
		_ = os.MkdirAll(filepath.Clean(cfg.Telemetry.WALBuffer.Path), 0750)
	}

	return cfg, nil
}
