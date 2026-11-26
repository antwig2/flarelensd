package system

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/antwig2/flarelens/internal/mesh"
)

// UninstallOptions configures clean unenrollment and host agent removal.
// Running Docker containers, networks, persistent volumes, and active /dev/shm mounts are NEVER touched.
type UninstallOptions struct {
	NodeID         string
	ControlURL     string
	AuthToken      string
	MeshInterface  string
	MeshPublicKey  string
	MeshKeyPath    string
	SSHPrivKeyPath string
	KeepConfig     bool
	KeepBinary     bool
	RootDir        string // Defaults to "/" on Unix; override in unit tests for hermetic fs isolation
	ExecutablePath string // Optional explicit agent binary path
	GOOS           string
	ExecFn         CommandExecutor
	HTTPClient     *http.Client
	Logger         *slog.Logger
}

// UninstallResult reports all cleanup steps completed during leave or uninstall.
type UninstallResult struct {
	NodeUnenrolled   bool     `json:"node_unenrolled,omitzero"`
	MeshRevoked      bool     `json:"mesh_revoked,omitzero"`
	ServiceRemoved   bool     `json:"service_removed,omitzero"`
	InterfaceRemoved bool     `json:"interface_removed,omitzero"`
	HostsCleaned     bool     `json:"hosts_cleaned,omitzero"`
	SSHConfigRemoved bool     `json:"ssh_config_removed,omitzero"`
	RemovedPaths     []string `json:"removed_paths,omitempty"`
	Warnings         []string `json:"warnings,omitempty"`
}

type funcMeshExecutor struct {
	fn CommandExecutor
}

func (f funcMeshExecutor) Run(ctx context.Context, cmd string, args ...string) ([]byte, error) {
	return f.fn(ctx, cmd, args...)
}

// DeregisterNode notifies the Control Plane (POST /api/v1/control/nodes/:id/leave) so stateless
// replicas are rescheduled onto healthy peers, stateful volumes are fenced, and the node is removed.
func DeregisterNode(
	ctx context.Context,
	controlURL string,
	nodeID string,
	authToken string,
	httpClient *http.Client,
) error {
	endpoint := strings.TrimRight(strings.TrimSpace(controlURL), "/")
	cleanNode := strings.TrimSpace(nodeID)
	if endpoint == "" || cleanNode == "" {
		return errors.New("control_url and node_id are required")
	}

	payload, _ := json.Marshal(map[string]any{
		"node_id": cleanNode,
		"reason":  "Operator executed flarelensd leave/uninstall on host",
	})

	reqCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	leaveURL := fmt.Sprintf("%s/api/v1/control/nodes/%s/leave", endpoint, cleanNode)
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, leaveURL, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if tok := strings.TrimSpace(authToken); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}

	client := cmp.Or(httpClient, &http.Client{Timeout: 8 * time.Second})
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("control plane returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// RunUninstall cleanly unenrolls this host from the Control Plane, stops and removes the
// background OS service, tears down WireGuard & MagicDNS host hooks, and removes agent files
// while keeping all running Docker workloads and volumes intact.
func RunUninstall(ctx context.Context, opts UninstallOptions) (*UninstallResult, error) {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	execFn := opts.ExecFn
	if execFn == nil {
		execFn = DefaultCommandExecutor
	}
	targetOS := cmp.Or(opts.GOOS, runtime.GOOS)
	iface := cmp.Or(strings.TrimSpace(opts.MeshInterface), "flarelens0")

	rootDir := strings.TrimSpace(opts.RootDir)
	resolveRootPath := func(rel string) string {
		if rootDir == "" || rootDir == "/" {
			return filepath.FromSlash(rel)
		}
		return filepath.Join(rootDir, filepath.FromSlash(strings.TrimPrefix(rel, "/")))
	}

	res := &UninstallResult{}

	// 1. Deregister server node from Control Plane (best-effort; never blocks offline uninstall)
	if strings.TrimSpace(opts.ControlURL) != "" && strings.TrimSpace(opts.NodeID) != "" && strings.TrimSpace(opts.AuthToken) != "" {
		if err := DeregisterNode(ctx, opts.ControlURL, opts.NodeID, opts.AuthToken, opts.HTTPClient); err != nil {
			warn := fmt.Sprintf("control plane node unenroll skipped (%v)", err)
			logger.Warn("Node unenroll warning", "node_id", opts.NodeID, "error", err)
			res.Warnings = append(res.Warnings, warn)
		} else {
			res.NodeUnenrolled = true
		}
	}

	// 2. Deregister WireGuard mesh peer if present
	meshPub := strings.TrimSpace(opts.MeshPublicKey)
	if meshPub == "" && opts.MeshKeyPath != "" {
		if _, loadedPub, err := mesh.LoadOrGenerateKeypair(opts.MeshKeyPath); err == nil {
			meshPub = loadedPub
		}
	}
	if strings.TrimSpace(opts.ControlURL) != "" && (meshPub != "" || opts.NodeID != "") {
		if err := mesh.DeregisterMeshPeer(
			ctx,
			opts.ControlURL,
			opts.AuthToken,
			opts.NodeID,
			meshPub,
			opts.SSHPrivKeyPath,
			opts.HTTPClient,
		); err == nil {
			res.MeshRevoked = true
		}
	}

	// 3. Stop & remove OS background service (systemd / launchd / Windows SCM)
	switch targetOS {
	case "linux":
		units := []string{"flarelens-agent.service", "flarelensd.service"}
		reloaded := false
		for _, u := range units {
			unitPath := resolveRootPath("/etc/systemd/system/" + u)
			_, statErr := os.Stat(unitPath)
			_, _ = execFn(ctx, "systemctl", "stop", u)
			_, _ = execFn(ctx, "systemctl", "disable", u)
			if statErr == nil {
				if err := os.Remove(unitPath); err == nil {
					res.RemovedPaths = append(res.RemovedPaths, unitPath)
					res.ServiceRemoved = true
					reloaded = true
				}
			}
		}
		if reloaded {
			_, _ = execFn(ctx, "systemctl", "daemon-reload")
			_, _ = execFn(ctx, "systemctl", "reset-failed")
		}

	case "darwin":
		plistPath := resolveRootPath("/Library/LaunchDaemons/dev.flarelens.agent.plist")
		if _, err := os.Stat(plistPath); err == nil {
			_, _ = execFn(ctx, "launchctl", "bootout", "system", plistPath)
			if rmErr := os.Remove(plistPath); rmErr == nil {
				res.RemovedPaths = append(res.RemovedPaths, plistPath)
				res.ServiceRemoved = true
			}
		}

	case "windows":
		_, _ = execFn(ctx, "sc.exe", "stop", "FlareLensAgent")
		if _, delErr := execFn(ctx, "sc.exe", "delete", "FlareLensAgent"); delErr == nil {
			res.ServiceRemoved = true
		}
	}

	// 4. Clean host DNS (/etc/hosts MagicDNS block + resolvectl) & tear down WireGuard interface
	hostsPath := resolveRootPath("/etc/hosts")
	res.HostsCleaned = mesh.CleanHostDNS(ctx, iface, hostsPath, execFn)

	if removedIface, ifaceErr := mesh.TeardownWireGuardInterface(ctx, iface, targetOS, funcMeshExecutor{fn: execFn}); ifaceErr != nil {
		res.Warnings = append(res.Warnings, ifaceErr.Error())
	} else {
		res.InterfaceRemoved = removedIface
	}

	// 5. Remove dynamic OpenSSH AuthorizedKeysCommand drop-in if installed
	sshdDropIn := resolveRootPath(mesh.OpenSSHConfigPath)
	if err := os.Remove(sshdDropIn); err == nil {
		res.SSHConfigRemoved = true
		res.RemovedPaths = append(res.RemovedPaths, sshdDropIn)
		if targetOS == "linux" {
			_, _ = execFn(ctx, "systemctl", "reload", "sshd")
		}
	}

	// 6. Remove persisted mesh state, WAL buffers, and optionally /etc/flarelens config
	// NOTE: /dev/shm/flarelens-secrets is intentionally preserved so running containers
	// with mounted RAM secret files continue serving traffic uninterrupted until reboot/redeploy.
	stateDirs := []string{
		resolveRootPath("/var/lib/flarelens"),
		resolveRootPath("/var/log/flarelens"),
		resolveRootPath("/opt/flarelens/logs"),
	}
	if !opts.KeepConfig {
		stateDirs = append(stateDirs, resolveRootPath("/etc/flarelens"))
		if targetOS == "windows" {
			if pd := os.Getenv("ProgramData"); pd != "" && (rootDir == "" || rootDir == "/") {
				stateDirs = append(stateDirs, filepath.Join(pd, "FlareLens"))
			}
		}
	}

	for _, dir := range stateDirs {
		if _, err := os.Stat(dir); err == nil {
			if rmErr := os.RemoveAll(dir); rmErr == nil {
				res.RemovedPaths = append(res.RemovedPaths, dir)
			}
		}
	}
	if rootDir == "" || rootDir == "/" {
		res.RemovedPaths = append(res.RemovedPaths, mesh.ClearState()...)
	}

	// 7. Remove agent binaries & symlinks (unless --keep-binary / `flarelensd leave`)
	if !opts.KeepBinary {
		binCandidates := []string{
			resolveRootPath("/usr/local/bin/flarelensd"),
			resolveRootPath("/usr/local/bin/flarelens-agent"),
			resolveRootPath("/opt/flarelens/bin/flarelens-agent"),
			resolveRootPath("/opt/flarelens/bin/flarelens-agent.prev"),
			resolveRootPath("/opt/flarelens/bin/flarelensd"),
		}
		if opts.ExecutablePath != "" {
			binCandidates = append(binCandidates, opts.ExecutablePath)
		}
		for _, binPath := range binCandidates {
			if _, err := os.Lstat(binPath); err == nil {
				if rmErr := os.Remove(binPath); rmErr == nil {
					res.RemovedPaths = append(res.RemovedPaths, binPath)
				}
			}
		}
		// Remove /opt/flarelens directory if empty (or only empty bin/ left)
		optBin := resolveRootPath("/opt/flarelens/bin")
		_ = os.Remove(optBin)
		optRoot := resolveRootPath("/opt/flarelens")
		_ = os.Remove(optRoot)
	}

	return res, nil
}
