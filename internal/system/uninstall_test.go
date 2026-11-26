package system

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/antwig2/flarelens/internal/mesh"
)

func TestRunUninstallFullAndLeaveKeepBinary(t *testing.T) {
	t.Run("full uninstall removes service, config, mesh, hosts block and binaries while preserving /dev/shm container mounts", func(t *testing.T) {
		root := t.TempDir()
		mkFile := func(rel, content string) string {
			full := filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(rel, "/")))
			if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(full, []byte(content), 0644); err != nil {
				t.Fatal(err)
			}
			return full
		}

		unitFile := mkFile("/etc/systemd/system/flarelens-agent.service", "[Service]\nExecStart=/opt/flarelens/bin/flarelens-agent\n")
		cfgFile := mkFile("/etc/flarelens/agent.yaml", "identity:\n  node_id: node-app-1\n")
		walFile := mkFile("/opt/flarelens/logs/wal/segment-01.log", "logs")
		binFile := mkFile("/opt/flarelens/bin/flarelens-agent", "binary")
		symBin := mkFile("/usr/local/bin/flarelensd", "symlink")
		sshdDropIn := mkFile(mesh.OpenSSHConfigPath, "AuthorizedKeysCommand /usr/local/bin/flarelens-agent ssh-auth %u %k %t\n")
		shmSecret := mkFile("/dev/shm/flarelens-secrets/app-prod/jwt.pem", "LIVE_CONTAINER_MOUNTED_SECRET")
		hostsFile := mkFile("/etc/hosts", "127.0.0.1 localhost\n\n"+mesh.MagicDNSHostsHeader+"\n100.64.0.1 node-app-1.mesh\n"+mesh.MagicDNSHostsFooter+"\n")

		wgKeyPath := filepath.Join(root, "etc", "flarelens", "mesh.key")
		_, wgPub, err := mesh.LoadOrGenerateKeypair(wgKeyPath)
		if err != nil {
			t.Fatal(err)
		}

		var hitPaths []string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hitPaths = append(hitPaths, r.Method+" "+r.URL.Path)
			if r.Header.Get("Authorization") != "Bearer test-ingest-secret" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		}))
		defer srv.Close()

		var cmds []string
		execMock := func(_ context.Context, name string, args ...string) ([]byte, error) {
			cmds = append(cmds, name+" "+strings.Join(args, " "))
			return []byte("ok"), nil
		}

		res, err := RunUninstall(t.Context(), UninstallOptions{
			NodeID:        "node-app-1",
			ControlURL:    srv.URL,
			AuthToken:     "test-ingest-secret",
			MeshInterface: "flarelens0",
			MeshPublicKey: wgPub,
			KeepConfig:    false,
			KeepBinary:    false,
			RootDir:       root,
			GOOS:          "linux",
			ExecFn:        execMock,
			HTTPClient:    srv.Client(),
		})
		if err != nil {
			t.Fatalf("RunUninstall failed: %v", err)
		}

		if !res.NodeUnenrolled || !res.MeshRevoked || !res.ServiceRemoved || !res.InterfaceRemoved || !res.HostsCleaned || !res.SSHConfigRemoved {
			t.Fatalf("expected all uninstall flags true, got: %+v", res)
		}
		if !slices.Contains(hitPaths, "POST /api/v1/control/nodes/node-app-1/leave") {
			t.Errorf("expected node leave call, got %v", hitPaths)
		}
		if !slices.Contains(hitPaths, "POST /api/v1/control/mesh/leave") {
			t.Errorf("expected mesh leave call, got %v", hitPaths)
		}
		if !slices.Contains(cmds, "systemctl stop flarelens-agent.service") ||
			!slices.Contains(cmds, "systemctl daemon-reload") ||
			!slices.Contains(cmds, "ip link delete dev flarelens0") ||
			!slices.Contains(cmds, "systemctl reload sshd") {
			t.Errorf("missing expected host commands, got: %v", cmds)
		}

		for _, removed := range []string{unitFile, cfgFile, walFile, binFile, symBin, sshdDropIn} {
			if _, statErr := os.Stat(removed); !os.IsNotExist(statErr) {
				t.Errorf("expected %s to be removed", removed)
			}
		}

		// CRITICAL: Running containers' /dev/shm secret mounts MUST remain untouched!
		if _, statErr := os.Stat(shmSecret); statErr != nil {
			t.Fatalf("expected live /dev/shm secret mount to remain untouched, got %v", statErr)
		}
		hostsBytes, _ := os.ReadFile(hostsFile)
		if strings.Contains(string(hostsBytes), "node-app-1.mesh") {
			t.Errorf("expected MagicDNS block stripped from /etc/hosts, got: %s", string(hostsBytes))
		}
	})

	t.Run("leave mode keeps binary and succeeds even when control plane is unreachable", func(t *testing.T) {
		root := t.TempDir()
		binPath := filepath.Join(root, "usr", "local", "bin", "flarelensd")
		_ = os.MkdirAll(filepath.Dir(binPath), 0755)
		_ = os.WriteFile(binPath, []byte("bin"), 0755)

		cfgPath := filepath.Join(root, "etc", "flarelens", "agent.yaml")
		_ = os.MkdirAll(filepath.Dir(cfgPath), 0755)
		_ = os.WriteFile(cfgPath, []byte("cfg"), 0600)

		res, err := RunUninstall(t.Context(), UninstallOptions{
			NodeID:     "node-offline-1",
			ControlURL: "http://127.0.0.1:1", // unreachable
			AuthToken:  "secret",
			KeepConfig: true,
			KeepBinary: true,
			RootDir:    root,
			GOOS:       "linux",
			ExecFn: func(_ context.Context, _ string, _ ...string) ([]byte, error) {
				return nil, os.ErrNotExist
			},
		})
		if err != nil {
			t.Fatalf("expected offline leave to succeed locally with warnings, got err=%v", err)
		}
		if len(res.Warnings) == 0 {
			t.Errorf("expected offline control plane warning to be recorded")
		}
		if _, err := os.Stat(binPath); err != nil {
			t.Errorf("expected binary preserved in leave mode: %v", err)
		}
		if _, err := os.Stat(cfgPath); err != nil {
			t.Errorf("expected config preserved when KeepConfig=true: %v", err)
		}
	})
}
