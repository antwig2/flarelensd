package deploy

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func buildDockerMuxFrame(stream byte, payload string) []byte {
	var buf bytes.Buffer
	header := make([]byte, 8)
	header[0] = stream
	binary.BigEndian.PutUint32(header[4:], uint32(len(payload)))
	buf.Write(header)
	buf.WriteString(payload)
	return buf.Bytes()
}

func TestRunJobEphemeralContainerSecretsMeshDNSAndTimeout(t *testing.T) {
	sockDir := t.TempDir()
	sockPath := filepath.Join(sockDir, "docker.sock")

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen unix socket: %v", err)
	}
	defer listener.Close()

	var (
		mu              sync.Mutex
		createdCfg      containerCreateConfig
		createdName     string
		removedIDs      []string
		stoppedIDs      []string
		secretSawDuring string
		secretHostDir   string
		simulatedDelay  time.Duration
		simulatedExit   int
	)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /images/create", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"Pull complete"}`))
	})
	mux.HandleFunc("GET /networks/{name}", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"Name":"app-net"}`))
	})
	mux.HandleFunc("GET /containers/{id}/json", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	mux.HandleFunc("POST /containers/create", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var cfg containerCreateConfig
		if err := json.Unmarshal(body, &cfg); err != nil {
			t.Errorf("unmarshal create config: %v", err)
		}
		mu.Lock()
		createdCfg = cfg
		createdName = r.URL.Query().Get("name")
		for _, b := range cfg.HostConfig.Binds {
			if strings.Contains(b, ":/app/certs:ro") {
				hostSrc, _, _ := strings.Cut(b, ":")
				secretHostDir = hostSrc
				if raw, readErr := os.ReadFile(filepath.Join(hostSrc, "jwt_private.pem")); readErr == nil {
					secretSawDuring = string(raw)
				}
			}
		}
		mu.Unlock()
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"Id":"ctr_job_12345"}`))
	})
	mux.HandleFunc("POST /containers/{id}/start", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /containers/{id}/wait", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		delay := simulatedDelay
		exitCode := simulatedExit
		mu.Unlock()

		if delay > 0 {
			select {
			case <-r.Context().Done():
				return
			case <-time.After(delay):
			}
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"StatusCode": exitCode})
	})
	mux.HandleFunc("POST /containers/{id}/stop", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		stoppedIDs = append(stoppedIDs, r.PathValue("id"))
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /containers/{id}/logs", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(buildDockerMuxFrame(1, "Reconciled 42 invoices\n"))
		_, _ = w.Write(buildDockerMuxFrame(2, "0 discrepancies found\n"))
	})
	mux.HandleFunc("DELETE /containers/{id}", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		removedIDs = append(removedIDs, r.PathValue("id"))
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})

	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(listener) }()
	defer srv.Close()

	runner := NewDockerRunner(sockPath)
	orch := NewOrchestrator(runner, NewHealthProber(), nil, nil, "node-eu-1", slog.New(slog.NewTextHandler(io.Discard, nil)))
	orch.SetMeshDNSHook(
		func(env string) ([]string, []string) {
			return []string{"100.64.0.1", "1.1.1.1"}, []string{env + ".mesh", "mesh"}
		},
		func(env string, extraHosts []string) {},
	)

	// 1. Happy path CronJob execution
	res := orch.RunJob(t.Context(), JobRunRequest{
		RunID:          "run_cron_001",
		JobName:        "nightly-reconcile",
		Service:        "billing-api",
		Env:            "uat",
		Image:          "ghcr.io/example/billing-api:1.2.0",
		Command:        []string{"/app/billing", "jobs", "reconcile"},
		Networks:       []string{"app-net"},
		MemoryMB:       512,
		CPUCores:       0.75,
		TimeoutSeconds: 30,
		Trigger:        "cron",
		ExtraHosts:     []string{"postgres:100.64.0.2"},
		Secrets: map[string]string{
			"DATABASE_URL":                         "postgres://app:secret@postgres:5432/app_uat",
			"__FLARELENS_FILE__/app/certs/jwt_private.pem": "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----",
		},
	})

	if res.Status != "succeeded" || res.ExitCode != 0 {
		t.Fatalf("expected succeeded exit 0, got status=%s exit=%d err=%s", res.Status, res.ExitCode, res.Error)
	}
	if !strings.Contains(res.Output, "Reconciled 42 invoices") || !strings.Contains(res.Output, "0 discrepancies found") {
		t.Fatalf("expected demultiplexed stdout+stderr output, got %q", res.Output)
	}

	mu.Lock()
	gotCfg := createdCfg
	gotName := createdName
	gotSecretContent := secretSawDuring
	gotSecretDir := secretHostDir
	gotRemoved := slices.Clone(removedIDs)
	mu.Unlock()

	if !strings.HasPrefix(gotName, "flarelens-job-uat-billing-api-nightly-reconcile-") {
		t.Fatalf("unexpected job container name: %s", gotName)
	}
	if gotCfg.HostConfig.RestartPolicy.Name != "no" {
		t.Fatalf("expected RestartPolicy=no on ephemeral job, got %q", gotCfg.HostConfig.RestartPolicy.Name)
	}
	if gotCfg.HostConfig.Memory != 512*1024*1024 || gotCfg.HostConfig.NanoCPUs != 750_000_000 {
		t.Fatalf("expected cgroups 512MiB / 0.75 CPU, got mem=%d nanocpu=%d", gotCfg.HostConfig.Memory, gotCfg.HostConfig.NanoCPUs)
	}
	if !slices.Contains(gotCfg.HostConfig.SecurityOpt, "no-new-privileges:true") {
		t.Fatalf("expected no-new-privileges:true SecurityOpt, got %v", gotCfg.HostConfig.SecurityOpt)
	}
	if !slices.Contains(gotCfg.HostConfig.DNS, "100.64.0.1") {
		t.Fatalf("expected WireGuard MagicDNS server injected, got %v", gotCfg.HostConfig.DNS)
	}
	if !slices.Contains(gotCfg.Env, "DATABASE_URL=postgres://app:secret@postgres:5432/app_uat") {
		t.Fatalf("expected in-memory DATABASE_URL env var injected")
	}
	if !strings.Contains(gotSecretContent, "BEGIN PRIVATE KEY") {
		t.Fatalf("expected RAM secret file materialized during container create, got %q", gotSecretContent)
	}
	if _, statErr := os.Stat(gotSecretDir); !os.IsNotExist(statErr) {
		t.Fatalf("expected ephemeral RAM secret directory %s to be wiped immediately after job exit", gotSecretDir)
	}
	if !slices.Contains(gotRemoved, "ctr_job_12345") {
		t.Fatalf("expected ephemeral job container ctr_job_12345 removed on exit, got %v", gotRemoved)
	}

	// 2. Non-zero exit code -> failed
	mu.Lock()
	simulatedExit = 2
	mu.Unlock()
	failRes := orch.RunJob(t.Context(), JobRunRequest{
		RunID:   "run_fail_002",
		JobName: "broken-migration",
		Service: "billing-api",
		Env:     "uat",
		Image:   "ghcr.io/example/billing-api:1.2.0",
		Command: []string{"/app/billing", "jobs", "fail"},
	})
	if failRes.Status != "failed" || failRes.ExitCode != 2 {
		t.Fatalf("expected failed exit=2, got status=%s exit=%d", failRes.Status, failRes.ExitCode)
	}

	// 3. Timeout enforcement -> timed_out (exit 124) + StopContainer + RemoveContainer
	mu.Lock()
	simulatedExit = 0
	simulatedDelay = 3 * time.Second
	stoppedIDs = nil
	removedIDs = nil
	mu.Unlock()
	timeoutRes := orch.RunJob(t.Context(), JobRunRequest{
		RunID:          "run_timeout_003",
		JobName:        "hung-job",
		Service:        "billing-api",
		Env:            "uat",
		Image:          "ghcr.io/example/billing-api:1.2.0",
		Command:        []string{"sleep", "60"},
		TimeoutSeconds: 1,
	})
	if timeoutRes.Status != "timed_out" || timeoutRes.ExitCode != 124 {
		t.Fatalf("expected timed_out exit=124, got status=%s exit=%d", timeoutRes.Status, timeoutRes.ExitCode)
	}
	mu.Lock()
	gotStopped := slices.Clone(stoppedIDs)
	gotRemovedTimeout := slices.Clone(removedIDs)
	mu.Unlock()
	if !slices.Contains(gotStopped, "ctr_job_12345") || !slices.Contains(gotRemovedTimeout, "ctr_job_12345") {
		t.Fatalf("expected timed-out container stopped and removed, stopped=%v removed=%v", gotStopped, gotRemovedTimeout)
	}
}
