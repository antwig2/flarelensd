package deploy

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSlotInvert(t *testing.T) {
	if SlotBlue.Invert() != SlotGreen {
		t.Errorf("Expected SlotBlue.Invert() to be SlotGreen")
	}
	if SlotGreen.Invert() != SlotBlue {
		t.Errorf("Expected SlotGreen.Invert() to be SlotBlue")
	}
}

func TestTraefikRouteFlipper(t *testing.T) {
	tmpDir := t.TempDir()
	flipper := NewTraefikRouteFlipper(tmpDir)

	err := flipper.FlipRoute("orders-api", "api.example.com", 8082)
	if err != nil {
		t.Fatalf("Failed to flip Traefik route: %v", err)
	}

	routeFile := filepath.Join(tmpDir, "orders-api.yaml")
	content, err := os.ReadFile(routeFile)
	if err != nil {
		t.Fatalf("Failed to read generated route file: %v", err)
	}

	str := string(content)
	if !strings.Contains(str, "orders-api-router:") {
		t.Errorf("Expected router definition, got: %s", str)
	}
	if !strings.Contains(str, "Host(`api.example.com`)") {
		t.Errorf("Expected Host rule, got: %s", str)
	}
	if !strings.Contains(str, "http://127.0.0.1:8082") {
		t.Errorf("Expected target port 8082, got: %s", str)
	}
}

func TestHealthProberSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	prober := NewHealthProber()
	err := prober.Probe(t.Context(), server.URL+"/healthz", 3*time.Second, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("Expected healthcheck probe to pass, got error: %v", err)
	}
}

func TestHealthProberTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	prober := NewHealthProber()
	err := prober.Probe(t.Context(), server.URL+"/healthz", 300*time.Millisecond, 50*time.Millisecond)
	if err == nil {
		t.Fatalf("Expected healthcheck probe to time out and return error, got nil")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Errorf("Expected timeout error message, got: %v", err)
	}
}

func TestPreDeployHookAbortsOnFailureAndPropagatesTargetDB(t *testing.T) {
	runner := NewDockerRunner("unix:///nonexistent.sock")
	prober := NewHealthProber()
	traefik := NewTraefikRouteFlipper(t.TempDir())
	orch := NewOrchestrator(runner, prober, traefik, nil, "test-node", nil)

	hookCalled := false
	gotTargetDB := ""
	orch.SetPreDeployHook(func(ctx context.Context, service, tag string) error {
		hookCalled = true
		gotTargetDB = TargetDBFromContext(ctx)
		if service != "orders-api" {
			t.Errorf("Expected service orders-api, got %s", service)
		}
		return context.DeadlineExceeded
	})

	req := DeployRequest{
		DeploymentID:      "dep-1",
		Service:           "orders-api",
		Image:             "app/api:v2",
		PreDeploySnapshot: true,
		Secrets: map[string]string{
			"ORDERS_DB_NAME": "orders_db",
		},
	}

	resp := orch.Deploy(t.Context(), req)
	if !hookCalled {
		t.Fatalf("Expected pre-deploy hook to be invoked")
	}
	if gotTargetDB != "orders_db" {
		t.Errorf("Expected TargetDBFromContext to resolve orders_db from ORDERS_DB_NAME, got %q", gotTargetDB)
	}
	if resp.Status != "failed" {
		t.Fatalf("Expected deploy to fail when pre-deploy hook fails, got status: %s", resp.Status)
	}
	if !strings.Contains(resp.Message, "Pre-deploy snapshot guardrail failed") {
		t.Errorf("Expected guardrail error message, got: %s", resp.Message)
	}
}

func TestParseEnvLines(t *testing.T) {
	raw := `
# Production Database
DATABASE_URL=postgres://user:pass@127.0.0.1:5432/db
REDIS_URL="redis://localhost:6379"
API_KEY='secret-key-123'
EMPTY_LINE=
`
	parsed := parseEnvLines(raw)
	if parsed["DATABASE_URL"] != "postgres://user:pass@127.0.0.1:5432/db" {
		t.Errorf("Mismatch DATABASE_URL: %s", parsed["DATABASE_URL"])
	}
	if parsed["REDIS_URL"] != "redis://localhost:6379" {
		t.Errorf("Mismatch REDIS_URL: %s", parsed["REDIS_URL"])
	}
	if parsed["API_KEY"] != "secret-key-123" {
		t.Errorf("Mismatch API_KEY: %s", parsed["API_KEY"])
	}
}

func TestMigrationFailureTriggersRollback(t *testing.T) {
	runner := NewDockerRunner("mock://socket")
	prober := NewHealthProber()
	traefik := NewTraefikRouteFlipper(t.TempDir())
	orch := NewOrchestrator(runner, prober, traefik, nil, "test-node", nil)

	snapshotCalled := false
	orch.SetPreDeployHook(func(ctx context.Context, service, tag string) error {
		snapshotCalled = true
		if service != "orders-api" {
			t.Errorf("Expected service orders-api, got %s", service)
		}
		return nil
	})

	rollbackCalled := false
	orch.SetRollbackHook(func(ctx context.Context, service, tag string) error {
		rollbackCalled = true
		if service != "orders-api" {
			t.Errorf("Expected service orders-api, got %s", service)
		}
		return nil
	})

	req := DeployRequest{
		DeploymentID:      "dep-mig-fail",
		Service:           "orders-api",
		Image:             "nonexistent-image:invalid",
		PreDeploySnapshot: true,
		RunMigrations:     true,
		MigrationCmd:      "exit 1",
	}

	resp := orch.Deploy(t.Context(), req)
	if !snapshotCalled {
		t.Errorf("Expected pre-deploy snapshot to be taken before migration")
	}
	if !rollbackCalled {
		t.Errorf("Expected snapshot rollback hook to be invoked when migration fails")
	}
	if resp.Status != "failed" {
		t.Errorf("Expected deploy status to be 'failed', got: %s", resp.Status)
	}
	if !strings.Contains(resp.Message, "Database migration failed") {
		t.Errorf("Expected migration failure message, got: %s", resp.Message)
	}
}

func TestTraefikCanaryRoute(t *testing.T) {
	tmpDir := t.TempDir()
	flipper := NewTraefikRouteFlipper(tmpDir)

	err := flipper.SetCanaryRoute("orders-api", "api.example.com", 8081, 8082, 10)
	if err != nil {
		t.Fatalf("Failed to set Traefik canary route: %v", err)
	}

	routeFile := filepath.Join(tmpDir, "orders-api.yaml")
	content, err := os.ReadFile(routeFile)
	if err != nil {
		t.Fatalf("Failed to read generated canary route file: %v", err)
	}

	str := string(content)
	if !strings.Contains(str, "weighted:") {
		t.Errorf("Expected weighted round-robin service, got: %s", str)
	}
	if !strings.Contains(str, "weight: 90") {
		t.Errorf("Expected active weight 90, got: %s", str)
	}
	if !strings.Contains(str, "weight: 10") {
		t.Errorf("Expected candidate weight 10, got: %s", str)
	}
	if !strings.Contains(str, "http://127.0.0.1:8081") {
		t.Errorf("Expected active port 8081, got: %s", str)
	}
	if !strings.Contains(str, "http://127.0.0.1:8082") {
		t.Errorf("Expected candidate port 8082, got: %s", str)
	}
}

func TestTraefikRemoveRoute(t *testing.T) {
	tmpDir := t.TempDir()
	flipper := NewTraefikRouteFlipper(tmpDir)

	_ = flipper.FlipRoute("orders-api-pr-42", "pr-42.example.com", 9042)
	routeFile := filepath.Join(tmpDir, "orders-api-pr-42.yaml")
	if _, err := os.Stat(routeFile); os.IsNotExist(err) {
		t.Fatalf("Expected route file to exist before removal")
	}

	if err := flipper.RemoveRoute("orders-api-pr-42"); err != nil {
		t.Fatalf("Failed to remove route: %v", err)
	}
	if _, err := os.Stat(routeFile); !os.IsNotExist(err) {
		t.Errorf("Expected route file to be removed")
	}

	// Removing non-existent route should not error
	if err := flipper.RemoveRoute("orders-api-pr-42"); err != nil {
		t.Errorf("Expected idempotent remove to succeed, got: %v", err)
	}
}

func TestTeardownPreview(t *testing.T) {
	tmpDir := t.TempDir()
	flipper := NewTraefikRouteFlipper(tmpDir)
	runner := NewDockerRunner("mock://")
	prober := NewHealthProber()
	orch := NewOrchestrator(runner, prober, flipper, nil, "node-1", nil)

	_ = flipper.FlipRoute("orders-api-pr-42", "pr-42-api.example.com", 9042)

	err := orch.TeardownPreview(t.Context(), TeardownRequest{
		Service:  "orders-api",
		PRNumber: 42,
	})
	if err != nil {
		t.Fatalf("TeardownPreview failed: %v", err)
	}

	routeFile := filepath.Join(tmpDir, "orders-api-pr-42.yaml")
	if _, err := os.Stat(routeFile); !os.IsNotExist(err) {
		t.Errorf("Expected preview route file to be removed after teardown")
	}
}

func TestSkipMigrationsWhenRunMigrationsIsFalse(t *testing.T) {
	runner := NewDockerRunner("mock://socket")
	prober := NewHealthProber()
	traefik := NewTraefikRouteFlipper(t.TempDir())
	orch := NewOrchestrator(runner, prober, traefik, nil, "test-node", nil)

	snapshotCalled := false
	orch.SetPreDeployHook(func(ctx context.Context, service, tag string) error {
		snapshotCalled = true
		return nil
	})

	req := DeployRequest{
		DeploymentID:      "dep-skip-mig",
		Service:           "orders-api",
		Image:             "nonexistent-image:invalid",
		PreDeploySnapshot: false,
		RunMigrations:     false,
	}

	resp := orch.Deploy(t.Context(), req)
	if snapshotCalled {
		t.Errorf("Expected pre-deploy snapshot NOT to be called when RunMigrations is false and PreDeploySnapshot is false")
	}
	if resp.Status != "failed" {
		t.Errorf("Expected deploy to fail on mock socket, got status: %s", resp.Status)
	}
}

func TestResolveServiceNetworkAliases(t *testing.T) {
	svcUAT := ResolveServiceNetworkAliases("workflow-engine", "uat", []string{"legacy-workflow-api"})
	for _, want := range []string{"workflow-engine", "workflow-engine-uat", "legacy-workflow-api"} {
		if !slices.Contains(svcUAT, want) {
			t.Errorf("Expected UAT aliases %v to contain %q", svcUAT, want)
		}
	}

	ordersProd := ResolveServiceNetworkAliases("orders-api", "production", []string{"orders-v1"})
	for _, want := range []string{"orders-api", "orders-api-prod", "orders-v1"} {
		if !slices.Contains(ordersProd, want) {
			t.Errorf("Expected production aliases %v to contain %q", ordersProd, want)
		}
	}

	dragonflyUAT := ResolveServiceNetworkAliases("dragonfly", "uat", nil)
	for _, want := range []string{"dragonfly", "dragonfly-uat", "redis", "redis-uat"} {
		if !slices.Contains(dragonflyUAT, want) {
			t.Errorf("Expected dragonfly UAT aliases %v to contain %q", dragonflyUAT, want)
		}
	}
}

func TestResolveMigrationNetwork(t *testing.T) {
	cases := []struct {
		name     string
		envName  string
		networks []string
		want     string
	}{
		{
			name:     "uat manifest order with edge second",
			envName:  "uat",
			networks: []string{"app-uat", "app-edge"},
			want:     "app-uat",
		},
		{
			name:     "webhook order with edge first",
			envName:  "uat",
			networks: []string{"app-edge", "app-uat"},
			want:     "app-uat",
		},
		{
			name:     "production normalizes to stack-prod",
			envName:  "production",
			networks: []string{"app-edge", "app-prod"},
			want:     "app-prod",
		},
		{
			name:     "custom non-edge network preferred over edge",
			envName:  "staging",
			networks: []string{"flarelens-edge", "internal-data"},
			want:     "internal-data",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ResolveMigrationNetwork(tc.envName, tc.networks)
			if got != tc.want {
				t.Errorf("ResolveMigrationNetwork(%q, %v) = %q, want %q", tc.envName, tc.networks, got, tc.want)
			}
		})
	}
}

func TestTraefikSwitchRoute(t *testing.T) {
	tmpDir := t.TempDir()
	flipper := NewTraefikRouteFlipper(tmpDir)

	if err := flipper.SwitchRoute("uat", "workflow-engine", "workflow-engine-green", 8086, ""); err == nil {
		t.Fatalf("Expected SwitchRoute with empty domain and no existing file to fail")
	}

	if err := flipper.SwitchRoute("uat", "workflow-engine", "workflow-engine-green", 8086, "workflow-uat.example.com"); err != nil {
		t.Fatalf("SwitchRoute failed: %v", err)
	}
	routePath := filepath.Join(tmpDir, "uat-workflow-engine.yaml")
	raw, err := os.ReadFile(routePath)
	if err != nil {
		t.Fatalf("Failed to read generated route file: %v", err)
	}
	content := string(raw)
	if !strings.Contains(content, "http://workflow-engine-green:8086") {
		t.Errorf("Expected upstream URL http://workflow-engine-green:8086, got:\n%s", content)
	}
	if !strings.Contains(content, "Host(`workflow-uat.example.com`)") {
		t.Errorf("Expected Host rule for workflow-uat.example.com, got:\n%s", content)
	}

	if err := flipper.SwitchRoute("uat", "workflow-engine", "workflow-engine-blue", 8086, ""); err != nil {
		t.Fatalf("SwitchRoute update failed: %v", err)
	}
	updatedRaw, err := os.ReadFile(routePath)
	if err != nil {
		t.Fatalf("Failed to read updated route file: %v", err)
	}
	if !strings.Contains(string(updatedRaw), "http://workflow-engine-blue:8086") {
		t.Errorf("Expected updated upstream URL http://workflow-engine-blue:8086, got:\n%s", string(updatedRaw))
	}
}

func TestDeployPromotesAliasesAfterHealthcheckAndReconcilesStartup(t *testing.T) {
	healthSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer healthSrv.Close()

	var (
		mu                  sync.Mutex
		createdCfg          containerCreateConfig
		aliasesDuringHealth []string
		containerNetworks   = map[string]map[string][]string{
			"id-dragonfly": {
				"app-uat": nil,
			},
			"id-workflow-blue": {
				"app-edge": nil,
				"app-uat":  nil,
			},
		}
		connectCalls int
	)

	healthProbed := false
	healthGate := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		aliasesDuringHealth = slices.Clone(containerNetworks["id-candidate"]["app-uat"])
		healthProbed = true
		mu.Unlock()
		resp, err := http.Get(healthSrv.URL + r.URL.Path)
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		w.WriteHeader(resp.StatusCode)
	}))
	defer healthGate.Close()

	gateURL, _ := url.Parse(healthGate.URL)
	_, gatePortStr, _ := net.SplitHostPort(gateURL.Host)
	gatePort, _ := strconv.Atoi(gatePortStr)

	sockDir, err := os.MkdirTemp("/tmp", "fl-sock-*")
	if err != nil {
		t.Fatalf("mkdir temp socket dir: %v", err)
	}
	defer os.RemoveAll(sockDir)
	sockPath := filepath.Join(sockDir, "d.sock")

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen unix socket: %v", err)
	}
	defer ln.Close()

	dockerMux := http.NewServeMux()
	dockerMux.HandleFunc("/images/create", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"pulled"}`))
	})
	dockerMux.HandleFunc("/networks/", func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/networks/")
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"Name":"` + path + `"}`))
			return
		}
		if strings.HasSuffix(path, "/disconnect") {
			netName := strings.TrimSuffix(path, "/disconnect")
			var body struct {
				Container string `json:"Container"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			mu.Lock()
			if containerNetworks[body.Container] != nil {
				delete(containerNetworks[body.Container], netName)
			}
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
			return
		}
		if strings.HasSuffix(path, "/connect") {
			netName := strings.TrimSuffix(path, "/connect")
			if netName == "host" || netName == "none" {
				http.Error(w, "cannot attach container to special network "+netName, http.StatusBadRequest)
				return
			}
			var body struct {
				Container      string                `json:"Container"`
				EndpointConfig networkEndpointConfig `json:"EndpointConfig"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			mu.Lock()
			connectCalls++
			if containerNetworks[body.Container] == nil {
				containerNetworks[body.Container] = make(map[string][]string)
			}
			containerNetworks[body.Container][netName] = slices.Clone(body.EndpointConfig.Aliases)
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	dockerMux.HandleFunc("/containers/create", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		_ = json.NewDecoder(r.Body).Decode(&createdCfg)
		primaryNet := createdCfg.HostConfig.NetworkMode
		var initAliases []string
		if createdCfg.NetworkingConfig != nil {
			initAliases = slices.Clone(createdCfg.NetworkingConfig.EndpointsConfig[primaryNet].Aliases)
		}
		containerNetworks["id-candidate"] = map[string][]string{
			primaryNet: initAliases,
		}
		mu.Unlock()
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"Id":"id-candidate"}`))
	})
	dockerMux.HandleFunc("/containers/json", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		respPayload := []map[string]any{
			{
				"Id":     "id-dragonfly",
				"Names":  []string{"/app-uat-dragonfly"},
				"Labels": map[string]string{},
				"NetworkSettings": map[string]any{
					"Networks": map[string]any{
						"app-uat": map[string]any{"Aliases": containerNetworks["id-dragonfly"]["app-uat"]},
					},
				},
			},
			{
				"Id":     "id-candidate",
				"Names":  []string{"/workflow-engine-green"},
				"Labels": createdCfg.Labels,
				"NetworkSettings": map[string]any{
					"Networks": map[string]any{
						"app-edge": map[string]any{"Aliases": containerNetworks["id-candidate"]["app-edge"]},
						"app-uat":  map[string]any{"Aliases": containerNetworks["id-candidate"]["app-uat"]},
					},
				},
			},
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(respPayload)
	})
	dockerMux.HandleFunc("/containers/", func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/containers/")
		if strings.HasSuffix(path, "/start") || strings.HasSuffix(path, "/stop") {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if strings.HasSuffix(path, "/json") {
			nameOrID := strings.TrimSuffix(path, "/json")
			mu.Lock()
			defer mu.Unlock()
			if nameOrID == "id-candidate" || nameOrID == "id-dragonfly" {
				nets := make(map[string]any)
				for netName, aliases := range containerNetworks[nameOrID] {
					nets[netName] = map[string]any{
						"IPAddress": "",
						"Aliases":   aliases,
					}
				}
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"Id": nameOrID,
					"NetworkSettings": map[string]any{
						"IPAddress": "",
						"Networks":  nets,
					},
				})
				return
			}
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	dockerSrv := &http.Server{Handler: dockerMux}
	go func() { _ = dockerSrv.Serve(ln) }()
	defer dockerSrv.Close()

	runner := NewDockerRunner("unix://" + sockPath)
	prober := NewHealthProber()
	traefik := NewTraefikRouteFlipper(t.TempDir())
	orch := NewOrchestrator(runner, prober, traefik, nil, "node-uat", nil)

	resp := orch.Deploy(t.Context(), DeployRequest{
		DeploymentID:  "dep-alias-1",
		Service:       "workflow-engine",
		Image:         "invalid.local/org/workflow-engine:uat",
		Env:           "uat",
		Domain:        "workflow-uat.example.com",
		ContainerPort: 8086,
		HostPortBlue:  gatePort,
		HostPortGreen: gatePort,
		HealthPath:    "/health",
		Networks:      []string{"app-edge", "app-uat"},
		Aliases:       []string{"workflow-api"},
		DrainSeconds:  1,
		Secrets: map[string]string{
			"SERVICE_KEY": "test-key",
		},
	})
	if resp.Status != "success" {
		t.Fatalf("Expected deploy status success, got %s (%s)", resp.Status, resp.Message)
	}

	mu.Lock()
	probed := healthProbed
	duringHealth := slices.Clone(aliasesDuringHealth)
	afterAliases := slices.Clone(containerNetworks["id-candidate"]["app-uat"])
	extraHosts := slices.Clone(createdCfg.HostConfig.ExtraHosts)
	envVars := slices.Clone(createdCfg.Env)
	callsBeforeIdempotent := connectCalls
	mu.Unlock()

	if !probed {
		t.Fatalf("Expected candidate health probe to hit gate server")
	}
	if len(duringHealth) != 0 {
		t.Errorf("Expected candidate NOT to hold shared aliases during healthcheck, got %v", duringHealth)
	}
	for _, wantAlias := range []string{"workflow-engine", "workflow-engine-uat", "workflow-api"} {
		if !slices.Contains(afterAliases, wantAlias) {
			t.Errorf("Expected promoted aliases %v on app-uat to include %q", afterAliases, wantAlias)
		}
	}
	if !slices.Contains(extraHosts, "host.docker.internal:host-gateway") {
		t.Errorf("Expected ExtraHosts %v to contain host.docker.internal:host-gateway", extraHosts)
	}
	for _, wantEnv := range []string{
		"SERVER_HOST=0.0.0.0",
		"SERVER_PORT=8086",
		"FEATURE_FLAGS_URL=http://host.docker.internal:8999/api/v1/flags",
	} {
		if !slices.Contains(envVars, wantEnv) {
			t.Errorf("Expected container Env %v to contain %q", envVars, wantEnv)
		}
	}

	if err := runner.PromoteNetworkAliases(t.Context(), "id-candidate", []string{"app-edge", "app-uat"}, afterAliases); err != nil {
		t.Fatalf("Idempotent PromoteNetworkAliases failed: %v", err)
	}
	mu.Lock()
	callsAfterIdempotent := connectCalls
	mu.Unlock()
	if callsAfterIdempotent != callsBeforeIdempotent {
		t.Errorf("Expected zero additional network connect calls on idempotent promote, got %d -> %d", callsBeforeIdempotent, callsAfterIdempotent)
	}

	// Clear aliases to prove ReconcileActiveAliases restores manifest aliases from flarelens.aliases label + redis/dragonfly aliases
	mu.Lock()
	containerNetworks["id-candidate"]["app-uat"] = nil
	mu.Unlock()

	orch.ReconcileActiveAliases(t.Context())
	mu.Lock()
	dragonflyAliases := slices.Clone(containerNetworks["id-dragonfly"]["app-uat"])
	restoredSvcAliases := slices.Clone(containerNetworks["id-candidate"]["app-uat"])
	mu.Unlock()
	for _, wantAlias := range []string{"dragonfly", "redis", "app-uat-dragonfly"} {
		if !slices.Contains(dragonflyAliases, wantAlias) {
			t.Errorf("Expected reconciled dragonfly aliases %v to include %q", dragonflyAliases, wantAlias)
		}
	}
	for _, wantAlias := range []string{"workflow-engine", "workflow-engine-uat", "workflow-api"} {
		if !slices.Contains(restoredSvcAliases, wantAlias) {
			t.Errorf("Expected ReconcileActiveAliases to restore manifest alias %q, got %v", wantAlias, restoredSvcAliases)
		}
	}
}

func TestReconcileSingletonCreatesHealsAndProtectsStateful(t *testing.T) {
	sockDir, err := os.MkdirTemp("/tmp", "fl-sing-*")
	if err != nil {
		t.Fatalf("mkdir temp socket dir: %v", err)
	}
	defer os.RemoveAll(sockDir)
	sockPath := filepath.Join(sockDir, "d.sock")

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen unix socket: %v", err)
	}
	defer ln.Close()

	type mockCtr struct {
		id       string
		running  bool
		image    string
		labels   map[string]string
		networks map[string][]string
		cfg      containerCreateConfig
	}

	var (
		mu         sync.Mutex
		containers = map[string]*mockCtr{
			"uat-postgres": {
				id:      "id-pg",
				running: true,
				image:   "postgres:16-alpine",
				labels:  map[string]string{},
				networks: map[string][]string{
					"app-uat": nil,
				},
			},
		}
		stoppedIDs []string
	)

	findByNameOrID := func(key string) (*mockCtr, string) {
		if c, ok := containers[key]; ok {
			return c, key
		}
		for name, c := range containers {
			if c.id == key {
				return c, name
			}
		}
		return nil, ""
	}

	dockerMux := http.NewServeMux()
	dockerMux.HandleFunc("/images/create", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"pulled"}`))
	})
	dockerMux.HandleFunc("/networks/", func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/networks/")
		if strings.HasSuffix(path, "/disconnect") {
			netName := strings.TrimSuffix(path, "/disconnect")
			var body struct {
				Container string `json:"Container"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			mu.Lock()
			if c, _ := findByNameOrID(body.Container); c != nil {
				delete(c.networks, netName)
			}
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
			return
		}
		if strings.HasSuffix(path, "/connect") {
			netName := strings.TrimSuffix(path, "/connect")
			if netName == "host" || netName == "none" {
				http.Error(w, "cannot attach container to special network "+netName, http.StatusBadRequest)
				return
			}
			var body struct {
				Container      string                `json:"Container"`
				EndpointConfig networkEndpointConfig `json:"EndpointConfig"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			mu.Lock()
			if c, _ := findByNameOrID(body.Container); c != nil {
				c.networks[netName] = slices.Clone(body.EndpointConfig.Aliases)
			}
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	dockerMux.HandleFunc("/containers/create", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		var cfg containerCreateConfig
		_ = json.NewDecoder(r.Body).Decode(&cfg)
		primaryNet := cfg.HostConfig.NetworkMode
		if (primaryNet == "host" || primaryNet == "none" || primaryNet == "bridge") && cfg.NetworkingConfig != nil {
			http.Error(w, "network-scoped alias is supported only for containers in user defined networks", http.StatusBadRequest)
			return
		}
		var initAliases []string
		if cfg.NetworkingConfig != nil {
			initAliases = slices.Clone(cfg.NetworkingConfig.EndpointsConfig[primaryNet].Aliases)
		}
		id := "id-" + name
		mu.Lock()
		containers[name] = &mockCtr{
			id:      id,
			running: false,
			image:   cfg.Image,
			labels:  cfg.Labels,
			networks: map[string][]string{
				primaryNet: initAliases,
			},
			cfg: cfg,
		}
		mu.Unlock()
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"Id":"` + id + `"}`))
	})
	dockerMux.HandleFunc("/containers/", func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/containers/")
		if strings.HasSuffix(path, "/start") {
			key := strings.TrimSuffix(path, "/start")
			mu.Lock()
			if c, _ := findByNameOrID(key); c != nil {
				c.running = true
			}
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if strings.HasSuffix(path, "/stop") {
			key := strings.TrimSuffix(path, "/stop")
			mu.Lock()
			if c, _ := findByNameOrID(key); c != nil {
				c.running = false
				stoppedIDs = append(stoppedIDs, c.id)
			}
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method == http.MethodDelete {
			mu.Lock()
			if _, name := findByNameOrID(path); name != "" {
				delete(containers, name)
			}
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if strings.HasSuffix(path, "/json") {
			key := strings.TrimSuffix(path, "/json")
			mu.Lock()
			defer mu.Unlock()
			c, _ := findByNameOrID(key)
			if c == nil {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			nets := make(map[string]any)
			for netName, aliases := range c.networks {
				nets[netName] = map[string]any{"Aliases": aliases}
			}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"Id": c.id,
				"State": map[string]any{
					"Running": c.running,
				},
				"Config": map[string]any{
					"Image":  c.image,
					"Labels": c.labels,
				},
				"NetworkSettings": map[string]any{
					"Networks": nets,
				},
			})
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	dockerSrv := &http.Server{Handler: dockerMux}
	go func() { _ = dockerSrv.Serve(ln) }()
	defer dockerSrv.Close()

	runner := NewDockerRunner("unix://" + sockPath)
	orch := NewOrchestrator(runner, NewHealthProber(), NewTraefikRouteFlipper(t.TempDir()), nil, "node-uat", nil)

	// 1. Stateful postgres container heals aliases live and is NOT stopped even if desired image differs
	pgResp := orch.ReconcileSingleton(t.Context(), SingletonSpec{
		DeploymentID:  "sing-pg-1",
		Service:       "postgres",
		Env:           "uat",
		Image:         "postgres:17-alpine",
		ContainerName: "uat-postgres",
		Networks:      []string{"app-uat"},
		Aliases:       []string{"db-primary"},
		Ports:         []string{"10.77.77.1:5432:5432"},
	})
	if pgResp.Status != "success" {
		t.Fatalf("Expected postgres singleton reconcile success, got %s: %s", pgResp.Status, pgResp.Message)
	}
	mu.Lock()
	pgAliases := slices.Clone(containers["uat-postgres"].networks["app-uat"])
	pgStops := slices.Clone(stoppedIDs)
	mu.Unlock()
	if len(pgStops) != 0 {
		t.Errorf("Expected stateful postgres NOT to be stopped without force_recreate_stateful, got stops=%v", pgStops)
	}
	for _, want := range []string{"postgres", "postgres-uat", "db-primary", "uat-postgres"} {
		if !slices.Contains(pgAliases, want) {
			t.Errorf("Expected healed postgres aliases %v to include %q", pgAliases, want)
		}
	}

	// 2. Stateless singleton (cdc-streamer) is created with host-IP port binding + healthcheck, then updated when image changes
	cdcV1 := SingletonSpec{
		DeploymentID:  "sing-cdc-1",
		Service:       "cdc-streamer",
		Env:           "uat",
		Image:         "invalid.local/org/benthos:v1",
		ContainerName: "uat-cdc-streamer",
		Restart:       "unless-stopped",
		Networks:      []string{"app-uat"},
		Ports:         []string{"10.77.77.1:4195:4195"},
		Healthcheck: &HealthcheckSpec{
			Test:     []string{"CMD", "wget", "-qO-", "http://127.0.0.1:4195/ping"},
			Interval: "10s",
			Timeout:  "3s",
			Retries:  3,
		},
	}
	r1 := orch.ReconcileSingleton(t.Context(), cdcV1)
	if r1.Status != "success" {
		t.Fatalf("Expected cdc v1 creation success, got %s: %s", r1.Status, r1.Message)
	}
	mu.Lock()
	createdCDC := containers["uat-cdc-streamer"]
	bindings := createdCDC.cfg.HostConfig.PortBindings["4195/tcp"]
	restartPol := createdCDC.cfg.HostConfig.RestartPolicy.Name
	hc := createdCDC.cfg.Healthcheck
	mu.Unlock()
	if len(bindings) != 1 || bindings[0].HostIP != "10.77.77.1" || bindings[0].HostPort != "4195" {
		t.Errorf("Expected host-IP port binding 10.77.77.1:4195, got %+v", bindings)
	}
	if restartPol != "unless-stopped" {
		t.Errorf("Expected restart policy unless-stopped, got %q", restartPol)
	}
	if hc == nil || hc.Retries != 3 || hc.IntervalNs != int64(10*time.Second) {
		t.Errorf("Expected translated container healthcheck, got %+v", hc)
	}

	// Re-reconciling identical spec is an idempotent no-op (zero stops)
	rNoop := orch.ReconcileSingleton(t.Context(), cdcV1)
	if rNoop.Status != "success" {
		t.Fatalf("Expected idempotent cdc reconcile success, got %s", rNoop.Status)
	}
	mu.Lock()
	stopsAfterNoop := len(stoppedIDs)
	mu.Unlock()
	if stopsAfterNoop != 0 {
		t.Errorf("Expected zero stops on identical singleton spec, got %d", stopsAfterNoop)
	}

	// Updating stateless singleton image triggers stop + recreate
	cdcV2 := cdcV1
	cdcV2.Image = "invalid.local/org/benthos:v2"
	r2 := orch.ReconcileSingleton(t.Context(), cdcV2)
	if r2.Status != "success" {
		t.Fatalf("Expected cdc v2 update success, got %s: %s", r2.Status, r2.Message)
	}
	mu.Lock()
	stopsAfterUpdate := len(stoppedIDs)
	currentImage := containers["uat-cdc-streamer"].image
	mu.Unlock()
	if stopsAfterUpdate != 1 || currentImage != "invalid.local/org/benthos:v2" {
		t.Errorf("Expected stateless singleton to recreate onto v2 (stops=%d, image=%s)", stopsAfterUpdate, currentImage)
	}

	// 3. Host-networked singleton (e.g. ingress tunnel daemon) omits bridge aliases & extra host-gateway
	hostSpec := SingletonSpec{
		DeploymentID:  "sing-tunnel-1",
		Service:       "tunnel-connector",
		Env:           "infra",
		Image:         "invalid.local/edge/connector:v1",
		ContainerName: "infra-tunnel-connector",
		Restart:       "always",
		Networks:      []string{"host"},
		Command:       []string{"tunnel", "--no-autoupdate", "run"},
		Secrets:       map[string]string{"TUNNEL_TOKEN": "tok-123"},
	}
	rHost := orch.ReconcileSingleton(t.Context(), hostSpec)
	if rHost.Status != "success" {
		t.Fatalf("Expected host-network singleton reconcile success, got %s: %s", rHost.Status, rHost.Message)
	}
	mu.Lock()
	hostCtr := containers["infra-tunnel-connector"]
	hostNetMode := hostCtr.cfg.HostConfig.NetworkMode
	hostExtra := slices.Clone(hostCtr.cfg.HostConfig.ExtraHosts)
	mu.Unlock()
	if hostNetMode != "host" {
		t.Errorf("Expected NetworkMode=host, got %q", hostNetMode)
	}
	if len(hostExtra) != 0 {
		t.Errorf("Expected no host.docker.internal extra host on host network, got %v", hostExtra)
	}
	rHostNoop := orch.ReconcileSingleton(t.Context(), hostSpec)
	if rHostNoop.Status != "success" {
		t.Fatalf("Expected idempotent host-network singleton re-reconcile success, got %s: %s", rHostNoop.Status, rHostNoop.Message)
	}
	mu.Lock()
	stopsAfterHostNoop := len(stoppedIDs)
	mu.Unlock()
	if stopsAfterHostNoop != 1 {
		t.Errorf("Expected zero additional stops on host-network idempotent re-reconcile, got total stops=%d", stopsAfterHostNoop)
	}
}

func TestLegacySlotAndPortDetectionAndWorkerEviction(t *testing.T) {
	containers := []RunningContainerSummary{
		{
			ID:       "id-legacy-api-green",
			Names:    []string{"acme-uat-billing-api-green"},
			State:    "running",
			Networks: map[string][]string{"acme-uat": {}, "acme-edge": {}},
		},
		{
			ID:       "id-legacy-drainer",
			Names:    []string{"acme-uat-job-drainer"},
			State:    "running",
			Networks: map[string][]string{"acme-uat": {}},
		},
		{
			ID:       "id-prod-drainer",
			Names:    []string{"acme-prod-job-drainer"},
			State:    "running",
			Networks: map[string][]string{"acme-prod": {}},
		},
		{
			ID:       "id-postgres",
			Names:    []string{"acme-uat-postgres"},
			State:    "running",
			Networks: map[string][]string{"acme-uat": {}},
		},
	}

	aliases := []string{"billing", "billing-uat", "billing-api", "acme-uat-billing-api"}
	workers := []WorkerSpec{{Name: "job-drainer", Networks: []string{"acme-uat"}}}

	matched := identifyServiceSlotContainers(
		containers,
		"billing",
		"billing",
		"uat",
		aliases,
		[]string{"acme-uat", "acme-edge"},
		workers,
	)
	if len(matched) != 1 || matched[0].container.ID != "id-legacy-api-green" || matched[0].slot != SlotGreen {
		t.Fatalf("Expected strictly acme-uat-billing-api-green as SlotGreen, got %+v", matched)
	}

	activeSlot := detectActiveServiceSlot(matched, containers, "", false, 8082, 8083)
	if activeSlot != SlotGreen {
		t.Fatalf("Expected activeSlot=SlotGreen so candidate stages onto SlotBlue, got %s", activeSlot)
	}

	// Verify managed slot takes precedence over lingering legacy opposite slot
	mixed := []RunningContainerSummary{
		{
			ID:       "id-managed-green",
			Names:    []string{"portal-ui-green"},
			State:    "running",
			Labels:   map[string]string{"flarelens.service": "portal-ui", "flarelens.slot": "green", "flarelens.env": "uat"},
			Networks: map[string][]string{"acme-uat": {}, "acme-edge": {}},
		},
		{
			ID:       "id-legacy-blue",
			Names:    []string{"acme-uat-portal-ui-blue"},
			State:    "running",
			Networks: map[string][]string{"acme-uat": {}, "acme-edge": {}},
		},
	}
	matchedMixed := identifyServiceSlotContainers(
		mixed,
		"portal-ui",
		"portal-ui",
		"uat",
		[]string{"portal-ui", "acme-uat-portal-ui"},
		[]string{"acme-uat", "acme-edge"},
		nil,
	)
	if len(matchedMixed) != 2 {
		t.Fatalf("Expected 2 matched slot containers (managed + legacy), got %d", len(matchedMixed))
	}
	if got := detectActiveServiceSlot(matchedMixed, mixed, "", false, 8091, 8092); got != SlotGreen {
		t.Fatalf("Expected managed green slot to win over legacy blue slot, got %s", got)
	}

	// Verify companion worker legacy match isolates environment strictly
	if !isLegacyCompanionWorkerContainer(containers[1], "job-drainer", "uat", []string{"acme-uat"}) {
		t.Errorf("Expected acme-uat-job-drainer to match uat job-drainer")
	}
	if isLegacyCompanionWorkerContainer(containers[2], "job-drainer", "uat", []string{"acme-uat"}) {
		t.Errorf("Expected acme-prod-job-drainer NOT to match uat job-drainer")
	}
}

func TestTraefikAliasSwitchAndRAMSecretFiles(t *testing.T) {
	routesDir := t.TempDir()
	existingRoute := filepath.Join(routesDir, "uat-billing-api.yml")
	initialYAML := `http:
  routers:
    uat-billing-api:
      rule: "Host(` + "`api-uat.example.com`" + `) || Host(` + "`auth-uat.example.com`" + `)"
      entryPoints:
        - web
      service: uat-billing-api
  services:
    uat-billing-api:
      loadBalancer:
        servers:
          - url: http://acme-uat-billing-api-green:8081
`
	if err := os.WriteFile(existingRoute, []byte(initialYAML), 0644); err != nil {
		t.Fatalf("write route: %v", err)
	}

	flipper := NewTraefikRouteFlipper(routesDir)
	if err := flipper.SwitchRoute("uat", "billing", "billing-blue", 8081, "api-uat.example.com", "billing-api"); err != nil {
		t.Fatalf("SwitchRoute failed: %v", err)
	}

	updatedBytes, err := os.ReadFile(existingRoute)
	if err != nil {
		t.Fatalf("read updated route: %v", err)
	}
	updated := string(updatedBytes)
	if !strings.Contains(updated, "url: http://billing-blue:8081") {
		t.Errorf("Expected uat-billing-api.yml upstream URL to flip to http://billing-blue:8081, got:\n%s", updated)
	}
	if !strings.Contains(updated, "auth-uat.example.com") {
		t.Errorf("Expected multi-host rule to remain intact, got:\n%s", updated)
	}

	// Verify RAM secret file materialization when host volume does not already mount /app/config
	binds := resolveVolumeBinds(nil, "uat", "blue", "billing-test", map[string]string{
		"/app/config/jwt-private.pem": "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----\n",
	})
	foundConfigBind := false
	for _, b := range binds {
		if strings.HasSuffix(b, ":/app/config:ro") {
			foundConfigBind = true
			hostDir := strings.Split(b, ":")[0]
			data, readErr := os.ReadFile(filepath.Join(hostDir, "jwt-private.pem"))
			if readErr != nil || !strings.Contains(string(data), "BEGIN PRIVATE KEY") {
				t.Errorf("Expected materialized jwt-private.pem in %s, err=%v", hostDir, readErr)
			}
			_ = os.RemoveAll(hostDir)
		}
	}
	if !foundConfigBind {
		t.Errorf("Expected RAM secret file bind :/app/config:ro in %v", binds)
	}
}

func TestDiscoverTraefikRoutesDirNestedRoutesSubdir(t *testing.T) {
	hostTraefikRoot := t.TempDir()
	nestedRoutesDir := filepath.Join(hostTraefikRoot, "routes")
	acmeDir := filepath.Join(hostTraefikRoot, "acme")
	if err := os.MkdirAll(nestedRoutesDir, 0755); err != nil {
		t.Fatalf("mkdir routes: %v", err)
	}
	if err := os.MkdirAll(acmeDir, 0755); err != nil {
		t.Fatalf("mkdir acme: %v", err)
	}

	sockPath := filepath.Join(t.TempDir(), "docker-traefik.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	defer ln.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/containers/json", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{
				"Id":    "id-traefik",
				"Names": []string{"/edge-traefik"},
				"Image": "traefik:v3.6",
				"State": "running",
				"Mounts": []map[string]any{
					{"Source": acmeDir, "Destination": "/etc/traefik/acme"},
					{"Source": hostTraefikRoot, "Destination": "/etc/traefik/dynamic"},
				},
			},
		})
	})
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	runner := NewDockerRunner("unix://" + sockPath)
	got := runner.DiscoverTraefikRoutesDir(t.Context())
	if got != nestedRoutesDir {
		t.Fatalf("Expected DiscoverTraefikRoutesDir=%q, got %q", nestedRoutesDir, got)
	}
}

func TestTraefikSwitchRouteWithMultiDomainsAndRuleAugmentation(t *testing.T) {
	routesDir := t.TempDir()
	flipper := NewTraefikRouteFlipper(routesDir)

	// Case 1: Greenfield route file generation with multiple domains
	if err := flipper.SwitchRouteWithDomains("prod", "billing-svc", "billing-svc-green", 8081, []string{"api.example.com", "auth.example.com"}, "bill-api"); err != nil {
		t.Fatalf("SwitchRouteWithDomains greenfield failed: %v", err)
	}
	generated, err := os.ReadFile(filepath.Join(routesDir, "prod-billing-svc.yaml"))
	if err != nil {
		t.Fatalf("read generated route: %v", err)
	}
	genStr := string(generated)
	if !strings.Contains(genStr, "Host(`api.example.com`) || Host(`auth.example.com`)") {
		t.Fatalf("expected multi-host rule in generated YAML, got:\n%s", genStr)
	}
	if !strings.Contains(genStr, "http://billing-svc-green:8081") {
		t.Fatalf("expected upstream http://billing-svc-green:8081, got:\n%s", genStr)
	}

	// Case 2: Existing alias route file missing migrated domains gets augmented in place without losing legacy rules
	legacyPath := filepath.Join(routesDir, "prod-portal-ui.yml")
	legacyYAML := `http:
  routers:
    prod-portal-ui:
      rule: "(HostRegexp(` + "`{org:[a-z0-9-]+}.legacy.io`" + `)) && (PathPrefix(` + "`/portal`" + `))"
      entryPoints:
        - web
      service: prod-portal-ui
  services:
    prod-portal-ui:
      loadBalancer:
        servers:
          - url: http://legacy-portal-blue:80
`
	if err := os.WriteFile(legacyPath, []byte(legacyYAML), 0644); err != nil {
		t.Fatalf("write legacy route: %v", err)
	}
	if err := flipper.SwitchRouteWithDomains("prod", "portal-ui", "portal-ui-green", 80, []string{"portal.example.com"}); err != nil {
		t.Fatalf("SwitchRouteWithDomains legacy augment failed: %v", err)
	}
	augmentedRaw, err := os.ReadFile(legacyPath)
	if err != nil {
		t.Fatalf("read augmented route: %v", err)
	}
	augStr := string(augmentedRaw)
	if !strings.Contains(augStr, "http://portal-ui-green:80") {
		t.Fatalf("expected updated upstream http://portal-ui-green:80, got:\n%s", augStr)
	}
	if !strings.Contains(augStr, "HostRegexp") || !strings.Contains(augStr, "Host(`portal.example.com`)") {
		t.Fatalf("expected both preserved HostRegexp and appended Host(`portal.example.com`), got:\n%s", augStr)
	}
}

func TestMultiNodeTraefikMeshUpstreamsAndDecommissionFencing(t *testing.T) {
	routesDir := t.TempDir()
	flipper := NewTraefikRouteFlipper(routesDir)

	if err := flipper.SyncMultiNodeRoute(
		"prod",
		"checkout-api",
		[]string{"api.example.com"},
		[]string{"http://127.0.0.1:18081", "http://100.64.0.2:28080", "http://100.64.0.3:28080"},
		"/health",
	); err != nil {
		t.Fatalf("SyncMultiNodeRoute failed: %v", err)
	}

	routeFile := filepath.Join(routesDir, "prod-checkout-api.yaml")
	rawBytes, err := os.ReadFile(routeFile)
	if err != nil {
		t.Fatalf("read multi-node route: %v", err)
	}
	content := string(rawBytes)
	for _, want := range []string{
		`path: "/health"`,
		`url: "http://127.0.0.1:18081"`,
		`url: "http://100.64.0.2:28080"`,
		`url: "http://100.64.0.3:28080"`,
	} {
		if !strings.Contains(content, want) {
			t.Fatalf("expected %q in multi-node Traefik YAML, got:\n%s", want, content)
		}
	}

	// Verify DecommissionService fences stateful Postgres singletons by default,
	// while draining stateless services and repointing Traefik to surviving remote mesh replicas.
	orch := NewOrchestrator(NewDockerRunner("mock://docker.sock"), NewHealthProber(), flipper, nil, "node-1", nil)
	fenced := orch.DecommissionService(t.Context(), DecommissionRequest{
		DeploymentID:  "dec-pg-1",
		Service:       "postgres",
		Env:           "prod",
		ContainerName: "postgres-prod",
	})
	if fenced.Status != "skipped" {
		t.Fatalf("expected stateful postgres decommission to be fenced (skipped), got %s: %s", fenced.Status, fenced.Message)
	}

	decStateless := orch.DecommissionService(t.Context(), DecommissionRequest{
		DeploymentID:    "dec-api-1",
		Service:         "checkout-api",
		Env:             "prod",
		Domains:         []string{"api.example.com"},
		HealthPath:      "/health",
		RemoteUpstreams: []string{"http://100.64.0.2:28080", "http://100.64.0.3:28080"},
		DrainSeconds:    0,
	})
	if decStateless.Status != "success" {
		t.Fatalf("expected stateless decommission success, got %s: %s", decStateless.Status, decStateless.Message)
	}

	afterDrainBytes, err := os.ReadFile(routeFile)
	if err != nil {
		t.Fatalf("expected Traefik route to remain pointed at surviving remote mesh replicas: %v", err)
	}
	afterDrain := string(afterDrainBytes)
	if strings.Contains(afterDrain, "127.0.0.1:18081") {
		t.Fatalf("expected drained local replica 127.0.0.1:18081 removed from Traefik route, got:\n%s", afterDrain)
	}
	if !strings.Contains(afterDrain, "http://100.64.0.2:28080") {
		t.Fatalf("expected surviving mesh replica http://100.64.0.2:28080 retained in Traefik route, got:\n%s", afterDrain)
	}
}

func TestMeshDNSHookPromotesExtraHostsToDynamicDNSWithFallback(t *testing.T) {
	sockDir, err := os.MkdirTemp("/tmp", "fl-dns-")
	if err != nil {
		t.Fatalf("mkdirtemp: %v", err)
	}
	defer os.RemoveAll(sockDir)
	sockPath := filepath.Join(sockDir, "d.sock")

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	defer ln.Close()

	var mu sync.Mutex
	created := make(map[string]containerCreateConfig)

	mux := http.NewServeMux()
	mux.HandleFunc("/images/create", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"pulled"}`))
	})
	mux.HandleFunc("/networks/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/containers/create", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		var cfg containerCreateConfig
		_ = json.NewDecoder(r.Body).Decode(&cfg)
		mu.Lock()
		created[name] = cfg
		mu.Unlock()
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"Id":"id-` + name + `"}`))
	})
	mux.HandleFunc("/containers/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/json") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	runner := NewDockerRunner("unix://" + sockPath)
	orch := NewOrchestrator(runner, NewHealthProber(), NewTraefikRouteFlipper(t.TempDir()), nil, "node-1", nil)

	var seededEnv string
	var seededEntries []string
	dnsActive := true

	orch.SetMeshRoutingHooks(
		func(env string) []string {
			return []string{"workflow:100.64.0.2", "workflow-uat:100.64.0.2"}
		},
		nil,
	)
	orch.SetMeshDNSHook(
		func(env string) ([]string, []string) {
			if !dnsActive {
				return nil, nil
			}
			return []string{"100.64.0.1", "1.1.1.1"}, []string{env + ".mesh", "mesh"}
		},
		func(env string, extraHosts []string) {
			seededEnv = env
			seededEntries = slices.Clone(extraHosts)
		},
	)

	// 1. When MagicDNS is bound on <overlay_ip>:53, HostConfig.Dns & DnsSearch are injected
	// and 100.64.0.0/10 entries are omitted from /etc/hosts so TTL=5s DNS failover works live.
	resp1 := orch.ReconcileSingleton(t.Context(), SingletonSpec{
		DeploymentID:  "dns-active-1",
		Service:       "billing-worker",
		Env:           "uat",
		Image:         "ghcr.io/example/billing:v1",
		ContainerName: "billing-worker-uat",
		Networks:      []string{"app-uat"},
		ExtraHosts:    []string{"erp.internal:192.168.10.25", "cache:100.64.0.3"},
	})
	if resp1.Status != "success" {
		t.Fatalf("singleton reconcile with active Mesh DNS failed: %s", resp1.Message)
	}

	mu.Lock()
	activeCfg := created["billing-worker-uat"]
	mu.Unlock()

	if !slices.Equal(activeCfg.HostConfig.DNS, []string{"100.64.0.1", "1.1.1.1"}) {
		t.Fatalf("want HostConfig.Dns=[100.64.0.1 1.1.1.1], got %v", activeCfg.HostConfig.DNS)
	}
	if !slices.Equal(activeCfg.HostConfig.DNSSearch, []string{"uat.mesh", "mesh"}) {
		t.Fatalf("want HostConfig.DnsSearch=[uat.mesh mesh], got %v", activeCfg.HostConfig.DNSSearch)
	}
	if seededEnv != "uat" || !slices.Contains(seededEntries, "workflow:100.64.0.2") || !slices.Contains(seededEntries, "cache:100.64.0.3") {
		t.Fatalf("expected CGNAT ExtraHosts seeded into MagicDNS, got env=%q entries=%v", seededEnv, seededEntries)
	}
	for _, eh := range activeCfg.HostConfig.ExtraHosts {
		if strings.Contains(eh, "100.64.0.") {
			t.Fatalf("expected 100.64.0.x stripped from /etc/hosts ExtraHosts when Mesh DNS is active, got %v", activeCfg.HostConfig.ExtraHosts)
		}
	}
	if !slices.Contains(activeCfg.HostConfig.ExtraHosts, "host.docker.internal:host-gateway") ||
		!slices.Contains(activeCfg.HostConfig.ExtraHosts, "erp.internal:192.168.10.25") {
		t.Fatalf("expected non-mesh ExtraHosts preserved, got %v", activeCfg.HostConfig.ExtraHosts)
	}

	// 2. When MagicDNS is unavailable (e.g. unprivileged host without port 53), ExtraHosts fallback stays intact.
	dnsActive = false
	resp2 := orch.ReconcileSingleton(t.Context(), SingletonSpec{
		DeploymentID:  "dns-fallback-1",
		Service:       "audit-worker",
		Env:           "uat",
		Image:         "ghcr.io/example/audit:v1",
		ContainerName: "audit-worker-uat",
		Networks:      []string{"app-uat"},
	})
	if resp2.Status != "success" {
		t.Fatalf("singleton reconcile fallback failed: %s", resp2.Message)
	}

	mu.Lock()
	fallbackCfg := created["audit-worker-uat"]
	mu.Unlock()

	if len(fallbackCfg.HostConfig.DNS) != 0 {
		t.Fatalf("expected empty HostConfig.Dns in fallback mode, got %v", fallbackCfg.HostConfig.DNS)
	}
	if !slices.Contains(fallbackCfg.HostConfig.ExtraHosts, "workflow:100.64.0.2") {
		t.Fatalf("expected ExtraHosts fallback to retain workflow:100.64.0.2, got %v", fallbackCfg.HostConfig.ExtraHosts)
	}
}

func TestContainerCgroupResourceLimitsLiveUpdateAndAutoImagePrune(t *testing.T) {
	sockDir, err := os.MkdirTemp("/tmp", "fl-res-")
	if err != nil {
		t.Fatalf("mkdirtemp: %v", err)
	}
	defer os.RemoveAll(sockDir)
	sockPath := filepath.Join(sockDir, "d.sock")

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	defer ln.Close()

	var mu sync.Mutex
	created := make(map[string]containerCreateConfig)
	running := make(map[string]bool)
	updatedLimits := make(map[string]struct {
		Memory   int64 `json:"Memory"`
		NanoCPUs int64 `json:"NanoCPUs"`
	})
	var pruneFilters []string

	mux := http.NewServeMux()
	mux.HandleFunc("/images/create", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"pulled"}`))
	})
	mux.HandleFunc("/images/prune", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		pruneFilters = append(pruneFilters, r.URL.Query().Get("filters"))
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ImagesDeleted":[{"Deleted":"sha256:old1"}],"SpaceReclaimed":104857600}`))
	})
	mux.HandleFunc("/networks/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/containers/create", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		var cfg containerCreateConfig
		_ = json.NewDecoder(r.Body).Decode(&cfg)
		mu.Lock()
		created[name] = cfg
		mu.Unlock()
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"Id":"id-` + name + `"}`))
	})
	mux.HandleFunc("/containers/", func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/containers/")
		if strings.HasSuffix(path, "/start") {
			id := strings.TrimSuffix(path, "/start")
			mu.Lock()
			running[id] = true
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if strings.HasSuffix(path, "/update") {
			id := strings.TrimSuffix(path, "/update")
			var body struct {
				Memory   int64 `json:"Memory"`
				NanoCPUs int64 `json:"NanoCPUs"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			mu.Lock()
			updatedLimits[id] = body
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"Warnings":[]}`))
			return
		}
		if strings.HasSuffix(path, "/json") {
			name := strings.TrimSuffix(path, "/json")
			mu.Lock()
			cfg, ok := created[name]
			isRun := running["id-"+name]
			mu.Unlock()
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"Id":    "id-" + name,
				"State": map[string]any{"Running": isRun},
				"Config": map[string]any{
					"Image":  cfg.Image,
					"Labels": cfg.Labels,
				},
				"NetworkSettings": map[string]any{"Networks": map[string]any{}},
			})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	runner := NewDockerRunner("unix://" + sockPath)
	orch := NewOrchestrator(runner, NewHealthProber(), NewTraefikRouteFlipper(t.TempDir()), nil, "node-1", nil)

	// 1. New container gets hard Memory (512 MiB) & NanoCPUs (1.5 cores) cgroup limits
	resp1 := orch.ReconcileSingleton(t.Context(), SingletonSpec{
		DeploymentID:  "cg-pg-1",
		Service:       "postgres",
		Env:           "uat",
		Image:         "postgres:18-alpine",
		ContainerName: "uat-postgres",
		Networks:      []string{"app-uat"},
		MemoryMB:      512,
		CPUCores:      1.5,
	})
	if resp1.Status != "success" {
		t.Fatalf("create postgres singleton failed: %s", resp1.Message)
	}

	mu.Lock()
	pgCfg := created["uat-postgres"]
	mu.Unlock()

	const want512MiB = int64(512) * 1024 * 1024
	const want15Cores = int64(1_500_000_000)
	if pgCfg.HostConfig.Memory != want512MiB {
		t.Fatalf("want HostConfig.Memory=%d, got %d", want512MiB, pgCfg.HostConfig.Memory)
	}
	if pgCfg.HostConfig.NanoCPUs != want15Cores {
		t.Fatalf("want HostConfig.NanoCPUs=%d, got %d", want15Cores, pgCfg.HostConfig.NanoCPUs)
	}

	// 2. Reconciling an already-running stateful singleton updates cgroup limits IN PLACE (zero restart)
	resp2 := orch.ReconcileSingleton(t.Context(), SingletonSpec{
		DeploymentID:  "cg-pg-2",
		Service:       "postgres",
		Env:           "uat",
		Image:         "postgres:18-alpine",
		ContainerName: "uat-postgres",
		Networks:      []string{"app-uat"},
		MemoryMB:      1024,
		CPUCores:      2.0,
	})
	if resp2.Status != "success" {
		t.Fatalf("live-update postgres singleton failed: %s", resp2.Message)
	}

	mu.Lock()
	liveUpd, didLiveUpdate := updatedLimits["id-uat-postgres"]
	mu.Unlock()
	if !didLiveUpdate {
		t.Fatalf("expected live /containers/id-uat-postgres/update call without restarting postgres")
	}
	if liveUpd.Memory != int64(1024)*1024*1024 || liveUpd.NanoCPUs != 2_000_000_000 {
		t.Fatalf("unexpected live resource update payload: %+v", liveUpd)
	}

	// 3. Auto Image Prune executes 2 passes (dangling 24h + unused tagged 72h) and respects cooldown debounce
	orch.SetImagePrunePolicy(time.Hour, 72*time.Hour)
	orch.MaybeAutoPruneImages(t.Context())
	orch.MaybeAutoPruneImages(t.Context()) // second call inside 1h cooldown must be skipped

	mu.Lock()
	gotFilters := slices.Clone(pruneFilters)
	mu.Unlock()

	if len(gotFilters) != 2 {
		t.Fatalf("expected exactly 2 prune API passes (debounced), got %d: %v", len(gotFilters), gotFilters)
	}
	if !strings.Contains(gotFilters[0], `"dangling":["true"]`) || !strings.Contains(gotFilters[0], `"24h"`) {
		t.Fatalf("unexpected pass 1 dangling prune filter: %s", gotFilters[0])
	}
	if !strings.Contains(gotFilters[1], `"dangling":["false"]`) || !strings.Contains(gotFilters[1], `"72h"`) {
		t.Fatalf("unexpected pass 2 unused image prune filter: %s", gotFilters[1])
	}
}
