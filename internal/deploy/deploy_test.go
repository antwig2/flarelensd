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
