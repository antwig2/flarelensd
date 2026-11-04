package deploy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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

	err := flipper.FlipRoute("bill-api", "api.example.com", 8082)
	if err != nil {
		t.Fatalf("Failed to flip Traefik route: %v", err)
	}

	routeFile := filepath.Join(tmpDir, "bill-api.yaml")
	content, err := os.ReadFile(routeFile)
	if err != nil {
		t.Fatalf("Failed to read generated route file: %v", err)
	}

	str := string(content)
	if !strings.Contains(str, "bill-api-router:") {
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
	ctx := context.Background()

	err := prober.Probe(ctx, server.URL+"/healthz", 3*time.Second, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("Expected healthcheck probe to pass, got error: %v", err)
	}
}

func TestHealthProberTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable) // 503 error
	}))
	defer server.Close()

	prober := NewHealthProber()
	ctx := context.Background()

	err := prober.Probe(ctx, server.URL+"/healthz", 300*time.Millisecond, 50*time.Millisecond)
	if err == nil {
		t.Fatalf("Expected healthcheck probe to time out and return error, got nil")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Errorf("Expected timeout error message, got: %v", err)
	}
}

func TestPreDeployHookAbortsOnFailure(t *testing.T) {
	runner := NewDockerRunner("unix:///nonexistent.sock")
	prober := NewHealthProber()
	traefik := NewTraefikRouteFlipper(t.TempDir())
	orch := NewOrchestrator(runner, prober, traefik, nil, "test-node", nil)

	hookCalled := false
	orch.SetPreDeployHook(func(ctx context.Context, service, tag string) error {
		hookCalled = true
		if service != "bill-api" {
			t.Errorf("Expected service bill-api, got %s", service)
		}
		return context.DeadlineExceeded
	})

	req := DeployRequest{
		DeploymentID:      "dep-1",
		Service:           "bill-api",
		Image:             "app/api:v2",
		PreDeploySnapshot: true,
	}

	resp := orch.Deploy(context.Background(), req)
	if !hookCalled {
		t.Fatalf("Expected pre-deploy hook to be invoked")
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
		if service != "bill-api" {
			t.Errorf("Expected service bill-api, got %s", service)
		}
		return nil
	})

	rollbackCalled := false
	orch.SetRollbackHook(func(ctx context.Context, service, tag string) error {
		rollbackCalled = true
		if service != "bill-api" {
			t.Errorf("Expected service bill-api, got %s", service)
		}
		return nil
	})

	req := DeployRequest{
		DeploymentID:      "dep-mig-fail",
		Service:           "bill-api",
		Image:             "nonexistent-image:invalid",
		PreDeploySnapshot: true,
		RunMigrations:     true,
		MigrationCmd:      "exit 1",
	}

	resp := orch.Deploy(context.Background(), req)
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

	err := flipper.SetCanaryRoute("bill-api", "api.example.com", 8081, 8082, 10)
	if err != nil {
		t.Fatalf("Failed to set Traefik canary route: %v", err)
	}

	routeFile := filepath.Join(tmpDir, "bill-api.yaml")
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

	_ = flipper.FlipRoute("bill-api-pr-42", "pr-42.example.com", 9042)
	routeFile := filepath.Join(tmpDir, "bill-api-pr-42.yaml")
	if _, err := os.Stat(routeFile); os.IsNotExist(err) {
		t.Fatalf("Expected route file to exist before removal")
	}

	if err := flipper.RemoveRoute("bill-api-pr-42"); err != nil {
		t.Fatalf("Failed to remove route: %v", err)
	}
	if _, err := os.Stat(routeFile); !os.IsNotExist(err) {
		t.Errorf("Expected route file to be removed")
	}

	// Removing non-existent route should not error
	if err := flipper.RemoveRoute("bill-api-pr-42"); err != nil {
		t.Errorf("Expected idempotent remove to succeed, got: %v", err)
	}
}

func TestTeardownPreview(t *testing.T) {
	tmpDir := t.TempDir()
	flipper := NewTraefikRouteFlipper(tmpDir)
	runner := NewDockerRunner("mock://")
	prober := NewHealthProber()
	orch := NewOrchestrator(runner, prober, flipper, nil, "node-1", nil)

	// Pre-create route file
	_ = flipper.FlipRoute("bill-api-pr-42", "pr-42-api.example.com", 9042)

	err := orch.TeardownPreview(context.Background(), TeardownRequest{
		Service:  "bill-api",
		PRNumber: 42,
	})
	if err != nil {
		t.Fatalf("TeardownPreview failed: %v", err)
	}

	routeFile := filepath.Join(tmpDir, "bill-api-pr-42.yaml")
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

	// Run deploy with RunMigrations = false and PreDeploySnapshot = false
	// Note: bill-api has a default MigrationCmd in profile, but because RunMigrations is false,
	// no snapshot and no migration should be executed.
	req := DeployRequest{
		DeploymentID:      "dep-skip-mig",
		Service:           "bill-api",
		Image:             "nonexistent-image:invalid",
		PreDeploySnapshot: false,
		RunMigrations:     false,
	}

	// This will fail during PullImage because the image doesn't exist, which proves
	// that it never tried to execute preDeployHook or migrations before step 3 (pull)!
	resp := orch.Deploy(context.Background(), req)
	if snapshotCalled {
		t.Errorf("Expected pre-deploy snapshot NOT to be called when RunMigrations is false and PreDeploySnapshot is false")
	}
	if resp.Status != "failed" {
		t.Errorf("Expected deploy to fail on mock socket, got status: %s", resp.Status)
	}
}

