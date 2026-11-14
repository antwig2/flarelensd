package system

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestValidateRetirableSystemdUnit(t *testing.T) {
	valid := []string{
		"legacy-app-auto-deploy-uat.timer",
		"legacy-app-auto-deploy-uat.service",
		"billing_poller@prod.timer",
	}
	for _, u := range valid {
		if err := ValidateRetirableSystemdUnit(u); err != nil {
			t.Fatalf("expected %q to be valid, got error: %v", u, err)
		}
	}

	invalid := []string{
		"",
		"-bad.service",
		"flarelens-agent.service",
		"flarelensd.service",
		"docker.service",
		"sshd.service",
		"cloudflared.service",
		"systemd-journald.service",
		"wg-quick@wg0.service",
		"../etc/passwd.service",
		"foo.service; rm -rf /",
		"foo.socket",
	}
	for _, u := range invalid {
		if err := ValidateRetirableSystemdUnit(u); err == nil {
			t.Fatalf("expected %q to be rejected", u)
		}
	}
}

func TestRetireSystemdUnits(t *testing.T) {
	var calls []string
	execFn := func(_ context.Context, name string, args ...string) ([]byte, error) {
		call := name + " " + strings.Join(args, " ")
		calls = append(calls, call)

		unit := args[len(args)-1]
		if args[0] == "show" {
			if strings.Contains(unit, "prod") {
				return []byte("not-found\n"), nil
			}
			return []byte("loaded\n"), nil
		}
		return []byte(""), nil
	}

	results, err := RetireSystemdUnits(t.Context(), []string{
		"app-auto-deploy-uat.timer",
		"app-auto-deploy-uat.service",
		"app-auto-deploy-prod.timer",
		"app-auto-deploy-uat.timer", // duplicate
	}, execFn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("expected 3 deduplicated results, got %d", len(results))
	}
	if results[0].Status != "retired" || results[1].Status != "retired" || results[2].Status != "not_present" {
		t.Fatalf("unexpected statuses: %+v", results)
	}
	if calls[len(calls)-1] != "systemctl daemon-reload" {
		t.Fatalf("expected trailing systemctl daemon-reload, got %v", calls)
	}
}

func TestRetireSystemdUnitsRejectsProtectedBatch(t *testing.T) {
	called := false
	_, err := RetireSystemdUnits(t.Context(), []string{
		"app-auto-deploy-uat.timer",
		"docker.service",
	}, func(_ context.Context, _ string, _ ...string) ([]byte, error) {
		called = true
		return nil, errors.New("should not execute")
	})
	if err == nil {
		t.Fatal("expected error for protected unit")
	}
	if called {
		t.Fatal("expected fail-closed validation before any command execution")
	}
}

func TestWaitForDrainLock(t *testing.T) {
	var busy atomic.Bool
	busy.Store(true)

	go func() {
		time.Sleep(40 * time.Millisecond)
		busy.Store(false)
	}()

	if err := WaitForDrainLock(t.Context(), func() bool { return !busy.Load() }, 500*time.Millisecond, 10*time.Millisecond); err != nil {
		t.Fatalf("expected drain lock to clear cleanly, got: %v", err)
	}

	busy.Store(true)
	if err := WaitForDrainLock(t.Context(), func() bool { return !busy.Load() }, 35*time.Millisecond, 10*time.Millisecond); err == nil {
		t.Fatal("expected timeout error when busy operations do not finish")
	}
}
