package updater

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func TestUpdaterHappyPathSymlinkInReadOnlyDir(t *testing.T) {
	rootDir := t.TempDir()
	optBinDir := filepath.Join(rootDir, "opt", "flarelens", "bin")
	usrLocalBinDir := filepath.Join(rootDir, "usr", "local", "bin")

	if err := os.MkdirAll(optBinDir, 0o755); err != nil {
		t.Fatalf("mkdir opt bin: %v", err)
	}
	if err := os.MkdirAll(usrLocalBinDir, 0o755); err != nil {
		t.Fatalf("mkdir usr local bin: %v", err)
	}

	realBinPath := filepath.Join(optBinDir, "flarelens-agent")
	oldPayload := []byte("#!/bin/sh\necho 'FlareLens Host Agent v2.1.0'\n")
	if err := os.WriteFile(realBinPath, oldPayload, 0o755); err != nil {
		t.Fatalf("write old binary: %v", err)
	}

	symlinkPath := filepath.Join(usrLocalBinDir, "flarelens-agent")
	if err := os.Symlink(realBinPath, symlinkPath); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	// Simulate systemd ProtectSystem=full where /usr/local/bin is read-only.
	if err := os.Chmod(usrLocalBinDir, 0o555); err != nil {
		t.Fatalf("chmod usr/local/bin read-only: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(usrLocalBinDir, 0o755)
	})

	newPayload := []byte("#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then\n  echo 'FlareLens Host Agent v2.2.0'\n  exit 0\nfi\nexit 0\n")
	newHash := sha256Hex(newPayload)

	var gotAuthHeader string
	var gotVersionQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuthHeader = r.Header.Get("Authorization")
		gotVersionQuery = r.URL.Query().Get("version")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(newPayload)
	}))
	defer srv.Close()

	restartedPath := ""
	upd := New(Config{
		CurrentVersion: "2.1.0",
		ControlURL:     srv.URL,
		AuthToken:      "enroll-secret-token",
		TargetArch:     "linux-amd64",
		ExecutablePath: symlinkPath,
		OnRestart: func(execPath string) error {
			restartedPath = execPath
			return nil
		},
	})

	res, err := upd.Apply(t.Context(), UpdateRequest{
		Version: "v2.2.0",
		SHA256:  newHash,
	})
	if err != nil {
		t.Fatalf("Apply failed: %v", err)
	}
	if res.Status != "updated" {
		t.Fatalf("expected status updated, got %s", res.Status)
	}
	if gotAuthHeader != "Bearer enroll-secret-token" {
		t.Errorf("expected Bearer auth header, got %q", gotAuthHeader)
	}
	if gotVersionQuery != "v2.2.0" {
		t.Errorf("expected version query v2.2.0, got %q", gotVersionQuery)
	}
	if restartedPath != realBinPath {
		t.Errorf("expected OnRestart(%q), got %q", realBinPath, restartedPath)
	}
	if !strings.Contains(res.SmokeOutput, "v2.2.0") {
		t.Errorf("expected smoke output to include v2.2.0, got %q", res.SmokeOutput)
	}

	swappedBytes, err := os.ReadFile(realBinPath)
	if err != nil {
		t.Fatalf("read swapped binary: %v", err)
	}
	if string(swappedBytes) != string(newPayload) {
		t.Errorf("real binary content was not updated")
	}

	prevBytes, err := os.ReadFile(realBinPath + ".prev")
	if err != nil {
		t.Fatalf("read .prev backup binary: %v", err)
	}
	if string(prevBytes) != string(oldPayload) {
		t.Errorf(".prev backup binary did not preserve previous version")
	}
}

func TestUpdaterRejectsCorruptSHA256AndFailingSmokeTest(t *testing.T) {
	binDir := t.TempDir()
	binPath := filepath.Join(binDir, "flarelens-agent")
	origPayload := []byte("#!/bin/sh\necho 'v2.1.0'\n")
	if err := os.WriteFile(binPath, origPayload, 0o755); err != nil {
		t.Fatalf("write original binary: %v", err)
	}

	badSmokePayload := []byte("#!/bin/sh\necho 'panic: corrupt build' >&2\nexit 1\n")
	badSmokeHash := sha256Hex(badSmokePayload)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(badSmokePayload)
	}))
	defer srv.Close()

	upd := New(Config{
		CurrentVersion: "2.1.0",
		ControlURL:     srv.URL,
		ExecutablePath: binPath,
		OnRestart:      func(string) error { return nil },
	})

	// 1. Missing SHA-256 rejected
	if _, err := upd.Apply(t.Context(), UpdateRequest{Version: "v2.2.0"}); err == nil {
		t.Fatalf("expected missing sha256 to be rejected")
	}

	// 2. Mismatched SHA-256 rejected
	if _, err := upd.Apply(t.Context(), UpdateRequest{
		Version: "v2.2.0",
		SHA256:  strings.Repeat("a", 64),
	}); err == nil || !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Fatalf("expected sha256 mismatch error, got: %v", err)
	}

	// 3. Valid SHA-256 but failing `--version` smoke check rejected
	if _, err := upd.Apply(t.Context(), UpdateRequest{
		Version: "v2.2.0",
		SHA256:  badSmokeHash,
	}); err == nil || !strings.Contains(err.Error(), "smoke test") {
		t.Fatalf("expected smoke test failure error, got: %v", err)
	}

	// Original binary must remain completely untouched and no temp files left behind
	currentBytes, err := os.ReadFile(binPath)
	if err != nil {
		t.Fatalf("read binary: %v", err)
	}
	if string(currentBytes) != string(origPayload) {
		t.Errorf("original binary was modified despite failed validation")
	}
	entries, _ := os.ReadDir(binDir)
	if len(entries) != 1 {
		t.Errorf("expected only original binary in dir after failed update, got %d entries", len(entries))
	}
}

func TestUpdaterWaitsForActiveOperationsToDrainAndSkipsSameVersion(t *testing.T) {
	binDir := t.TempDir()
	binPath := filepath.Join(binDir, "flarelens-agent")
	origPayload := []byte("#!/bin/sh\necho 'FlareLens Host Agent v2.2.0'\n")
	if err := os.WriteFile(binPath, origPayload, 0o755); err != nil {
		t.Fatalf("write binary: %v", err)
	}

	nextPayload := []byte("#!/bin/sh\necho 'FlareLens Host Agent v2.3.0'\n")
	nextHash := sha256Hex(nextPayload)

	var activeDeploys atomic.Int32
	activeDeploys.Store(1)

	var swappedWhileBusy atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if activeDeploys.Load() > 0 {
			swappedWhileBusy.Store(true)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(nextPayload)
	}))
	defer srv.Close()

	upd := New(Config{
		CurrentVersion: "v2.2.0",
		ControlURL:     srv.URL,
		ExecutablePath: binPath,
		IsIdle: func() bool {
			return activeDeploys.Load() == 0
		},
		DrainTimeout: 2 * time.Second,
		OnRestart:    func(string) error { return nil },
	})

	// Same version is a no-op
	noopRes, err := upd.Apply(t.Context(), UpdateRequest{Version: "2.2.0", SHA256: nextHash})
	if err != nil || noopRes.Status != "up_to_date" {
		t.Fatalf("expected up_to_date no-op, got res=%+v err=%v", noopRes, err)
	}

	// Release active deploy after 250ms
	go func() {
		time.Sleep(250 * time.Millisecond)
		activeDeploys.Store(0)
	}()

	res, err := upd.Apply(t.Context(), UpdateRequest{Version: "2.3.0", SHA256: nextHash})
	if err != nil {
		t.Fatalf("Apply after drain failed: %v", err)
	}
	if res.Status != "updated" {
		t.Fatalf("expected updated status, got %s", res.Status)
	}
	if swappedWhileBusy.Load() {
		t.Errorf("updater began downloading/swapping before active deploys reached 0")
	}
}
