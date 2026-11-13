package updater

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Config configures the atomic Over-The-Air (OTA) binary self-updater.
type Config struct {
	CurrentVersion string
	ControlURL     string
	AuthToken      string
	TargetArch     string
	ExecutablePath string
	HTTPClient     *http.Client
	IsIdle         func() bool
	DrainTimeout   time.Duration
	OnRestart      func(execPath string) error
	Logger         *slog.Logger
}

// UpdateRequest defines an OTA self-update trigger.
type UpdateRequest struct {
	Version         string `json:"version"`
	SHA256          string `json:"sha256"`
	DownloadURL     string `json:"download_url,omitempty"`
	Force           bool   `json:"force,omitempty"`
	AllowUnverified bool   `json:"-"`
}

// UpdateResult reports the outcome of an OTA self-update execution.
type UpdateResult struct {
	Status          string `json:"status"` // "updated", "up_to_date"
	PreviousVersion string `json:"previous_version"`
	TargetVersion   string `json:"target_version"`
	SHA256          string `json:"sha256"`
	ExecutablePath  string `json:"executable_path"`
	BackupPath      string `json:"backup_path,omitempty"`
	SmokeOutput     string `json:"smoke_output,omitempty"`
}

// Updater executes drain-aware, symlink-safe, SHA-256 verified binary swaps.
type Updater struct {
	cfg Config
}

// New creates a new Updater with safe defaults.
func New(cfg Config) *Updater {
	if cfg.TargetArch == "" {
		cfg.TargetArch = fmt.Sprintf("%s-%s", runtime.GOOS, runtime.GOARCH)
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 5 * time.Minute}
	}
	if cfg.DrainTimeout <= 0 {
		cfg.DrainTimeout = 5 * time.Minute
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Updater{cfg: cfg}
}

// NormalizeVersion strips leading "v" prefixes and whitespace for version comparison.
func NormalizeVersion(v string) string {
	trimmed := strings.TrimSpace(v)
	trimmed = strings.TrimPrefix(trimmed, "v")
	trimmed = strings.TrimPrefix(trimmed, "V")
	return trimmed
}

// Apply downloads, verifies, smoke-tests, and atomically swaps the running agent binary.
func (u *Updater) Apply(ctx context.Context, req UpdateRequest) (UpdateResult, error) {
	prevNorm := NormalizeVersion(u.cfg.CurrentVersion)
	targetNorm := NormalizeVersion(req.Version)

	if targetNorm != "" && targetNorm == prevNorm && !req.Force {
		return UpdateResult{
			Status:          "up_to_date",
			PreviousVersion: u.cfg.CurrentVersion,
			TargetVersion:   req.Version,
		}, nil
	}

	expectedSum := strings.ToLower(strings.TrimSpace(req.SHA256))
	if expectedSum == "" && !req.AllowUnverified {
		return UpdateResult{}, errors.New("refusing OTA self-update without cryptographic sha256 digest")
	}

	// 1. Wait for active deployments and backups to drain cleanly.
	if err := u.waitForIdle(ctx); err != nil {
		return UpdateResult{}, err
	}

	// 2. Resolve symlink target so swaps occur in the writable install directory (e.g. /opt/.../bin under ProtectSystem=full).
	execPath, err := u.resolveExecutablePath()
	if err != nil {
		return UpdateResult{}, fmt.Errorf("resolve executable path: %w", err)
	}
	execDir := filepath.Dir(execPath)
	execBase := filepath.Base(execPath)
	tmpPath := filepath.Join(execDir, fmt.Sprintf(".%s.new.%d", execBase, os.Getpid()))
	backupPath := execPath + ".prev"
	defer func() {
		_ = os.Remove(tmpPath)
	}()

	// 3. Build download URL and stream binary while computing SHA-256.
	downloadURL, err := u.resolveDownloadURL(req)
	if err != nil {
		return UpdateResult{}, err
	}

	u.cfg.Logger.Info("Downloading OTA agent binary",
		"current_version", u.cfg.CurrentVersion,
		"target_version", req.Version,
		"url", downloadURL,
		"target_path", execPath,
	)

	actualSum, err := u.downloadAndHash(ctx, downloadURL, tmpPath)
	if err != nil {
		return UpdateResult{}, err
	}

	if expectedSum != "" && actualSum != expectedSum {
		return UpdateResult{}, fmt.Errorf("sha256 mismatch: expected %s, got %s", expectedSum, actualSum)
	}

	// 4. Mark executable and run pre-flight `--version` smoke check before touching live binary.
	if err := os.Chmod(tmpPath, 0o755); err != nil {
		return UpdateResult{}, fmt.Errorf("chmod candidate binary: %w", err)
	}

	smokeCtx, cancelSmoke := context.WithTimeout(ctx, 5*time.Second)
	defer cancelSmoke()
	smokeOutBytes, err := exec.CommandContext(smokeCtx, tmpPath, "--version").CombinedOutput()
	smokeOut := strings.TrimSpace(string(smokeOutBytes))
	if err != nil {
		return UpdateResult{}, fmt.Errorf("candidate binary failed --version smoke test: %w (output: %s)", err, smokeOut)
	}

	// 5. Back up current binary to .prev and atomically swap via POSIX rename(2) on the same filesystem.
	if err := copyFileAtomic(execPath, backupPath, 0o755); err != nil {
		return UpdateResult{}, fmt.Errorf("backup current binary to %s: %w", backupPath, err)
	}

	if err := os.Rename(tmpPath, execPath); err != nil {
		return UpdateResult{}, fmt.Errorf("atomic rename %s -> %s: %w", tmpPath, execPath, err)
	}

	res := UpdateResult{
		Status:          "updated",
		PreviousVersion: u.cfg.CurrentVersion,
		TargetVersion:   cmp.Or(req.Version, smokeOut),
		SHA256:          actualSum,
		ExecutablePath:  execPath,
		BackupPath:      backupPath,
		SmokeOutput:     smokeOut,
	}

	u.cfg.Logger.Info("OTA binary swap succeeded",
		"previous_version", res.PreviousVersion,
		"target_version", res.TargetVersion,
		"sha256", res.SHA256,
		"smoke_output", res.SmokeOutput,
	)

	if u.cfg.OnRestart != nil {
		if err := u.cfg.OnRestart(execPath); err != nil {
			return res, fmt.Errorf("restart hook failed: %w", err)
		}
	}

	return res, nil
}

func (u *Updater) waitForIdle(ctx context.Context) error {
	if u.cfg.IsIdle == nil || u.cfg.IsIdle() {
		return nil
	}
	u.cfg.Logger.Info("Waiting for active deployments/backups to finish before OTA binary swap...",
		"timeout", u.cfg.DrainTimeout,
	)
	drainCtx, cancel := context.WithTimeout(ctx, u.cfg.DrainTimeout)
	defer cancel()

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		if u.cfg.IsIdle() {
			return nil
		}
		select {
		case <-drainCtx.Done():
			return fmt.Errorf("timed out waiting for active operations to drain before OTA update: %w", drainCtx.Err())
		case <-ticker.C:
		}
	}
}

func (u *Updater) resolveExecutablePath() (string, error) {
	rawPath := strings.TrimSpace(u.cfg.ExecutablePath)
	if rawPath == "" {
		var err error
		rawPath, err = os.Executable()
		if err != nil {
			return "", err
		}
	}
	resolved, err := filepath.EvalSymlinks(rawPath)
	if err != nil {
		return "", err
	}
	return filepath.Abs(resolved)
}

func (u *Updater) resolveDownloadURL(req UpdateRequest) (string, error) {
	if trimmed := strings.TrimSpace(req.DownloadURL); trimmed != "" {
		return trimmed, nil
	}
	base := strings.TrimRight(strings.TrimSpace(u.cfg.ControlURL), "/")
	if base == "" {
		return "", errors.New("missing download_url and control plane URL for OTA update")
	}
	uPath := fmt.Sprintf("%s/api/v1/agent/binary/%s", base, url.PathEscape(u.cfg.TargetArch))
	if v := strings.TrimSpace(req.Version); v != "" {
		uPath += "?version=" + url.QueryEscape(v)
	}
	return uPath, nil
}

func (u *Updater) downloadAndHash(ctx context.Context, downloadURL, destPath string) (string, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return "", fmt.Errorf("build download request: %w", err)
	}
	if u.cfg.AuthToken != "" {
		httpReq.Header.Set("Authorization", "Bearer "+u.cfg.AuthToken)
	}

	resp, err := u.cfg.HTTPClient.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("download binary: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyPreview, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", fmt.Errorf("download binary returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(bodyPreview)))
	}

	outFile, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o700)
	if err != nil {
		return "", fmt.Errorf("open temp binary %s: %w", destPath, err)
	}

	hasher := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(outFile, hasher), resp.Body)
	syncErr := outFile.Sync()
	closeErr := outFile.Close()
	if copyErr != nil {
		return "", fmt.Errorf("stream binary to %s: %w", destPath, copyErr)
	}
	if syncErr != nil {
		return "", fmt.Errorf("fsync temp binary %s: %w", destPath, syncErr)
	}
	if closeErr != nil {
		return "", fmt.Errorf("close temp binary %s: %w", destPath, closeErr)
	}
	if written == 0 {
		return "", errors.New("downloaded binary is empty (0 bytes)")
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func copyFileAtomic(srcPath, dstPath string, mode os.FileMode) error {
	in, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer in.Close()

	tmpDst := fmt.Sprintf("%s.tmp.%d", dstPath, os.Getpid())
	out, err := os.OpenFile(tmpDst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, in)
	syncErr := out.Sync()
	closeErr := out.Close()
	if copyErr != nil || syncErr != nil || closeErr != nil {
		_ = os.Remove(tmpDst)
		return cmp.Or(copyErr, syncErr, closeErr)
	}
	if err := os.Chmod(tmpDst, mode); err != nil {
		_ = os.Remove(tmpDst)
		return err
	}
	if err := os.Rename(tmpDst, dstPath); err != nil {
		_ = os.Remove(tmpDst)
		return err
	}
	return nil
}
