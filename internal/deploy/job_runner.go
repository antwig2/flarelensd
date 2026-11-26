package deploy

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// RunJob executes an isolated One-Off Job or scheduled CronJob inside an ephemeral Docker container (--rm semantics),
// enforcing hard cgroup limits, WireGuard mesh DNS, RAM-only secret materialization, and execution timeouts.
func (o *Orchestrator) RunJob(ctx context.Context, req JobRunRequest) JobRunResponse {
	o.BeginOp()
	defer o.EndOp()
	startTime := time.Now()

	envName := normalizeEnvShort(cmp.Or(req.Env, "uat"))
	serviceName := strings.TrimSpace(req.Service)
	baseService := canonicalServiceName(cmp.Or(serviceName, "job"))
	jobName := sanitizeJobToken(cmp.Or(req.JobName, "adhoc"))
	runID := cmp.Or(strings.TrimSpace(req.RunID), fmt.Sprintf("job_%d", startTime.UnixMilli()))
	nodeID := cmp.Or(strings.TrimSpace(req.NodeID), o.nodeID)

	failResp := func(status string, exitCode int, errMsg string, output string, containerID string) JobRunResponse {
		return JobRunResponse{
			RunID:       runID,
			JobName:     cmp.Or(strings.TrimSpace(req.JobName), jobName),
			Service:     serviceName,
			Env:         envName,
			NodeID:      nodeID,
			ContainerID: containerID,
			Status:      status,
			ExitCode:    exitCode,
			Output:      output,
			Error:       errMsg,
			DurationMS:  time.Since(startTime).Milliseconds(),
		}
	}

	if strings.TrimSpace(req.Image) == "" {
		return failResp("failed", 1, "job image is required", "", "")
	}
	if len(req.Command) == 0 && len(req.Entrypoint) == 0 {
		return failResp("failed", 1, "job command or entrypoint is required", "", "")
	}

	timeoutSec := min(max(cmp.Or(req.TimeoutSeconds, 600), 1), 86400)

	o.logger.Info("Starting isolated container job",
		"run_id", runID,
		"service", serviceName,
		"job_name", jobName,
		"env", envName,
		"image", req.Image,
		"trigger", cmp.Or(req.Trigger, "manual"),
		"timeout_seconds", timeoutSec,
	)

	// 1. Pull job image
	pullCtx, cancelPull := context.WithTimeout(ctx, 3*time.Minute)
	pullErr := o.runner.PullImage(pullCtx, req.Image)
	cancelPull()
	if pullErr != nil {
		o.logger.Error("Job failed during image pull", "run_id", runID, "image", req.Image, "error", pullErr)
		return failResp("failed", 1, "Image pull failed: "+pullErr.Error(), "", "")
	}

	// 2. Separate in-memory env secrets from __FLARELENS_FILE__ RAM secret files
	activeSecrets := make(map[string]string, len(req.Secrets))
	secretFiles := make(map[string]string)
	for k, v := range req.Secrets {
		if after, ok := strings.CutPrefix(k, "__FLARELENS_FILE__"); ok {
			if cleanPath := strings.TrimSpace(after); cleanPath != "" && v != "" {
				secretFiles[cleanPath] = v
			}
			continue
		}
		activeSecrets[k] = v
	}

	envList := make([]string, 0, len(activeSecrets)+6)
	envList = append(envList,
		fmt.Sprintf("DEPLOY_ENV=%s", envName),
		fmt.Sprintf("SERVICE_NAME=%s", baseService),
		fmt.Sprintf("FLARELENS_JOB_NAME=%s", cmp.Or(strings.TrimSpace(req.JobName), jobName)),
		fmt.Sprintf("FLARELENS_JOB_RUN_ID=%s", runID),
		fmt.Sprintf("FLARELENS_JOB_TRIGGER=%s", cmp.Or(req.Trigger, "manual")),
	)
	if !hasEnvKeyOrSuffix(activeSecrets, "APP_ENV") {
		envList = append(envList, fmt.Sprintf("APP_ENV=%s", envName))
	}
	secretKeys := slices.Sorted(func(yield func(string) bool) {
		for k := range activeSecrets {
			if !yield(k) {
				return
			}
		}
	})
	for _, k := range secretKeys {
		envList = append(envList, fmt.Sprintf("%s=%s", k, activeSecrets[k]))
	}

	// 3. Resolve volume binds + per-run ephemeral /dev/shm secret files (cleaned up immediately on exit)
	mountedDests := make(map[string]bool)
	binds := make([]string, 0, len(req.Volumes)+len(secretFiles)+1)
	for _, vol := range req.Volumes {
		cleanVol := strings.TrimSpace(vol)
		if cleanVol == "" {
			continue
		}
		parts := strings.Split(cleanVol, ":")
		if len(parts) >= 2 && strings.HasPrefix(parts[0], "/") {
			if _, statErr := os.Stat(parts[0]); statErr == nil {
				binds = append(binds, cleanVol)
				mountedDests[strings.TrimSuffix(filepath.ToSlash(parts[1]), "/")] = true
			}
		} else {
			binds = append(binds, cleanVol)
		}
	}
	if _, statErr := os.Stat("/etc/flarelens/flags"); statErr == nil && !mountedDests["/etc/flarelens/flags"] {
		binds = append(binds, "/etc/flarelens/flags:/etc/flarelens/flags:ro")
		mountedDests["/etc/flarelens/flags"] = true
	}

	ephemeralBinds, cleanupSecrets := materializeEphemeralJobSecretBinds(secretFiles, mountedDests, runID)
	defer cleanupSecrets()
	binds = append(binds, ephemeralBinds...)

	// 4. Resolve Docker networks & WireGuard split-horizon MagicDNS / ExtraHosts
	profile := resolveServiceProfile(cmp.Or(serviceName, jobName), envName)
	networks := dedupeNonEmptyStrings(req.Networks)
	if len(networks) == 0 && strings.TrimSpace(req.Network) != "" {
		networks = []string{strings.TrimSpace(req.Network)}
	}
	if len(networks) == 0 {
		networks = profile.Networks
	}
	if len(networks) == 0 {
		networks = []string{"flarelens-edge"}
	}
	extraHosts, dnsServers, dnsSearch := o.resolveMeshNetworkConfig(envName, req.ExtraHosts)

	shortRun := sanitizeJobToken(runID)
	if len(shortRun) > 16 {
		shortRun = shortRun[len(shortRun)-16:]
	}
	containerName := fmt.Sprintf("flarelens-job-%s-%s-%s-%s", envName, sanitizeJobToken(baseService), jobName, shortRun)
	if len(containerName) > 63 {
		containerName = strings.TrimRight(containerName[:63], "-")
	}

	// Best-effort cleanup if a retry collides with a stale container name
	if staleID, _ := o.runner.FindContainerIDByName(ctx, containerName); staleID != "" {
		_ = o.runner.RemoveContainer(ctx, staleID)
	}

	containerID, createErr := o.runner.CreateContainerWithOptions(ctx, ContainerConfig{
		Name:          containerName,
		Image:         req.Image,
		EnvVars:       envList,
		Cmd:           slices.Clone(req.Command),
		Entrypoint:    slices.Clone(req.Entrypoint),
		Binds:         binds,
		ExtraHosts:    extraHosts,
		DNS:           dnsServers,
		DNSSearch:     dnsSearch,
		MemoryMB:      req.MemoryMB,
		CPUCores:      req.CPUCores,
		SecurityOpt:   []string{"no-new-privileges:true"},
		RestartPolicy: "no",
		Networks:      networks,
		Labels: map[string]string{
			"flarelens.managed": "true",
			"flarelens.role":    "job",
			"flarelens.env":     envName,
			"flarelens.service": baseService,
			"flarelens.job":     cmp.Or(strings.TrimSpace(req.JobName), jobName),
			"flarelens.run_id":  runID,
		},
	})
	if createErr != nil {
		o.logger.Error("Failed to create job container", "run_id", runID, "error", createErr)
		return failResp("failed", 1, "Container create failed: "+createErr.Error(), "", "")
	}

	// Strictly enforce --rm semantics regardless of exit code, panic, or timeout
	defer func() {
		rmCtx, cancelRm := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancelRm()
		_ = o.runner.RemoveContainer(rmCtx, containerID)
	}()

	if startErr := o.runner.StartContainer(ctx, containerID); startErr != nil {
		o.logger.Error("Failed to start job container", "run_id", runID, "container_id", containerID, "error", startErr)
		return failResp("failed", 1, "Container start failed: "+startErr.Error(), "", containerID)
	}

	// 5. Wait for completion under hard job timeout
	waitCtx, cancelWait := context.WithTimeout(ctx, time.Duration(timeoutSec)*time.Second)
	exitCode, waitErrMsg, waitErr := o.runner.WaitContainer(waitCtx, containerID)
	timedOut := errors.Is(waitErr, context.DeadlineExceeded)
	cancelWait()

	if timedOut {
		stopCtx, cancelStop := context.WithTimeout(context.Background(), 10*time.Second)
		_ = o.runner.StopContainer(stopCtx, containerID, 5)
		cancelStop()
	}

	logCtx, cancelLogs := context.WithTimeout(context.Background(), 10*time.Second)
	logsOut, _ := o.runner.FetchContainerLogs(logCtx, containerID, 250)
	cancelLogs()

	if timedOut {
		msg := fmt.Sprintf("Job timed out after %ds", timeoutSec)
		o.logger.Warn("Container job timed out", "run_id", runID, "job_name", jobName, "timeout_seconds", timeoutSec)
		return failResp("timed_out", 124, msg, logsOut, containerID)
	}
	if waitErr != nil {
		o.logger.Error("Error waiting on job container", "run_id", runID, "error", waitErr)
		return failResp("failed", 1, "Container wait failed: "+waitErr.Error(), logsOut, containerID)
	}
	if exitCode != 0 {
		errDetail := cmp.Or(waitErrMsg, fmt.Sprintf("Process exited with status %d", exitCode))
		o.logger.Warn("Container job exited with non-zero code",
			"run_id", runID,
			"job_name", jobName,
			"exit_code", exitCode,
		)
		return failResp("failed", exitCode, errDetail, logsOut, containerID)
	}

	o.logger.Info("Container job completed successfully",
		"run_id", runID,
		"job_name", jobName,
		"duration_ms", time.Since(startTime).Milliseconds(),
	)
	return JobRunResponse{
		RunID:       runID,
		JobName:     cmp.Or(strings.TrimSpace(req.JobName), jobName),
		Service:     serviceName,
		Env:         envName,
		NodeID:      nodeID,
		ContainerID: containerID,
		Status:      "succeeded",
		ExitCode:    0,
		Output:      logsOut,
		DurationMS:  time.Since(startTime).Milliseconds(),
	}
}

func sanitizeJobToken(raw string) string {
	lower := strings.ToLower(strings.TrimSpace(raw))
	if lower == "" {
		return "job"
	}
	var b strings.Builder
	b.Grow(len(lower))
	lastDash := false
	for _, r := range lower {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			lastDash = false
		} else if !lastDash && b.Len() > 0 {
			b.WriteByte('-')
			lastDash = true
		}
	}
	res := strings.Trim(b.String(), "-")
	if res == "" {
		return "job"
	}
	return res
}

func materializeEphemeralJobSecretBinds(
	secretFiles map[string]string,
	mountedDests map[string]bool,
	runID string,
) ([]string, func()) {
	noop := func() {}
	if len(secretFiles) == 0 {
		return nil, noop
	}

	rootBase := "/dev/shm/flarelens-secrets"
	if info, err := os.Stat("/dev/shm"); err != nil || !info.IsDir() {
		rootBase = filepath.Join(os.TempDir(), "flarelens-secrets")
	}
	if err := os.MkdirAll(rootBase, 0700); err != nil {
		return nil, noop
	}
	_ = os.Chmod(rootBase, 0700)

	runDir := filepath.Join(rootBase, fmt.Sprintf("job-%s-%d", sanitizeJobToken(runID), time.Now().UnixNano()))
	if err := os.MkdirAll(runDir, 0700); err != nil {
		return nil, noop
	}
	cleanup := func() {
		_ = os.RemoveAll(runDir)
	}

	rootFiles := make(map[string]string)
	byDir := make(map[string]map[string]string)
	for containerPath, content := range secretFiles {
		clean := filepath.ToSlash(strings.TrimSpace(containerPath))
		if !strings.HasPrefix(clean, "/") || content == "" {
			continue
		}
		rawDir := filepath.ToSlash(filepath.Dir(clean))
		base := filepath.Base(clean)
		if base == "" || base == "." || base == "/" {
			continue
		}
		if rawDir == "/" {
			if !mountedDests[clean] {
				rootFiles[clean] = content
			}
			continue
		}
		dir := strings.TrimSuffix(rawDir, "/")
		if mountedDests[dir] {
			continue
		}
		if byDir[dir] == nil {
			byDir[dir] = make(map[string]string)
		}
		byDir[dir][base] = content
	}

	var binds []string
	dirKeys := slices.Sorted(func(yield func(string) bool) {
		for k := range byDir {
			if !yield(k) {
				return
			}
		}
	})
	for _, containerDir := range dirKeys {
		files := byDir[containerDir]
		sanitizedDir := strings.ReplaceAll(strings.TrimPrefix(containerDir, "/"), "/", "_")
		hostDir := filepath.Join(runDir, sanitizedDir)
		if err := os.MkdirAll(hostDir, 0755); err != nil {
			continue
		}
		fileNames := slices.Sorted(func(yield func(string) bool) {
			for fn := range files {
				if !yield(fn) {
					return
				}
			}
		})
		wroteAny := false
		for _, fn := range fileNames {
			targetFile := filepath.Join(hostDir, fn)
			mode := secretFileMode(fn)
			if err := os.WriteFile(targetFile, []byte(files[fn]), mode); err == nil {
				_ = os.Chmod(targetFile, mode)
				wroteAny = true
			}
		}
		if wroteAny {
			binds = append(binds, fmt.Sprintf("%s:%s:ro", hostDir, containerDir))
			mountedDests[containerDir] = true
		}
	}

	rootPaths := slices.Sorted(func(yield func(string) bool) {
		for p := range rootFiles {
			if !yield(p) {
				return
			}
		}
	})
	for _, containerFile := range rootPaths {
		fn := filepath.Base(containerFile)
		targetFile := filepath.Join(runDir, "root_"+fn)
		mode := secretFileMode(fn)
		if err := os.WriteFile(targetFile, []byte(rootFiles[containerFile]), mode); err == nil {
			_ = os.Chmod(targetFile, mode)
			binds = append(binds, fmt.Sprintf("%s:%s:ro", targetFile, containerFile))
			mountedDests[containerFile] = true
		}
	}

	return binds, cleanup
}
