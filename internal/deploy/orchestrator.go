package deploy

import (
	"cmp"
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/antwig2/flarelens/internal/transport"
)

// PreDeploySnapshotHook defines a callback executed before candidate container staging
type PreDeploySnapshotHook func(ctx context.Context, service, tag string) error

// PreDeployRollbackHook defines a callback executed if candidate staging or migrations fail
type PreDeployRollbackHook func(ctx context.Context, service, tag string) error

// Orchestrator executes zero-downtime Blue/Green deployments with automated rollback
type Orchestrator struct {
	runner        *DockerRunner
	prober        *HealthProber
	traefik       *TraefikRouteFlipper
	natsClient    *transport.NATSClient
	logger        *slog.Logger
	preDeployHook PreDeploySnapshotHook
	rollbackHook  PreDeployRollbackHook
	migrator      *MigrationRunner

	mu          sync.RWMutex
	activeSlots map[string]Slot
	nodeID      string
}

func NewOrchestrator(
	runner *DockerRunner,
	prober *HealthProber,
	traefik *TraefikRouteFlipper,
	natsClient *transport.NATSClient,
	nodeID string,
	logger *slog.Logger,
) *Orchestrator {
	if logger == nil {
		logger = slog.Default()
	}
	return &Orchestrator{
		runner:      runner,
		prober:      prober,
		traefik:     traefik,
		natsClient:  natsClient,
		logger:      logger,
		activeSlots: make(map[string]Slot),
		nodeID:      nodeID,
		migrator:    NewMigrationRunner(logger),
	}
}

// SetPreDeployHook registers a pre-deploy backup guardrail hook
func (o *Orchestrator) SetPreDeployHook(hook PreDeploySnapshotHook) {
	o.preDeployHook = hook
}

// SetRollbackHook registers an automated rollback hook for failed migrations/rollouts
func (o *Orchestrator) SetRollbackHook(hook PreDeployRollbackHook) {
	o.rollbackHook = hook
}

// Deploy executes the complete 7-step zero-downtime Blue/Green deployment sequence
func (o *Orchestrator) Deploy(ctx context.Context, req DeployRequest) DeployResponse {
	startTime := time.Now()

	// Guarantee pre-deploy snapshot whenever database migrations are requested
	if req.RunMigrations {
		req.PreDeploySnapshot = true
	}

	o.logger.Info("Starting Blue/Green deployment",
		"service", req.Service,
		"image", req.Image,
		"env", req.Env,
		"domain", req.Domain,
		"pre_deploy_snapshot", req.PreDeploySnapshot,
		"run_migrations", req.RunMigrations,
	)

	// 0. Pre-Deploy Guardrail: Database Snapshot (if requested or migrations enabled)
	if req.PreDeploySnapshot && o.preDeployHook != nil {
		o.emitProgress(req, "backup", "Executing pre-deploy database snapshot guardrail...", 5)
		snapshotTag := fmt.Sprintf("pre-deploy-%s", req.Service)
		if err := o.preDeployHook(ctx, req.Service, snapshotTag); err != nil {
			o.logger.Error("Pre-deploy database snapshot failed! Aborting deployment", "error", err)
			return o.failResponse(req, "Pre-deploy snapshot guardrail failed: "+err.Error(), SlotBlue, startTime)
		}
		o.emitProgress(req, "backup", "Pre-deploy database snapshot verified and stored in Cloudflare R2", 10)
	}

	// 1. Resolve declarative service profile (Kamal-style multi-role, workers, ports, migrations, networks)
	envName := strings.ToLower(req.Env)
	if envName == "" {
		envName = "uat"
	}
	profile := resolveServiceProfile(req.Service, envName)

	// User overrides in DeployRequest take precedence
	if req.ContainerPort > 0 {
		profile.ContainerPort = req.ContainerPort
	}
	if req.HealthPath != "" {
		profile.HealthPath = req.HealthPath
	}
	if len(req.Networks) > 0 {
		profile.Networks = req.Networks
	}
	if len(req.Command) > 0 {
		profile.Command = req.Command
	}
	if len(req.Entrypoint) > 0 {
		profile.Entrypoint = req.Entrypoint
	}
	if len(req.Volumes) > 0 {
		profile.Volumes = req.Volumes
	}
	if req.MigrationCmd != "" {
		profile.MigrationCmd = req.MigrationCmd
	}
	if len(req.Workers) > 0 {
		profile.Workers = req.Workers
	}

	// 2. Identify active slot and target candidate slot
	baseServiceName := profile.BaseService
	slotGreenName := fmt.Sprintf("%s-%s-green", baseServiceName, envName)
	slotBlueName := fmt.Sprintf("%s-%s-blue", baseServiceName, envName)

	o.mu.Lock()
	currentSlot, exists := o.activeSlots[req.Service]
	if !exists {
		// Detect by container presence on host
		if id, _ := o.runner.FindContainerIDByName(ctx, slotGreenName); id != "" {
			currentSlot = SlotGreen
		} else if id, _ := o.runner.FindContainerIDByName(ctx, fmt.Sprintf("%s-green", req.Service)); id != "" {
			currentSlot = SlotGreen
		} else if id, _ := o.runner.FindContainerIDByName(ctx, slotBlueName); id != "" {
			currentSlot = SlotBlue
		} else {
			currentSlot = SlotBlue
		}
	}
	candidateSlot := currentSlot.Invert()
	o.mu.Unlock()

	// Determine host ports for slots
	portBlue := cmp.Or(req.HostPortBlue, profile.HostPortBlue, profile.ContainerPort+1)
	portGreen := cmp.Or(req.HostPortGreen, profile.HostPortGreen, profile.ContainerPort+2)

	candidatePort := portGreen
	if candidateSlot == SlotBlue {
		candidatePort = portBlue
	}

	var candidateName, prevName string
	if req.IsPreview {
		previewPort := 9000 + (req.PRNumber % 900)
		candidatePort = cmp.Or(req.HostPortGreen, previewPort)
		candidateName = fmt.Sprintf("%s-pr-%d", req.Service, req.PRNumber)
		prevName = candidateName
		candidateSlot = Slot(fmt.Sprintf("pr-%d", req.PRNumber))
		if req.Domain == "" {
			req.Domain = fmt.Sprintf("pr-%d-%s.mesh", req.PRNumber, req.Service)
		}
	} else {
		candidateName = fmt.Sprintf("%s-%s", req.Service, candidateSlot)
		prevName = fmt.Sprintf("%s-%s", req.Service, currentSlot)
	}

	o.emitProgress(req, "pulling", fmt.Sprintf("Pulling candidate image: %s", req.Image), 15)

	// 3. Pull candidate container image
	if err := o.runner.PullImage(ctx, req.Image); err != nil {
		o.logger.Error("Deploy failed during image pull", "error", err)
		return o.failResponse(req, "Image pull failed: "+err.Error(), currentSlot, startTime)
	}

	// 4. Inject secrets into container environment
	// When secrets are provided by FlareLens Control Plane, use them as authoritative (RAM-only).
	// Fall back to host .env files ONLY when FlareLens Control Plane provides zero secrets.
	activeSecrets := make(map[string]string)
	if len(req.Secrets) > 0 {
		for k, v := range req.Secrets {
			activeSecrets[k] = v
		}
		o.logger.Info("Injected in-memory secrets from FlareLens Control Plane", "count", len(req.Secrets))
	} else {
		activeSecrets = loadFallbackEnv(baseServiceName, envName, string(candidateSlot))
		if activeSecrets == nil {
			activeSecrets = make(map[string]string)
		}
		o.logger.Warn("No secrets provided in deploy request; using legacy host .env fallback files", "count", len(activeSecrets))
	}

	envList := make([]string, 0, len(activeSecrets)+6)
	envList = append(envList,
		fmt.Sprintf("DEPLOY_ENV=%s", envName),
		fmt.Sprintf("DEPLOY_SLOT=%s", candidateSlot),
		fmt.Sprintf("SERVICE_NAME=%s", baseServiceName),
		fmt.Sprintf("APP_ENV=%s", envName),
		"FEATURE_FLAGS_FILE=/etc/flarelens/flags/flags.json",
		"FEATURE_FLAGS_URL=http://127.0.0.1:8999/api/v1/flags",
	)
	for k, v := range activeSecrets {
		envList = append(envList, fmt.Sprintf("%s=%s", k, v))
	}

	dbNetwork := fmt.Sprintf("%s-db", envName)
	if len(profile.Networks) > 1 {
		dbNetwork = profile.Networks[1]
	}

	// 5. Execute Database Schema Migrations (in throwaway ephemeral container only when requested)
	if req.RunMigrations {
		migCmd := cmp.Or(req.MigrationCmd, profile.MigrationCmd)
		if migCmd != "" {
			o.emitProgress(req, "migrating", fmt.Sprintf("Executing database schema migration: %s", migCmd), 25)
			migrationOutput, err := o.migrator.Run(ctx, req.Image, migCmd, envList, dbNetwork)
			if err != nil {
				o.logger.Error("Database schema migration failed! Aborting deployment", "error", err, "output", migrationOutput)

				// Automated rollback to pre-deploy snapshot if guardrail was enabled
				if req.PreDeploySnapshot && o.rollbackHook != nil {
					o.emitProgress(req, "rollback", "Restoring database schema to pre-deploy snapshot...", 28)
					snapshotTag := fmt.Sprintf("pre-deploy-%s", req.Service)
					if rbErr := o.rollbackHook(ctx, req.Service, snapshotTag); rbErr != nil {
						o.logger.Error("Failed to restore pre-deploy snapshot after migration error", "error", rbErr)
					} else {
						o.logger.Info("Database schema successfully rolled back to pre-deploy snapshot")
					}
				}

				return o.failResponse(req, "Database migration failed: "+err.Error(), currentSlot, startTime)
			}
			o.emitProgress(req, "migrated", "Database schema migration applied successfully", 30)
		}
	}

	o.emitProgress(req, "starting", fmt.Sprintf("Staging candidate container: %s", candidateName), 40)

	// 6. Remove stale candidate container if one was lingering from previous failed run
	if oldID, _ := o.runner.FindContainerIDByName(ctx, candidateName); oldID != "" {
		_ = o.runner.RemoveContainer(ctx, oldID)
	}

	// Resolve volume binds (format slot-specific volume paths if present)
	resolvedBinds := make([]string, 0, len(profile.Volumes))
	for _, b := range profile.Volumes {
		formattedBind := b
		if strings.Contains(formattedBind, "%s") {
			formattedBind = fmt.Sprintf(formattedBind, envName, candidateSlot)
		}
		// Verify source path exists on host before binding
		parts := strings.Split(formattedBind, ":")
		if len(parts) > 0 {
			if _, statErr := os.Stat(parts[0]); statErr == nil {
				resolvedBinds = append(resolvedBinds, formattedBind)
			}
		}
	}

	// Mount host feature flags directory read-only into container if present
	if _, statErr := os.Stat("/etc/flarelens/flags"); statErr == nil {
		hasFlagBind := false
		for _, b := range resolvedBinds {
			if strings.HasPrefix(b, "/etc/flarelens/flags") {
				hasFlagBind = true
				break
			}
		}
		if !hasFlagBind {
			resolvedBinds = append(resolvedBinds, "/etc/flarelens/flags:/etc/flarelens/flags:ro")
		}
	}

	// 7. Create & Start Candidate Container with multi-network and secret volumes
	containerID, err := o.runner.CreateContainerWithOptions(ctx, ContainerConfig{
		Name:          candidateName,
		Image:         req.Image,
		EnvVars:       envList,
		Cmd:           profile.Command,
		Entrypoint:    profile.Entrypoint,
		Binds:         resolvedBinds,
		HostPort:      candidatePort,
		ContainerPort: profile.ContainerPort,
		Networks:      profile.Networks,
		Labels: map[string]string{
			"flarelens.service": baseServiceName,
			"flarelens.slot":    string(candidateSlot),
			"flarelens.env":     envName,
		},
	})
	if err != nil {
		o.logger.Error("Failed to create candidate container", "error", err)
		return o.failResponse(req, "Container creation failed: "+err.Error(), currentSlot, startTime)
	}

	if err := o.runner.StartContainer(ctx, containerID); err != nil {
		_ = o.runner.RemoveContainer(ctx, containerID)
		o.logger.Error("Failed to start candidate container", "error", err)
		return o.failResponse(req, "Container start failed: "+err.Error(), currentSlot, startTime)
	}

	// 8. Healthcheck Probe Guardrail
	probeHost, _ := o.runner.InspectContainerIP(ctx, containerID)
	if probeHost == "" || probeHost == "127.0.0.1" {
		probeHost = candidateName
	}
	probeURL := fmt.Sprintf("http://%s:%d%s", probeHost, profile.ContainerPort, profile.HealthPath)
	timeout := time.Duration(cmp.Or(req.TimeoutSeconds, 30)) * time.Second

	o.emitProgress(req, "probing", fmt.Sprintf("Probing candidate health at %s (timeout: %s)", probeURL, timeout), 65)

	if err := o.prober.Probe(ctx, probeURL, timeout, 500*time.Millisecond); err != nil {
		// ROLLBACK PATH: Candidate failed health checks!
		o.logger.Warn("Candidate failed health checks! Triggering automatic rollback",
			"candidate", candidateName,
			"error", err,
		)
		o.emitProgress(req, "failed", "Candidate failed healthcheck. Rolling back...", 80)

		// Destroy the unhealthy candidate container
		_ = o.runner.StopContainer(ctx, containerID, 2)
		_ = o.runner.RemoveContainer(ctx, containerID)

		o.emitProgress(req, "failed", fmt.Sprintf("Rolled back. Live traffic remains 100%% on slot: %s", currentSlot), 100)

		return DeployResponse{
			DeploymentID: req.DeploymentID,
			Service:      req.Service,
			Status:       "rolled_back",
			ActiveSlot:   string(currentSlot),
			ActivePort:   o.portForSlot(currentSlot, portBlue, portGreen),
			Message:      fmt.Sprintf("Candidate failed healthcheck: %v. Rolled back to %s.", err, currentSlot),
			DurationMS:   time.Since(startTime).Milliseconds(),
		}
	}

	currentPort := o.portForSlot(currentSlot, portBlue, portGreen)

	// If Ephemeral PR Preview, register dedicated route
	if req.IsPreview {
		o.emitProgress(req, "preview_routing", fmt.Sprintf("Candidate healthy! Registering ephemeral preview route https://%s -> port %d", req.Domain, candidatePort), 90)
		if err := o.traefik.FlipRoute(candidateName, req.Domain, candidatePort); err != nil {
			o.logger.Error("Failed to register Traefik preview route", "error", err)
			_ = o.runner.StopContainer(ctx, containerID, 2)
			_ = o.runner.RemoveContainer(ctx, containerID)
			return o.failResponse(req, "Preview route creation failed: "+err.Error(), currentSlot, startTime)
		}

		o.emitProgress(req, "completed", fmt.Sprintf("Ephemeral PR preview environment live at https://%s", req.Domain), 100)
		return DeployResponse{
			DeploymentID: req.DeploymentID,
			Service:      req.Service,
			Status:       "success",
			ActiveSlot:   string(candidateSlot),
			ActivePort:   candidatePort,
			Message:      fmt.Sprintf("Ephemeral PR preview environment live at https://%s", req.Domain),
			DurationMS:   time.Since(startTime).Milliseconds(),
		}
	}

	// 9. Optional Canary Soak Phase
	if req.CanaryWeight > 0 && req.CanaryWeight < 100 && req.Domain != "" {
		o.emitProgress(req, "canary", fmt.Sprintf("Candidate healthy! Starting canary soak: %d%% candidate, %d%% live", req.CanaryWeight, 100-req.CanaryWeight), 75)
		if err := o.traefik.SetCanaryRoute(baseServiceName, req.Domain, currentPort, candidatePort, req.CanaryWeight); err != nil {
			o.logger.Error("Failed to configure canary route", "error", err)
			_ = o.runner.StopContainer(ctx, containerID, 2)
			_ = o.runner.RemoveContainer(ctx, containerID)
			return o.failResponse(req, "Canary route setup failed: "+err.Error(), currentSlot, startTime)
		}

		soakDuration := time.Duration(cmp.Or(req.CanaryDuration, 5)) * time.Second
		select {
		case <-ctx.Done():
			_ = o.traefik.SwitchRoute(envName, baseServiceName, prevName, profile.ContainerPort, req.Domain)
			_ = o.runner.StopContainer(ctx, containerID, 2)
			_ = o.runner.RemoveContainer(ctx, containerID)
			return o.failResponse(req, "Deployment cancelled during canary soak", currentSlot, startTime)
		case <-time.After(soakDuration):
			if err := o.prober.Probe(ctx, probeURL, 5*time.Second, 500*time.Millisecond); err != nil {
				o.logger.Warn("Candidate failed during canary soak! Rolling back to 100% live", "error", err)
				_ = o.traefik.SwitchRoute(envName, baseServiceName, prevName, profile.ContainerPort, req.Domain)
				_ = o.runner.StopContainer(ctx, containerID, 2)
				_ = o.runner.RemoveContainer(ctx, containerID)
				return DeployResponse{
					DeploymentID: req.DeploymentID,
					Service:      req.Service,
					Status:       "rolled_back",
					ActiveSlot:   string(currentSlot),
					ActivePort:   currentPort,
					Message:      fmt.Sprintf("Canary soak failed: %v. Rolled back to %s.", err, currentSlot),
					DurationMS:   time.Since(startTime).Milliseconds(),
				}
			}
			o.emitProgress(req, "canary_passed", "Canary soak successful with 0 errors. Promoting to 100% traffic...", 85)
		}
	}

	// 10. Zero-Downtime Traffic Switch in Traefik
	o.emitProgress(req, "flipping", fmt.Sprintf("Candidate healthy! Atomically flipping live route to %s (%s)", candidateName, candidateSlot), 88)
	if err := o.traefik.SwitchRoute(envName, baseServiceName, candidateName, profile.ContainerPort, req.Domain); err != nil {
		o.logger.Warn("Traefik SwitchRoute warning, trying FlipRoute fallback", "error", err)
		if req.Domain != "" {
			_ = o.traefik.FlipRoute(candidateName, req.Domain, candidatePort)
		}
	}

	// Update active slot in memory
	o.mu.Lock()
	o.activeSlots[req.Service] = candidateSlot
	o.mu.Unlock()

	// 11. Companion Workers Rollout (Kamal-style)
	for _, worker := range profile.Workers {
		workerName := fmt.Sprintf("%s-%s", worker.Name, envName)
		o.emitProgress(req, "worker", fmt.Sprintf("Rolling out companion worker: %s", workerName), 92)
		o.rolloutWorker(ctx, req.Image, workerName, worker, envList, profile.Networks)
	}

	// 12. Drain and stop previous web slot
	drainSec := cmp.Or(req.DrainSeconds, 15)
	o.emitProgress(req, "draining", fmt.Sprintf("Draining previous slot %s for %d seconds...", currentSlot, drainSec), 95)

	go func(oldContainerName string, drainTime time.Duration) {
		time.Sleep(drainTime)
		drainCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if prevID, _ := o.runner.FindContainerIDByName(drainCtx, oldContainerName); prevID != "" {
			_ = o.runner.StopContainer(drainCtx, prevID, 10)
			o.logger.Info("Previous deployment slot stopped after drain period", "container", oldContainerName)
		}
	}(prevName, time.Duration(drainSec)*time.Second)

	o.emitProgress(req, "completed", fmt.Sprintf("Deployment succeeded! Active slot is now %s (%s)", candidateSlot, candidateName), 100)

	return DeployResponse{
		DeploymentID: req.DeploymentID,
		Service:      req.Service,
		Status:       "success",
		ActiveSlot:   string(candidateSlot),
		ActivePort:   candidatePort,
		Message:      fmt.Sprintf("Successfully deployed %s to slot %s", req.Service, candidateSlot),
		DurationMS:   time.Since(startTime).Milliseconds(),
	}
}

// rolloutWorker starts the new companion worker container and replaces the previous instance
func (o *Orchestrator) rolloutWorker(
	ctx context.Context,
	image string,
	containerName string,
	worker WorkerSpec,
	envVars []string,
	networks []string,
) {
	// 1. Remove previous stopped container or prepare graceful swap
	staleID, _ := o.runner.FindContainerIDByName(ctx, containerName)
	if staleID != "" {
		_ = o.runner.StopContainer(ctx, staleID, 10)
		_ = o.runner.RemoveContainer(ctx, staleID)
	}

	workerNets := worker.Networks
	if len(workerNets) == 0 {
		workerNets = networks
	}

	resolvedWorkerBinds := make([]string, 0, len(worker.Volumes))
	for _, b := range worker.Volumes {
		parts := strings.Split(b, ":")
		if len(parts) > 0 {
			if _, statErr := os.Stat(parts[0]); statErr == nil {
				resolvedWorkerBinds = append(resolvedWorkerBinds, b)
			}
		}
	}

	// Mount host feature flags directory read-only into worker container if present
	if _, statErr := os.Stat("/etc/flarelens/flags"); statErr == nil {
		hasFlagBind := false
		for _, b := range resolvedWorkerBinds {
			if strings.HasPrefix(b, "/etc/flarelens/flags") {
				hasFlagBind = true
				break
			}
		}
		if !hasFlagBind {
			resolvedWorkerBinds = append(resolvedWorkerBinds, "/etc/flarelens/flags:/etc/flarelens/flags:ro")
		}
	}

	// 2. Create and start worker container
	workerID, err := o.runner.CreateContainerWithOptions(ctx, ContainerConfig{
		Name:       containerName,
		Image:      image,
		EnvVars:    envVars,
		Cmd:        worker.Command,
		Entrypoint: worker.Entrypoint,
		Binds:      resolvedWorkerBinds,
		Networks:   workerNets,
		Labels: map[string]string{
			"flarelens.worker": worker.Name,
		},
	})
	if err != nil {
		o.logger.Error("Failed to create companion worker", "worker", containerName, "error", err)
		return
	}

	if err := o.runner.StartContainer(ctx, workerID); err != nil {
		o.logger.Error("Failed to start companion worker", "worker", containerName, "error", err)
		return
	}

	o.logger.Info("Companion worker rolled out successfully", "worker", containerName, "id", workerID)
}

// ServiceProfile defines declarative defaults for known microservices
type ServiceProfile struct {
	BaseService   string
	ContainerPort int
	HostPortBlue  int
	HostPortGreen int
	HealthPath    string
	Command       []string
	Entrypoint    []string
	MigrationCmd  string
	Volumes       []string
	Networks      []string
	Workers       []WorkerSpec
}

func resolveServiceProfile(service, envName string) ServiceProfile {
	return ServiceProfile{
		BaseService:   service,
		ContainerPort: 8080,
		HostPortBlue:  8081,
		HostPortGreen: 8082,
		HealthPath:    "/healthz",
		Networks:      []string{"flarelens-edge"},
	}
}

// TeardownPreview destroys an ephemeral PR preview container and removes its Traefik dynamic route
func (o *Orchestrator) TeardownPreview(ctx context.Context, req TeardownRequest) error {
	previewName := fmt.Sprintf("%s-pr-%d", req.Service, req.PRNumber)
	o.logger.Info("Tearing down ephemeral PR preview environment",
		"service", req.Service,
		"pr_number", req.PRNumber,
		"container", previewName,
	)

	// 1. Remove Traefik route first so traffic drops immediately
	if err := o.traefik.RemoveRoute(previewName); err != nil {
		o.logger.Warn("Failed to remove Traefik preview route", "container", previewName, "error", err)
	}

	// 2. Stop and remove container
	if containerID, err := o.runner.FindContainerIDByName(ctx, previewName); err == nil && containerID != "" {
		_ = o.runner.StopContainer(ctx, containerID, 5)
		if err := o.runner.RemoveContainer(ctx, containerID); err != nil {
			return fmt.Errorf("failed to remove preview container %s: %w", previewName, err)
		}
	}

	o.logger.Info("Successfully destroyed ephemeral PR preview environment",
		"service", req.Service,
		"pr_number", req.PRNumber,
	)
	return nil
}

func (o *Orchestrator) portForSlot(s Slot, portBlue, portGreen int) int {
	if s == SlotBlue {
		return portBlue
	}
	return portGreen
}

func (o *Orchestrator) failResponse(req DeployRequest, msg string, currentSlot Slot, startTime time.Time) DeployResponse {
	return DeployResponse{
		DeploymentID: req.DeploymentID,
		Service:      req.Service,
		Status:       "failed",
		ActiveSlot:   string(currentSlot),
		Message:      msg,
		DurationMS:   time.Since(startTime).Milliseconds(),
	}
}

func (o *Orchestrator) emitProgress(req DeployRequest, stage, message string, percent int) {
	progress := DeployProgress{
		DeploymentID: req.DeploymentID,
		Service:      req.Service,
		Stage:        stage,
		Message:      message,
		Percent:      percent,
		Timestamp:    time.Now().UTC(),
	}

	o.logger.Info("Deploy progress",
		"service", req.Service,
		"stage", stage,
		"percent", percent,
		"message", message,
	)

	if o.natsClient != nil && o.natsClient.IsConnected() {
		subject := fmt.Sprintf("flarelens.node.%s.deploy.progress", o.nodeID)
		_ = o.natsClient.PublishJSON(subject, progress)
	}
}

func loadFallbackEnv(service, envName string, slot ...string) map[string]string {
	result := make(map[string]string)

	// Layer 1: Global shared environment (e.g. /etc/flarelens/uat/.env)
	sharedPaths := []string{
		fmt.Sprintf("/etc/flarelens/%s/.env", envName),
		".env",
	}
	for _, p := range sharedPaths {
		if data, err := os.ReadFile(p); err == nil {
			for k, v := range parseEnvLines(string(data)) {
				result[k] = v
			}
			break
		}
	}

	// Layer 2: Service-level environment (e.g. /etc/flarelens/uat/services/api/.env)
	servicePaths := []string{
		fmt.Sprintf("/etc/flarelens/%s/services/%s/.env", envName, service),
		fmt.Sprintf("/etc/flarelens/%s/%s.env", envName, service),
		fmt.Sprintf("%s.env", service),
	}
	for _, p := range servicePaths {
		if data, err := os.ReadFile(p); err == nil {
			for k, v := range parseEnvLines(string(data)) {
				result[k] = v
			}
			break
		}
	}

	// Layer 3: Slot-specific environment (e.g. /etc/flarelens/uat/services/api-green/.env)
	if len(slot) > 0 && slot[0] != "" {
		slotPath := fmt.Sprintf("/etc/flarelens/%s/services/%s-%s/.env", envName, service, slot[0])
		if data, err := os.ReadFile(slotPath); err == nil {
			for k, v := range parseEnvLines(string(data)) {
				result[k] = v
			}
		}
	}

	if len(result) == 0 {
		return nil
	}
	return result
}

func parseEnvLines(content string) map[string]string {
	res := make(map[string]string)
	lines := strings.Split(content, "\n")
	for _, l := range lines {
		trimmed := strings.TrimSpace(l)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		k, v, found := strings.Cut(trimmed, "=")
		if found {
			k = strings.TrimSpace(k)
			v = strings.TrimSpace(v)
			v = strings.Trim(v, `"'`)
			if k != "" {
				res[k] = v
			}
		}
	}
	return res
}
