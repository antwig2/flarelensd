package deploy

import (
	"cmp"
	"context"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/antwig2/flarelens/internal/transport"
)

type targetDBContextKey struct{}

// WithTargetDB attaches an optional target database name hint to ctx for pre-deploy snapshot/rollback hooks.
func WithTargetDB(ctx context.Context, targetDB string) context.Context {
	if strings.TrimSpace(targetDB) == "" {
		return ctx
	}
	return context.WithValue(ctx, targetDBContextKey{}, strings.TrimSpace(targetDB))
}

// TargetDBFromContext retrieves an optional target database name hint from ctx.
func TargetDBFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(targetDBContextKey{}).(string); ok {
		return v
	}
	return ""
}

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
	activeOps   atomic.Int32
}

// BeginOp increments the active orchestration operation counter (used by OTA drain lock).
func (o *Orchestrator) BeginOp() {
	o.activeOps.Add(1)
}

// EndOp decrements the active orchestration operation counter.
func (o *Orchestrator) EndOp() {
	o.activeOps.Add(-1)
}

// ActiveOps returns the number of currently executing Deploy or ReconcileSingleton operations.
func (o *Orchestrator) ActiveOps() int32 {
	return o.activeOps.Load()
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
	o.BeginOp()
	defer o.EndOp()
	startTime := time.Now()

	// Guarantee pre-deploy snapshot whenever database migrations are requested
	if req.RunMigrations {
		req.PreDeploySnapshot = true
	}

	targetDB := cmp.Or(
		strings.TrimSpace(req.TargetDB),
		envValueByKeyOrSuffix(req.Secrets, "DB_NAME"),
		envValueByKeyOrSuffix(req.Secrets, "POSTGRES_DB"),
	)
	hookCtx := WithTargetDB(ctx, targetDB)

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
		if err := o.preDeployHook(hookCtx, req.Service, snapshotTag); err != nil {
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
	} else if req.Network != "" {
		profile.Networks = []string{req.Network}
	}
	profile.Aliases = ResolveServiceNetworkAliases(req.Service, envName, req.Aliases)
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

	// 2. Identify active slot, legacy containers, and target candidate slot
	baseServiceName := profile.BaseService
	slotGreenName := fmt.Sprintf("%s-%s-green", baseServiceName, envName)
	slotBlueName := fmt.Sprintf("%s-%s-blue", baseServiceName, envName)

	portBlue := cmp.Or(req.HostPortBlue, profile.HostPortBlue, profile.ContainerPort+1)
	portGreen := cmp.Or(req.HostPortGreen, profile.HostPortGreen, profile.ContainerPort+2)

	allContainers, _ := o.runner.ListAllContainers(ctx)
	matchedSlots := identifyServiceSlotContainers(
		allContainers,
		req.Service,
		baseServiceName,
		envName,
		profile.Aliases,
		profile.Networks,
		profile.Workers,
	)

	o.mu.Lock()
	knownSlot, hasKnown := o.activeSlots[req.Service]
	currentSlot := detectActiveServiceSlot(
		matchedSlots,
		allContainers,
		knownSlot,
		hasKnown,
		portBlue,
		portGreen,
	)
	if len(matchedSlots) == 0 && !hasKnown {
		// Backwards-compatible direct name lookup when container listing is unavailable (e.g. unit test mocks)
		if id, _ := o.runner.FindContainerIDByName(ctx, slotGreenName); id != "" {
			currentSlot = SlotGreen
		} else if id, _ := o.runner.FindContainerIDByName(ctx, fmt.Sprintf("%s-green", req.Service)); id != "" {
			currentSlot = SlotGreen
		} else if id, _ := o.runner.FindContainerIDByName(ctx, slotBlueName); id != "" {
			currentSlot = SlotBlue
		}
	}
	candidateSlot := currentSlot.Invert()

	// Defensive host-port collision avoidance when an unrelated container occupies candidateSlot's port
	if !req.IsPreview {
		candPort := o.portForSlot(candidateSlot, portBlue, portGreen)
		oppPort := o.portForSlot(currentSlot, portBlue, portGreen)
		if isHostPortBoundByUnrelatedRunning(allContainers, matchedSlots, candPort) &&
			!isHostPortBound(allContainers, oppPort) &&
			!hasRunningSlotContainerOnPort(matchedSlots, currentSlot, oppPort) {
			o.logger.Warn("Candidate host port occupied by unrelated container; switching candidate to free opposite slot",
				"occupied_port", candPort,
				"free_port", oppPort,
				"new_candidate_slot", currentSlot,
			)
			candidateSlot = currentSlot
			currentSlot = candidateSlot.Invert()
		}
	}
	o.mu.Unlock()

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
	secretFiles := make(map[string]string)
	if len(req.Secrets) > 0 {
		for k, v := range req.Secrets {
			if after, ok := strings.CutPrefix(k, "__FLARELENS_FILE__"); ok {
				if cleanPath := strings.TrimSpace(after); cleanPath != "" && v != "" {
					secretFiles[cleanPath] = v
				}
				continue
			}
			activeSecrets[k] = v
		}
		o.logger.Info("Injected in-memory secrets from FlareLens Control Plane",
			"count", len(activeSecrets),
			"secret_files", len(secretFiles),
		)
	} else {
		activeSecrets = loadFallbackEnv(baseServiceName, envName, string(candidateSlot))
		if activeSecrets == nil {
			activeSecrets = make(map[string]string)
		}
		o.logger.Warn("No secrets provided in deploy request; using legacy host .env fallback files", "count", len(activeSecrets))
	}

	envList := make([]string, 0, len(activeSecrets)+8)
	envList = append(envList,
		fmt.Sprintf("DEPLOY_ENV=%s", envName),
		fmt.Sprintf("DEPLOY_SLOT=%s", candidateSlot),
		fmt.Sprintf("SERVICE_NAME=%s", baseServiceName),
	)
	if !hasEnvKeyOrSuffix(activeSecrets, "APP_ENV") {
		envList = append(envList, fmt.Sprintf("APP_ENV=%s", envName))
	}
	if !hasEnvKeyOrSuffix(activeSecrets, "SERVER_HOST") {
		envList = append(envList, "SERVER_HOST=0.0.0.0")
	}
	if profile.ContainerPort > 0 && !hasEnvKeyOrSuffix(activeSecrets, "SERVER_PORT") {
		envList = append(envList, fmt.Sprintf("SERVER_PORT=%d", profile.ContainerPort))
	}
	if !hasEnvKeyOrSuffix(activeSecrets, "FEATURE_FLAGS_FILE") {
		envList = append(envList, "FEATURE_FLAGS_FILE=/etc/flarelens/flags/flags.json")
	}
	if !hasEnvKeyOrSuffix(activeSecrets, "FEATURE_FLAGS_URL") {
		envList = append(envList, "FEATURE_FLAGS_URL=http://host.docker.internal:8999/api/v1/flags")
	}
	for k, v := range activeSecrets {
		envList = append(envList, fmt.Sprintf("%s=%s", k, v))
	}

	// Resolve volume binds (format slot-specific volume paths if present, plus RAM tmpfs secret files when needed)
	resolvedBinds := resolveVolumeBinds(profile.Volumes, envName, string(candidateSlot), baseServiceName, secretFiles)

	if targetDB == "" {
		targetDB = cmp.Or(
			envValueByKeyOrSuffix(activeSecrets, "DB_NAME"),
			envValueByKeyOrSuffix(activeSecrets, "POSTGRES_DB"),
		)
		hookCtx = WithTargetDB(ctx, targetDB)
	}

	dbNetwork := ResolveMigrationNetwork(envName, profile.Networks)

	// 5. Execute Database Schema Migrations (in throwaway ephemeral container only when requested)
	if req.RunMigrations {
		migCmd := cmp.Or(req.MigrationCmd, profile.MigrationCmd)
		if migCmd != "" {
			_ = o.runner.EnsureNetwork(ctx, dbNetwork)
			o.emitProgress(req, "migrating", fmt.Sprintf("Executing database schema migration: %s", migCmd), 25)
			migrationOutput, err := o.migrator.Run(ctx, req.Image, migCmd, envList, dbNetwork, resolvedBinds...)
			if err != nil {
				o.logger.Error("Database schema migration failed! Aborting deployment", "error", err, "output", migrationOutput)

				// Automated rollback to pre-deploy snapshot if guardrail was enabled
				if req.PreDeploySnapshot && o.rollbackHook != nil {
					o.emitProgress(req, "rollback", "Restoring database schema to pre-deploy snapshot...", 28)
					snapshotTag := fmt.Sprintf("pre-deploy-%s", req.Service)
					if rbErr := o.rollbackHook(hookCtx, req.Service, snapshotTag); rbErr != nil {
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

	// 6. Remove stale candidate container or inactive legacy slot containers occupying candidateSlot / candidatePort
	if oldID, _ := o.runner.FindContainerIDByName(ctx, candidateName); oldID != "" {
		_ = o.runner.StopContainer(ctx, oldID, 5)
		_ = o.runner.RemoveContainer(ctx, oldID)
	}
	if !req.IsPreview {
		for _, m := range matchedSlots {
			if m.slot == candidateSlot {
				o.logger.Info("Evicting inactive slot container before candidate staging",
					"container", m.primaryName,
					"slot", m.slot,
				)
				_ = o.runner.StopContainer(ctx, m.container.ID, 5)
				_ = o.runner.RemoveContainer(ctx, m.container.ID)
			}
		}
		for _, c := range allContainers {
			if !strings.EqualFold(c.State, "running") && containerHasHostPort(c, candidatePort) {
				_ = o.runner.RemoveContainer(ctx, c.ID)
			}
		}
	}

	candidateLabels := map[string]string{
		"flarelens.service": baseServiceName,
		"flarelens.slot":    string(candidateSlot),
		"flarelens.env":     envName,
	}
	if !req.IsPreview && len(profile.Aliases) > 0 {
		candidateLabels["flarelens.aliases"] = strings.Join(profile.Aliases, ",")
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
		Labels:        candidateLabels,
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
	probePort := profile.ContainerPort
	if probeHost == "" || probeHost == "127.0.0.1" {
		if candidatePort > 0 {
			probeHost = "127.0.0.1"
			probePort = candidatePort
		} else {
			probeHost = candidateName
		}
	}
	probeURL := fmt.Sprintf("http://%s:%d%s", probeHost, probePort, profile.HealthPath)
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
			_ = o.traefik.SwitchRoute(envName, baseServiceName, prevName, profile.ContainerPort, req.Domain, profile.Aliases...)
			_ = o.runner.StopContainer(ctx, containerID, 2)
			_ = o.runner.RemoveContainer(ctx, containerID)
			return o.failResponse(req, "Deployment cancelled during canary soak", currentSlot, startTime)
		case <-time.After(soakDuration):
			if err := o.prober.Probe(ctx, probeURL, 5*time.Second, 500*time.Millisecond); err != nil {
				o.logger.Warn("Candidate failed during canary soak! Rolling back to 100% live", "error", err)
				_ = o.traefik.SwitchRoute(envName, baseServiceName, prevName, profile.ContainerPort, req.Domain, profile.Aliases...)
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

	// 10. Promote stable Docker DNS aliases onto healthy candidate before flipping live traffic
	if len(profile.Aliases) > 0 {
		if err := o.runner.PromoteNetworkAliases(ctx, containerID, profile.Networks, profile.Aliases); err != nil {
			o.logger.Warn("Failed to promote Docker network aliases onto active candidate",
				"container", candidateName,
				"aliases", profile.Aliases,
				"error", err,
			)
		} else {
			o.logger.Info("Promoted stable Docker network aliases onto active candidate",
				"container", candidateName,
				"aliases", profile.Aliases,
			)
		}
	}

	// Zero-Downtime Traffic Switch in Traefik
	o.emitProgress(req, "flipping", fmt.Sprintf("Candidate healthy! Atomically flipping live route to %s (%s)", candidateName, candidateSlot), 88)
	if err := o.traefik.SwitchRoute(envName, baseServiceName, candidateName, profile.ContainerPort, req.Domain, profile.Aliases...); err != nil {
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
		o.rolloutWorker(ctx, req.Image, workerName, worker, envList, profile.Networks, baseServiceName, envName, secretFiles)
	}

	// 12. Drain, stop, and remove previous web slot(s) (both canonical and legacy pre-GitOps slots)
	drainSec := cmp.Or(req.DrainSeconds, 15)
	o.emitProgress(req, "draining", fmt.Sprintf("Draining previous slot %s for %d seconds...", currentSlot, drainSec), 95)

	retiredNames := []string{prevName}
	for _, m := range matchedSlots {
		if m.container.ID != containerID && m.primaryName != "" && m.primaryName != candidateName {
			if !slices.Contains(retiredNames, m.primaryName) {
				retiredNames = append(retiredNames, m.primaryName)
			}
		}
	}

	go func(oldContainers []string, activeCandidateID string, drainTime time.Duration) {
		time.Sleep(drainTime)
		drainCtx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()

		for _, oldName := range oldContainers {
			if oldName == "" || oldName == candidateName {
				continue
			}
			prevID, _ := o.runner.FindContainerIDByName(drainCtx, oldName)
			if prevID == "" || prevID == activeCandidateID {
				continue
			}
			_ = o.runner.StopContainer(drainCtx, prevID, 10)
			_ = o.runner.RemoveContainer(drainCtx, prevID)
			o.logger.Info("Previous deployment slot stopped and retired after drain period", "container", oldName)
		}
	}(retiredNames, containerID, time.Duration(drainSec)*time.Second)

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

// rolloutWorker starts the new companion worker container and replaces any previous canonical or legacy instance
func (o *Orchestrator) rolloutWorker(
	ctx context.Context,
	image string,
	containerName string,
	worker WorkerSpec,
	envVars []string,
	networks []string,
	baseServiceName string,
	envName string,
	secretFiles map[string]string,
) {
	workerNets := worker.Networks
	if len(workerNets) == 0 {
		workerNets = networks
	}

	// 1. Remove previous canonical worker container and any legacy pre-GitOps worker matching this role/env
	staleID, _ := o.runner.FindContainerIDByName(ctx, containerName)
	if staleID != "" {
		_ = o.runner.StopContainer(ctx, staleID, 10)
		_ = o.runner.RemoveContainer(ctx, staleID)
	}
	if allContainers, err := o.runner.ListAllContainers(ctx); err == nil {
		for _, c := range allContainers {
			if c.ID == staleID {
				continue
			}
			if isLegacyCompanionWorkerContainer(c, worker.Name, envName, workerNets) {
				o.logger.Info("Stopping and retiring legacy companion worker before starting replacement",
					"legacy_worker", firstNonEmpty(c.Names),
					"replacement", containerName,
				)
				_ = o.runner.StopContainer(ctx, c.ID, 10)
				_ = o.runner.RemoveContainer(ctx, c.ID)
			}
		}
	}

	resolvedWorkerBinds := resolveVolumeBinds(worker.Volumes, envName, "worker", baseServiceName, secretFiles)

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
			"flarelens.env":    envName,
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
	Aliases       []string
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
		Aliases:       ResolveServiceNetworkAliases(service, envName, nil),
	}
}

func normalizeEnvShort(envName string) string {
	e := strings.ToLower(strings.TrimSpace(envName))
	switch e {
	case "":
		return "uat"
	case "production":
		return "prod"
	default:
		return e
	}
}

func canonicalServiceName(service string) string {
	s := strings.ToLower(strings.TrimSpace(service))
	for _, suffix := range []string{"-production", "-prod", "-uat", "-staging"} {
		if strings.HasSuffix(s, suffix) && len(s) > len(suffix) {
			s = strings.TrimSuffix(s, suffix)
			break
		}
	}
	return s
}

// ResolveServiceNetworkAliases computes canonical Docker DNS aliases plus any manifest-defined aliases for a service.
func ResolveServiceNetworkAliases(service, envName string, explicit []string) []string {
	envShort := normalizeEnvShort(envName)
	clean := canonicalServiceName(service)
	if clean == "" {
		return dedupeNonEmptyStrings(explicit)
	}

	aliases := []string{
		clean,
		fmt.Sprintf("%s-%s", clean, envShort),
	}

	// Dragonfly is a drop-in Redis protocol engine; expose standard redis DNS aliases automatically.
	if clean == "dragonfly" {
		aliases = append(aliases, "redis", fmt.Sprintf("redis-%s", envShort))
	}

	aliases = append(aliases, explicit...)
	return dedupeNonEmptyStrings(aliases)
}

// ResolveMigrationNetwork selects the internal database-reachable Docker network rather than edge-only networks.
func ResolveMigrationNetwork(envName string, networks []string) string {
	envShort := normalizeEnvShort(envName)
	preferred := []string{
		envShort,
		fmt.Sprintf("%s-db", envShort),
	}
	for _, want := range preferred {
		if slices.Contains(networks, want) {
			return want
		}
	}
	// Prefer networks scoped to the target environment (e.g. "<stack>-uat", "<stack>-prod")
	for _, netName := range networks {
		trimmed := strings.TrimSpace(netName)
		lower := strings.ToLower(trimmed)
		if trimmed != "" && !strings.HasSuffix(lower, "-edge") &&
			(strings.HasSuffix(lower, "-"+envShort) || strings.HasSuffix(lower, "_"+envShort)) {
			return trimmed
		}
	}
	for _, netName := range networks {
		trimmed := strings.TrimSpace(netName)
		if trimmed != "" && !strings.HasSuffix(strings.ToLower(trimmed), "-edge") {
			return trimmed
		}
	}
	for _, netName := range networks {
		if trimmed := strings.TrimSpace(netName); trimmed != "" {
			return trimmed
		}
	}
	return "flarelens-edge"
}

func hasEnvKeyOrSuffix(envMap map[string]string, suffix string) bool {
	return envValueByKeyOrSuffix(envMap, suffix) != ""
}

func envValueByKeyOrSuffix(envMap map[string]string, suffix string) string {
	if len(envMap) == 0 || suffix == "" {
		return ""
	}
	wantUpper := strings.ToUpper(suffix)
	if v, ok := envMap[wantUpper]; ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	keys := slices.Sorted(maps.Keys(envMap))
	for _, k := range keys {
		upper := strings.ToUpper(strings.TrimSpace(k))
		if upper == wantUpper || strings.HasSuffix(upper, "_"+wantUpper) {
			if val := strings.TrimSpace(envMap[k]); val != "" {
				return val
			}
		}
	}
	return ""
}

// ReconcileActiveAliases inspects running containers on agent startup and ensures active slots and stateful services
// expose their stable Docker DNS aliases without requiring a full redeploy.
func (o *Orchestrator) ReconcileActiveAliases(ctx context.Context) {
	containers, err := o.runner.ListRunningContainers(ctx)
	if err != nil || len(containers) == 0 {
		return
	}

	type slotCandidate struct {
		containerID     string
		name            string
		service         string
		envName         string
		slot            Slot
		networks        []string
		explicitAliases []string
		hasAlias        bool
	}

	byService := make(map[string][]slotCandidate)

	for _, c := range containers {
		if c.Labels["flarelens.worker"] != "" {
			continue
		}
		primaryName := ""
		if len(c.Names) > 0 {
			primaryName = c.Names[0]
		}
		lowerName := strings.ToLower(primaryName)
		if strings.Contains(lowerName, "-pr-") ||
			strings.Contains(lowerName, "worker") ||
			strings.Contains(lowerName, "drainer") ||
			strings.Contains(lowerName, "benthos") ||
			strings.Contains(lowerName, "traefik") ||
			strings.Contains(lowerName, "cloudflared") {
			continue
		}

		targetNets := make([]string, 0, len(c.Networks))
		for netName := range maps.Keys(c.Networks) {
			if netName == "" || netName == "bridge" || netName == "host" || netName == "none" {
				continue
			}
			targetNets = append(targetNets, netName)
		}
		slices.Sort(targetNets)
		if len(targetNets) == 0 {
			continue
		}

		envName := strings.ToLower(strings.TrimSpace(c.Labels["flarelens.env"]))
		if envName == "" {
			for _, netName := range targetNets {
				lowerNet := strings.ToLower(netName)
				switch {
				case lowerNet == "prod" || lowerNet == "production" || strings.HasSuffix(lowerNet, "-prod") || strings.HasSuffix(lowerNet, "-production"):
					envName = "prod"
				case lowerNet == "staging" || strings.HasSuffix(lowerNet, "-staging"):
					envName = "staging"
				case lowerNet == "uat" || strings.HasSuffix(lowerNet, "-uat"):
					envName = "uat"
				}
				if envName != "" {
					break
				}
			}
		}
		if envName == "" {
			if strings.Contains(lowerName, "-prod-") || strings.HasSuffix(lowerName, "-prod") {
				envName = "prod"
			} else {
				envName = "uat"
			}
		}

		var labelAliases []string
		if rawAliases := strings.TrimSpace(c.Labels["flarelens.aliases"]); rawAliases != "" {
			labelAliases = dedupeNonEmptyStrings(strings.Split(rawAliases, ","))
		}

		if c.Labels["flarelens.mode"] == "singleton" {
			svc := cmp.Or(strings.TrimSpace(c.Labels["flarelens.service"]), primaryName)
			aliases := ResolveServiceNetworkAliases(svc, envName, labelAliases)
			if err := o.runner.PromoteNetworkAliases(ctx, c.ID, targetNets, aliases); err != nil {
				o.logger.Warn("Startup alias reconciliation warning for singleton container",
					"container", primaryName,
					"error", err,
				)
			}
			continue
		}

		// Reconcile stateful foundation services (postgres, dragonfly/redis)
		statefulService := ""
		switch {
		case strings.Contains(lowerName, "postgres"):
			statefulService = "postgres"
		case strings.Contains(lowerName, "dragonfly") || strings.Contains(lowerName, "redis"):
			statefulService = "dragonfly"
		}
		if statefulService != "" {
			extra := slices.Clone(labelAliases)
			if primaryName != "" {
				extra = append(extra, primaryName)
			}
			aliases := ResolveServiceNetworkAliases(statefulService, envName, extra)
			if err := o.runner.PromoteNetworkAliases(ctx, c.ID, targetNets, aliases); err != nil {
				o.logger.Warn("Startup alias reconciliation warning for stateful container",
					"container", primaryName,
					"error", err,
				)
			}
			continue
		}

		service := strings.TrimSpace(c.Labels["flarelens.service"])
		slotStr := strings.ToLower(strings.TrimSpace(c.Labels["flarelens.slot"]))
		if strings.HasPrefix(slotStr, "pr-") {
			continue
		}
		if slotStr != string(SlotBlue) && slotStr != string(SlotGreen) {
			switch {
			case strings.HasSuffix(lowerName, "-blue"):
				slotStr = string(SlotBlue)
				if service == "" {
					service = strings.TrimSuffix(primaryName, "-blue")
				}
			case strings.HasSuffix(lowerName, "-green"):
				slotStr = string(SlotGreen)
				if service == "" {
					service = strings.TrimSuffix(primaryName, "-green")
				}
			default:
				continue
			}
		}
		if service == "" {
			continue
		}

		canon := canonicalServiceName(service)
		alreadyAliased := false
		for _, aliases := range c.Networks {
			if slices.Contains(aliases, canon) {
				alreadyAliased = true
				break
			}
		}

		byService[service] = append(byService[service], slotCandidate{
			containerID:     c.ID,
			name:            primaryName,
			service:         service,
			envName:         envName,
			slot:            Slot(slotStr),
			networks:        targetNets,
			explicitAliases: labelAliases,
			hasAlias:        alreadyAliased,
		})
	}

	for service, candidates := range byService {
		chosen := candidates[0]
		if len(candidates) > 1 {
			o.mu.RLock()
			knownSlot, hasKnown := o.activeSlots[service]
			o.mu.RUnlock()

			selected := false
			if hasKnown {
				for _, cand := range candidates {
					if cand.slot == knownSlot {
						chosen = cand
						selected = true
						break
					}
				}
			}
			if !selected {
				for _, cand := range candidates {
					if cand.hasAlias {
						chosen = cand
						selected = true
						break
					}
				}
			}
			if !selected {
				for _, cand := range candidates {
					if cand.slot == SlotGreen {
						chosen = cand
						break
					}
				}
			}
		}

		aliases := ResolveServiceNetworkAliases(chosen.service, chosen.envName, chosen.explicitAliases)
		if err := o.runner.PromoteNetworkAliases(ctx, chosen.containerID, chosen.networks, aliases); err != nil {
			o.logger.Warn("Startup alias reconciliation warning",
				"service", chosen.service,
				"container", chosen.name,
				"error", err,
			)
			continue
		}

		o.mu.Lock()
		if _, exists := o.activeSlots[service]; !exists {
			o.activeSlots[service] = chosen.slot
		}
		o.mu.Unlock()
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

type matchedSlotContainer struct {
	container   RunningContainerSummary
	primaryName string
	slot        Slot
	isManaged   bool
	isRunning   bool
}

func firstNonEmpty(items []string) string {
	for _, s := range items {
		if trimmed := strings.TrimSpace(s); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func containerHasHostPort(c RunningContainerSummary, hostPort int) bool {
	if hostPort <= 0 {
		return false
	}
	for _, p := range c.Ports {
		if p.PublicPort == hostPort {
			return true
		}
	}
	return false
}

func isHostPortBound(containers []RunningContainerSummary, hostPort int) bool {
	if hostPort <= 0 {
		return false
	}
	for _, c := range containers {
		if strings.EqualFold(c.State, "running") && containerHasHostPort(c, hostPort) {
			return true
		}
	}
	return false
}

func isHostPortBoundByUnrelatedRunning(
	containers []RunningContainerSummary,
	matched []matchedSlotContainer,
	hostPort int,
) bool {
	if hostPort <= 0 {
		return false
	}
	for _, c := range containers {
		if !strings.EqualFold(c.State, "running") || !containerHasHostPort(c, hostPort) {
			continue
		}
		isMatched := false
		for _, m := range matched {
			if m.container.ID == c.ID {
				isMatched = true
				break
			}
		}
		if !isMatched {
			return true
		}
	}
	return false
}

func hasRunningSlotContainerOnPort(matched []matchedSlotContainer, slot Slot, hostPort int) bool {
	for _, m := range matched {
		if m.isRunning && m.slot == slot && containerHasHostPort(m.container, hostPort) {
			return true
		}
	}
	return false
}

func identifyServiceSlotContainers(
	containers []RunningContainerSummary,
	serviceName string,
	baseServiceName string,
	envName string,
	aliases []string,
	targetNetworks []string,
	workers []WorkerSpec,
) []matchedSlotContainer {
	normEnv := normalizeEnvShort(envName)
	prefixes := dedupeNonEmptyStrings(append(
		[]string{
			serviceName,
			baseServiceName,
			fmt.Sprintf("%s-%s", baseServiceName, normEnv),
		},
		aliases...,
	))

	out := make([]matchedSlotContainer, 0)
	for _, c := range containers {
		primaryName := firstNonEmpty(c.Names)
		lowerPrimary := strings.ToLower(primaryName)
		if lowerPrimary == "" {
			continue
		}

		// Skip preview containers, companion workers, and shared stateful/infra singletons
		if strings.HasPrefix(strings.ToLower(c.Labels["flarelens.slot"]), "pr-") || strings.Contains(lowerPrimary, "-pr-") {
			continue
		}
		if c.Labels["flarelens.worker"] != "" || c.Labels["flarelens.role"] == "singleton" {
			continue
		}
		isWorker := false
		for _, w := range workers {
			wn := strings.ToLower(strings.TrimSpace(w.Name))
			if wn != "" && (lowerPrimary == wn ||
				lowerPrimary == fmt.Sprintf("%s-%s", wn, normEnv) ||
				lowerPrimary == fmt.Sprintf("%s-%s", normEnv, wn) ||
				strings.HasSuffix(lowerPrimary, "-"+wn)) {
				isWorker = true
				break
			}
		}
		if isWorker {
			continue
		}
		if strings.Contains(lowerPrimary, "postgres") ||
			strings.Contains(lowerPrimary, "dragonfly") ||
			strings.Contains(lowerPrimary, "redis") ||
			strings.Contains(lowerPrimary, "traefik") ||
			strings.Contains(lowerPrimary, "vector") ||
			strings.Contains(lowerPrimary, "cloudflared") {
			continue
		}

		if labelEnv := strings.TrimSpace(c.Labels["flarelens.env"]); labelEnv != "" &&
			normalizeEnvShort(labelEnv) != normEnv {
			continue
		}

		isRunning := strings.EqualFold(c.State, "running")

		// 1. Explicit FlareLens-managed slot label match
		if strings.EqualFold(strings.TrimSpace(c.Labels["flarelens.service"]), baseServiceName) {
			slotVal := Slot(strings.ToLower(strings.TrimSpace(c.Labels["flarelens.slot"])))
			if slotVal == SlotBlue || slotVal == SlotGreen {
				out = append(out, matchedSlotContainer{
					container:   c,
					primaryName: primaryName,
					slot:        slotVal,
					isManaged:   true,
					isRunning:   isRunning,
				})
				continue
			}
		}

		// 2. Canonical or alias-prefixed slot container match (e.g. <alias>-green, <alias>-blue, or unslotted <alias>)
		var matchedSlot Slot
		matched := false
		for _, n := range c.Names {
			ln := strings.ToLower(strings.TrimSpace(n))
			for _, p := range prefixes {
				lp := strings.ToLower(strings.TrimSpace(p))
				if lp == "" {
					continue
				}
				switch {
				case ln == lp+"-green":
					matchedSlot = SlotGreen
					matched = true
				case ln == lp+"-blue":
					matchedSlot = SlotBlue
					matched = true
				case ln == lp && sharesTargetNetwork(c.Networks, targetNetworks):
					matchedSlot = SlotGreen
					matched = true
				}
				if matched {
					break
				}
			}
			if matched {
				break
			}
		}
		if !matched {
			continue
		}

		// Guard cross-environment matches on non-labeled containers using network overlap when available
		if len(targetNetworks) > 0 && len(c.Networks) > 0 && !sharesTargetNetwork(c.Networks, targetNetworks) {
			isCanonicalDirect := lowerPrimary == strings.ToLower(serviceName)+"-blue" ||
				lowerPrimary == strings.ToLower(serviceName)+"-green"
			if !isCanonicalDirect {
				continue
			}
		}

		out = append(out, matchedSlotContainer{
			container:   c,
			primaryName: primaryName,
			slot:        matchedSlot,
			isManaged:   false,
			isRunning:   isRunning,
		})
	}
	return out
}

func sharesTargetNetwork(containerNets map[string][]string, targetNetworks []string) bool {
	for _, tn := range targetNetworks {
		clean := strings.TrimSpace(tn)
		if clean == "" || isSpecialDockerNetwork(clean) {
			continue
		}
		if _, ok := containerNets[clean]; ok {
			return true
		}
	}
	return false
}

func detectActiveServiceSlot(
	matched []matchedSlotContainer,
	allContainers []RunningContainerSummary,
	knownSlot Slot,
	hasKnown bool,
	portBlue int,
	portGreen int,
) Slot {
	if hasKnown {
		for _, m := range matched {
			if m.isRunning && m.slot == knownSlot {
				return knownSlot
			}
		}
	}

	// Prefer FlareLens-managed active slot when both managed and legacy containers exist
	var managedBlue, managedGreen bool
	for _, m := range matched {
		if m.isRunning && m.isManaged {
			if m.slot == SlotGreen {
				managedGreen = true
			} else if m.slot == SlotBlue {
				managedBlue = true
			}
		}
	}
	if managedGreen {
		return SlotGreen
	}
	if managedBlue {
		return SlotBlue
	}

	// Next, inspect running legacy slot containers matching canonical/alias names
	var legacyBlue, legacyGreen bool
	for _, m := range matched {
		if m.isRunning && !m.isManaged {
			if m.slot == SlotGreen {
				legacyGreen = true
			} else if m.slot == SlotBlue {
				legacyBlue = true
			}
		}
	}
	if legacyGreen && !legacyBlue {
		return SlotGreen
	}
	if legacyBlue && !legacyGreen {
		return SlotBlue
	}
	if legacyGreen {
		return SlotGreen
	}

	// Fallback: inspect host port bindings so candidate never stages onto a bound slot port when the opposite port is free
	greenBound := isHostPortBound(allContainers, portGreen)
	blueBound := isHostPortBound(allContainers, portBlue)
	if greenBound && !blueBound {
		return SlotGreen
	}
	if blueBound && !greenBound {
		return SlotBlue
	}
	if hasKnown {
		return knownSlot
	}
	return SlotBlue
}

func isLegacyCompanionWorkerContainer(
	c RunningContainerSummary,
	workerName string,
	envName string,
	workerNetworks []string,
) bool {
	wn := strings.ToLower(strings.TrimSpace(workerName))
	if wn == "" {
		return false
	}
	normEnv := normalizeEnvShort(envName)
	canonical := fmt.Sprintf("%s-%s", wn, normEnv)

	if labelEnv := strings.TrimSpace(c.Labels["flarelens.env"]); labelEnv != "" &&
		normalizeEnvShort(labelEnv) != normEnv {
		return false
	}

	for _, n := range c.Names {
		ln := strings.ToLower(strings.TrimSpace(n))
		if ln == "" || ln == canonical {
			continue
		}
		if ln == fmt.Sprintf("%s-%s", normEnv, wn) ||
			strings.HasSuffix(ln, fmt.Sprintf("-%s-%s", normEnv, wn)) {
			return true
		}
		if (ln == wn || strings.HasSuffix(ln, "-"+wn)) && sharesTargetNetwork(c.Networks, workerNetworks) {
			return true
		}
	}
	return false
}

func resolveVolumeBinds(
	volumes []string,
	envName string,
	slotOrRole string,
	baseServiceName string,
	secretFiles map[string]string,
) []string {
	resolvedBinds := make([]string, 0, len(volumes)+2)
	mountedDests := make(map[string]bool)

	for _, b := range volumes {
		formattedBind := b
		if strings.Contains(formattedBind, "%s") {
			formattedBind = fmt.Sprintf(formattedBind, envName, slotOrRole)
		}
		parts := strings.Split(formattedBind, ":")
		if len(parts) > 0 {
			if _, statErr := os.Stat(parts[0]); statErr == nil {
				resolvedBinds = append(resolvedBinds, formattedBind)
				if len(parts) > 1 {
					mountedDests[strings.TrimSuffix(filepath.ToSlash(parts[1]), "/")] = true
				}
			}
		}
	}

	if _, statErr := os.Stat("/etc/flarelens/flags"); statErr == nil {
		if !mountedDests["/etc/flarelens/flags"] {
			resolvedBinds = append(resolvedBinds, "/etc/flarelens/flags:/etc/flarelens/flags:ro")
			mountedDests["/etc/flarelens/flags"] = true
		}
	}

	if len(secretFiles) > 0 {
		byDir := make(map[string]map[string]string)
		for containerPath, content := range secretFiles {
			clean := filepath.ToSlash(strings.TrimSpace(containerPath))
			if !strings.HasPrefix(clean, "/") || content == "" {
				continue
			}
			dir := strings.TrimSuffix(filepath.ToSlash(filepath.Dir(clean)), "/")
			base := filepath.Base(clean)
			if dir == "" || dir == "." || base == "" || base == "." || base == "/" {
				continue
			}
			if mountedDests[dir] {
				continue
			}
			if byDir[dir] == nil {
				byDir[dir] = make(map[string]string)
			}
			byDir[dir][base] = content
		}

		for containerDir, files := range byDir {
			hostBase := selectRAMSecretsBaseDir()
			safeDirSlug := strings.ReplaceAll(strings.TrimPrefix(containerDir, "/"), "/", "_")
			hostDir := filepath.Join(hostBase, fmt.Sprintf("%s-%s", baseServiceName, normalizeEnvShort(envName)), safeDirSlug)
			if err := os.MkdirAll(hostDir, 0700); err != nil {
				continue
			}
			wroteAll := true
			for fileName, fileContent := range files {
				targetFile := filepath.Join(hostDir, fileName)
				if err := os.WriteFile(targetFile, []byte(fileContent), 0600); err != nil {
					wroteAll = false
					break
				}
			}
			if wroteAll {
				resolvedBinds = append(resolvedBinds, fmt.Sprintf("%s:%s:ro", hostDir, containerDir))
				mountedDests[containerDir] = true
			}
		}
	}

	return resolvedBinds
}

func selectRAMSecretsBaseDir() string {
	for _, candidate := range []string{"/run/shm", "/dev/shm", "/run"} {
		if isExistingDir(candidate) {
			dir := filepath.Join(candidate, "flarelens-secrets")
			if err := os.MkdirAll(dir, 0700); err == nil {
				return dir
			}
		}
	}
	return filepath.Join(os.TempDir(), "flarelens-secrets")
}
