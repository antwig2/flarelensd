package deploy

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"
)

// HealthcheckSpec defines a declarative Docker container healthcheck in a fleet manifest.
type HealthcheckSpec struct {
	Test     []string `json:"test,omitempty"`
	Interval string   `json:"interval,omitempty"`
	Timeout  string   `json:"timeout,omitempty"`
	Retries  int      `json:"retries,omitempty"`
}

// SingletonSpec defines a declarative stateful or singleton container reconciliation request.
type SingletonSpec struct {
	DeploymentID          string            `json:"deployment_id"`
	NodeID                string            `json:"node_id,omitempty"`
	Service               string            `json:"service"`
	Env                   string            `json:"env"`
	Image                 string            `json:"image"`
	ContainerName         string            `json:"container_name"`
	Restart               string            `json:"restart,omitempty"`
	Networks              []string          `json:"networks,omitempty"`
	Aliases               []string          `json:"aliases,omitempty"`
	Volumes               []string          `json:"volumes,omitempty"`
	Ports                 []string          `json:"ports,omitempty"`
	Command               []string          `json:"command,omitempty"`
	Entrypoint            []string          `json:"entrypoint,omitempty"`
	Healthcheck           *HealthcheckSpec  `json:"healthcheck,omitempty"`
	Secrets               map[string]string `json:"secrets,omitempty"`
	ForceRecreateStateful bool              `json:"force_recreate_stateful,omitempty"`
}

// ReconcileSingleton reconciles a single-instance or stateful service container (e.g. databases, caches, CDC pipelines)
// against its desired Fleet manifest, healing Docker networks and DNS aliases without restarting stateful engines.
func (o *Orchestrator) ReconcileSingleton(ctx context.Context, spec SingletonSpec) DeployResponse {
	o.BeginOp()
	defer o.EndOp()
	startTime := time.Now()

	envName := normalizeEnvShort(spec.Env)
	service := cmp.Or(strings.TrimSpace(spec.Service), strings.TrimSpace(spec.ContainerName))
	containerName := cmp.Or(strings.TrimSpace(spec.ContainerName), fmt.Sprintf("%s-%s", service, envName))

	if service == "" || strings.TrimSpace(spec.Image) == "" {
		return DeployResponse{
			DeploymentID: spec.DeploymentID,
			Service:      service,
			Status:       "failed",
			ActiveSlot:   "singleton",
			Message:      "singleton reconciliation requires non-empty service and image",
			DurationMS:   time.Since(startTime).Milliseconds(),
		}
	}

	networks := dedupeNonEmptyStrings(spec.Networks)
	if len(networks) == 0 {
		networks = []string{"flarelens-edge"}
	}
	for _, netName := range networks {
		if err := o.runner.EnsureNetwork(ctx, netName); err != nil {
			o.logger.Warn("EnsureNetwork warning during singleton reconciliation", "network", netName, "error", err)
		}
	}

	var aliases []string
	if !slices.Contains(networks, "host") && !slices.Contains(networks, "none") {
		aliases = ResolveServiceNetworkAliases(service, envName, append(slices.Clone(spec.Aliases), containerName))
	}
	specHash := computeSingletonSpecHash(spec, envName, networks, aliases)

	existing, err := o.runner.InspectContainerDetail(ctx, containerName)
	if err != nil {
		return DeployResponse{
			DeploymentID: spec.DeploymentID,
			Service:      service,
			Status:       "failed",
			ActiveSlot:   "singleton",
			Message:      fmt.Sprintf("inspect singleton %s failed: %v", containerName, err),
			DurationMS:   time.Since(startTime).Milliseconds(),
		}
	}

	statefulProtected := isStatefulProtected(service, containerName)

	if existing != nil && existing.Running {
		// Always heal missing networks and DNS aliases live with zero container restart.
		if err := o.runner.PromoteNetworkAliases(ctx, existing.ID, networks, aliases); err != nil {
			o.logger.Warn("Failed to heal singleton network aliases",
				"container", containerName,
				"networks", networks,
				"aliases", aliases,
				"error", err,
			)
		}

		existingHash := strings.TrimSpace(existing.Labels["flarelens.spec_hash"])
		if existingHash == specHash || (existingHash == "" && existing.Image == spec.Image && statefulProtected) {
			return DeployResponse{
				DeploymentID: spec.DeploymentID,
				Service:      service,
				Status:       "success",
				ActiveSlot:   "singleton",
				Message:      fmt.Sprintf("Singleton %s is synced and running (network aliases verified)", containerName),
				DurationMS:   time.Since(startTime).Milliseconds(),
			}
		}

		if statefulProtected && !spec.ForceRecreateStateful {
			o.logger.Info("Stateful singleton guardrail prevented container recreation; live network aliases synced",
				"service", service,
				"container", containerName,
				"running_image", existing.Image,
				"desired_image", spec.Image,
			)
			return DeployResponse{
				DeploymentID: spec.DeploymentID,
				Service:      service,
				Status:       "success",
				ActiveSlot:   "singleton",
				Message:      fmt.Sprintf("Stateful singleton %s preserved without restart (aliases synced; pass force_recreate_stateful=true to recreate)", containerName),
				DurationMS:   time.Since(startTime).Milliseconds(),
			}
		}
	}

	if existing != nil && !existing.Running {
		existingHash := strings.TrimSpace(existing.Labels["flarelens.spec_hash"])
		if (existingHash == specHash || statefulProtected) && !spec.ForceRecreateStateful {
			if err := o.runner.StartContainer(ctx, existing.ID); err != nil {
				return DeployResponse{
					DeploymentID: spec.DeploymentID,
					Service:      service,
					Status:       "failed",
					ActiveSlot:   "singleton",
					Message:      fmt.Sprintf("failed to start stopped singleton %s: %v", containerName, err),
					DurationMS:   time.Since(startTime).Milliseconds(),
				}
			}
			_ = o.runner.PromoteNetworkAliases(ctx, existing.ID, networks, aliases)
			return DeployResponse{
				DeploymentID: spec.DeploymentID,
				Service:      service,
				Status:       "success",
				ActiveSlot:   "singleton",
				Message:      fmt.Sprintf("Started stopped singleton %s and synced network aliases", containerName),
				DurationMS:   time.Since(startTime).Milliseconds(),
			}
		}
	}

	// Pull desired image BEFORE stopping any running container so pull failures never cause downtime.
	if err := o.runner.PullImage(ctx, spec.Image); err != nil {
		return DeployResponse{
			DeploymentID: spec.DeploymentID,
			Service:      service,
			Status:       "failed",
			ActiveSlot:   "singleton",
			Message:      fmt.Sprintf("singleton image pull failed for %s: %v", spec.Image, err),
			DurationMS:   time.Since(startTime).Milliseconds(),
		}
	}

	if existing != nil {
		if existing.Running {
			_ = o.runner.StopContainer(ctx, existing.ID, 15)
		}
		if err := o.runner.RemoveContainer(ctx, existing.ID); err != nil {
			return DeployResponse{
				DeploymentID: spec.DeploymentID,
				Service:      service,
				Status:       "failed",
				ActiveSlot:   "singleton",
				Message:      fmt.Sprintf("failed to remove previous singleton %s: %v", containerName, err),
				DurationMS:   time.Since(startTime).Milliseconds(),
			}
		}
	}

	activeSecrets := maps.Clone(spec.Secrets)
	if len(activeSecrets) == 0 {
		activeSecrets = loadFallbackEnv(service, envName)
	}
	envList := make([]string, 0, len(activeSecrets)+3)
	envList = append(envList,
		fmt.Sprintf("DEPLOY_ENV=%s", envName),
		fmt.Sprintf("SERVICE_NAME=%s", service),
	)
	for _, k := range slices.Sorted(maps.Keys(activeSecrets)) {
		envList = append(envList, fmt.Sprintf("%s=%s", k, activeSecrets[k]))
	}

	labels := map[string]string{
		"flarelens.managed":   "true",
		"flarelens.mode":      "singleton",
		"flarelens.service":   service,
		"flarelens.env":       envName,
		"flarelens.spec_hash": specHash,
	}
	if len(aliases) > 0 {
		labels["flarelens.aliases"] = strings.Join(aliases, ",")
	}

	containerID, err := o.runner.CreateContainerWithOptions(ctx, ContainerConfig{
		Name:          containerName,
		Image:         spec.Image,
		EnvVars:       envList,
		Cmd:           spec.Command,
		Entrypoint:    spec.Entrypoint,
		Binds:         dedupeNonEmptyStrings(spec.Volumes),
		PortMappings:  spec.Ports,
		RestartPolicy: cmp.Or(strings.TrimSpace(spec.Restart), "always"),
		Healthcheck:   toContainerHealthcheck(spec.Healthcheck),
		Networks:      networks,
		Aliases:       aliases,
		Labels:        labels,
	})
	if err != nil {
		return DeployResponse{
			DeploymentID: spec.DeploymentID,
			Service:      service,
			Status:       "failed",
			ActiveSlot:   "singleton",
			Message:      fmt.Sprintf("singleton container creation failed for %s: %v", containerName, err),
			DurationMS:   time.Since(startTime).Milliseconds(),
		}
	}

	if err := o.runner.StartContainer(ctx, containerID); err != nil {
		_ = o.runner.RemoveContainer(ctx, containerID)
		return DeployResponse{
			DeploymentID: spec.DeploymentID,
			Service:      service,
			Status:       "failed",
			ActiveSlot:   "singleton",
			Message:      fmt.Sprintf("singleton container start failed for %s: %v", containerName, err),
			DurationMS:   time.Since(startTime).Milliseconds(),
		}
	}

	_ = o.runner.PromoteNetworkAliases(ctx, containerID, networks, aliases)

	action := "Created and started"
	if existing != nil {
		action = "Reconciled and restarted"
	}
	return DeployResponse{
		DeploymentID: spec.DeploymentID,
		Service:      service,
		Status:       "success",
		ActiveSlot:   "singleton",
		Message:      fmt.Sprintf("%s singleton %s (%s)", action, containerName, spec.Image),
		DurationMS:   time.Since(startTime).Milliseconds(),
	}
}

func isStatefulProtected(service, containerName string) bool {
	combined := strings.ToLower(service + " " + containerName)
	for _, keyword := range []string{"postgres", "dragonfly", "redis", "mysql", "mariadb", "mongo"} {
		if strings.Contains(combined, keyword) {
			return true
		}
	}
	return false
}

func toContainerHealthcheck(spec *HealthcheckSpec) *ContainerHealthcheck {
	if spec == nil || len(spec.Test) == 0 {
		return nil
	}
	hc := &ContainerHealthcheck{
		Test:    slices.Clone(spec.Test),
		Retries: spec.Retries,
	}
	if d, err := time.ParseDuration(strings.TrimSpace(spec.Interval)); err == nil && d > 0 {
		hc.IntervalNs = d.Nanoseconds()
	}
	if d, err := time.ParseDuration(strings.TrimSpace(spec.Timeout)); err == nil && d > 0 {
		hc.TimeoutNs = d.Nanoseconds()
	}
	return hc
}

func computeSingletonSpecHash(spec SingletonSpec, envName string, networks, aliases []string) string {
	secretDigest := make(map[string]string, len(spec.Secrets))
	for k, v := range spec.Secrets {
		sum := sha256.Sum256([]byte(v))
		secretDigest[k] = hex.EncodeToString(sum[:8])
	}

	canonical := struct {
		Service     string            `json:"service"`
		Env         string            `json:"env"`
		Image       string            `json:"image"`
		Container   string            `json:"container"`
		Restart     string            `json:"restart"`
		Networks    []string          `json:"networks"`
		Aliases     []string          `json:"aliases"`
		Volumes     []string          `json:"volumes"`
		Ports       []string          `json:"ports"`
		Command     []string          `json:"command"`
		Entrypoint  []string          `json:"entrypoint"`
		Healthcheck *HealthcheckSpec  `json:"healthcheck,omitempty"`
		Secrets     map[string]string `json:"secrets,omitempty"`
	}{
		Service:     spec.Service,
		Env:         envName,
		Image:       spec.Image,
		Container:   spec.ContainerName,
		Restart:     cmp.Or(strings.TrimSpace(spec.Restart), "always"),
		Networks:    networks,
		Aliases:     aliases,
		Volumes:     dedupeNonEmptyStrings(spec.Volumes),
		Ports:       dedupeNonEmptyStrings(spec.Ports),
		Command:     spec.Command,
		Entrypoint:  spec.Entrypoint,
		Healthcheck: spec.Healthcheck,
		Secrets:     secretDigest,
	}

	raw, _ := json.Marshal(canonical)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:16])
}
