package deploy

import (
	"bytes"
	"cmp"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// DockerRunner manages programmatic Docker container lifecycles via Unix domain socket
type DockerRunner struct {
	client *http.Client
	socket string
}

func NewDockerRunner(socketPath string) *DockerRunner {
	cleanPath := strings.TrimPrefix(socketPath, "unix://")

	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", cleanPath)
		},
	}

	return &DockerRunner{
		client: &http.Client{
			Transport: transport,
			Timeout:   180 * time.Second, // Long timeout for large image pulls
		},
		socket: cleanPath,
	}
}

// PullImage pulls candidate container image from registry
func (r *DockerRunner) PullImage(ctx context.Context, image string) error {
	if strings.HasPrefix(r.socket, "mock") {
		return nil
	}

	// 1. Try host docker CLI first if available (supports credentials seamlessly like Kamal)
	if dockerBin, err := exec.LookPath("docker"); err == nil && dockerBin != "" {
		cmd := exec.CommandContext(ctx, dockerBin, "pull", image)
		if _, err := cmd.CombinedOutput(); err == nil {
			return nil
		}
	}

	// 2. Docker Engine API fallback with X-Registry-Auth
	u := fmt.Sprintf("http://localhost/images/create?fromImage=%s", url.QueryEscape(image))
	req, err := http.NewRequestWithContext(ctx, "POST", u, nil)
	if err != nil {
		return err
	}

	// Read Docker credentials from standard config paths if present
	if authHeader := resolveRegistryAuth(image); authHeader != "" {
		req.Header.Set("X-Registry-Auth", authHeader)
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to pull image %s: %w", image, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("docker pull returned status %d: %s", resp.StatusCode, string(body))
	}

	// Drain output stream to wait for pull completion
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

func resolveRegistryAuth(image string) string {
	homeDir, _ := os.UserHomeDir()
	paths := []string{
		filepath.Join(homeDir, ".docker", "config.json"),
		"/root/.docker/config.json",
		"/etc/docker/config.json",
	}

	var registry string
	parts := strings.Split(image, "/")
	if len(parts) > 1 && (strings.Contains(parts[0], ".") || strings.Contains(parts[0], ":")) {
		registry = parts[0]
	}

	for _, p := range paths {
		if p == "" {
			continue
		}
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var cfg struct {
			Auths map[string]struct {
				Auth string `json:"auth"`
			} `json:"auths"`
		}
		if err := json.Unmarshal(data, &cfg); err == nil && len(cfg.Auths) > 0 {
			if registry != "" {
				if entry, ok := cfg.Auths[registry]; ok && entry.Auth != "" {
					return base64.StdEncoding.EncodeToString(fmt.Appendf(nil, `{"auth":"%s","serveraddress":"%s"}`, entry.Auth, registry))
				}
			}
			for server, entry := range cfg.Auths {
				if entry.Auth != "" {
					return base64.StdEncoding.EncodeToString(fmt.Appendf(nil, `{"auth":"%s","serveraddress":"%s"}`, entry.Auth, server))
				}
			}
		}
	}
	return ""
}

type containerCreateConfig struct {
	Image            string                     `json:"Image"`
	Cmd              []string                   `json:"Cmd,omitempty"`
	Entrypoint       []string                   `json:"Entrypoint,omitempty"`
	Env              []string                   `json:"Env"`
	Labels           map[string]string          `json:"Labels,omitempty"`
	ExposedPorts     map[string]struct{}        `json:"ExposedPorts,omitempty"`
	Healthcheck      *ContainerHealthcheck      `json:"Healthcheck,omitempty"`
	HostConfig       containerHostConfig        `json:"HostConfig"`
	NetworkingConfig *containerNetworkingConfig `json:"NetworkingConfig,omitempty"`
}

// ContainerHealthcheck maps to Docker Engine API HealthConfig
type ContainerHealthcheck struct {
	Test       []string `json:"Test,omitempty"`
	IntervalNs int64    `json:"Interval,omitempty"`
	TimeoutNs  int64    `json:"Timeout,omitempty"`
	Retries    int      `json:"Retries,omitempty"`
}

type containerNetworkingConfig struct {
	EndpointsConfig map[string]networkEndpointConfig `json:"EndpointsConfig,omitempty"`
}

type networkEndpointConfig struct {
	Aliases []string `json:"Aliases,omitempty"`
}

type containerHostConfig struct {
	Binds         []string                      `json:"Binds,omitempty"`
	ExtraHosts    []string                      `json:"ExtraHosts,omitempty"`
	PortBindings  map[string][]portBindingEntry `json:"PortBindings,omitempty"`
	NetworkMode   string                        `json:"NetworkMode,omitempty"`
	OomScoreAdj   int                           `json:"OomScoreAdj"`
	RestartPolicy restartPolicy                 `json:"RestartPolicy"`
}

func determineOomScore(serviceName string) int {
	lower := strings.ToLower(serviceName)
	if strings.Contains(lower, "postgres") || strings.Contains(lower, "db") {
		return -900
	}
	if strings.Contains(lower, "redis") || strings.Contains(lower, "dragonfly") {
		return -800
	}
	if strings.Contains(lower, "worker") || strings.Contains(lower, "cron") || strings.Contains(lower, "drainer") {
		return 500
	}
	return 0
}

type portBindingEntry struct {
	HostIP   string `json:"HostIp,omitempty"`
	HostPort string `json:"HostPort"`
}

type restartPolicy struct {
	Name string `json:"Name"`
}

// ContainerConfig defines full parameters for running containerized roles
type ContainerConfig struct {
	Name          string
	Image         string
	EnvVars       []string
	Cmd           []string
	Entrypoint    []string
	Binds         []string
	ExtraHosts    []string
	HostPort      int
	ContainerPort int
	PortMappings  []string
	RestartPolicy string
	Healthcheck   *ContainerHealthcheck
	Networks      []string
	Aliases       []string
	Labels        map[string]string
}

// ContainerDetail describes the live state of an inspected Docker container
type ContainerDetail struct {
	ID       string
	Running  bool
	Image    string
	Labels   map[string]string
	Networks map[string][]string
}

// PublishedPort describes an active host-to-container port binding reported by Docker Engine
type PublishedPort struct {
	IP          string
	PrivatePort int
	PublicPort  int
	Type        string
}

// ContainerMount describes a host bind mount reported by Docker Engine
type ContainerMount struct {
	Source      string
	Destination string
}

// RunningContainerSummary holds network, port, mount, and label metadata for a Docker container
type RunningContainerSummary struct {
	ID       string
	Names    []string
	Image    string
	State    string
	Labels   map[string]string
	Ports    []PublishedPort
	Mounts   []ContainerMount
	Networks map[string][]string // networkName -> aliases
}

// EnsureNetwork idempotently creates a bridge Docker network if it does not already exist
func (r *DockerRunner) EnsureNetwork(ctx context.Context, networkName string) error {
	if strings.HasPrefix(r.socket, "mock") || networkName == "" || networkName == "bridge" || networkName == "host" || networkName == "none" {
		return nil
	}

	inspectURL := fmt.Sprintf("http://localhost/networks/%s", url.PathEscape(networkName))
	inspectReq, err := http.NewRequestWithContext(ctx, "GET", inspectURL, nil)
	if err == nil {
		if resp, doErr := r.client.Do(inspectReq); doErr == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
	}

	payload := map[string]any{
		"Name":           networkName,
		"Driver":         "bridge",
		"CheckDuplicate": true,
	}
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", "http://localhost/networks/create", bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("create network %s: %w", networkName, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusConflict {
		body, _ := io.ReadAll(resp.Body)
		bodyStr := string(body)
		if !strings.Contains(bodyStr, "already exists") {
			return fmt.Errorf("create network %s returned %d: %s", networkName, resp.StatusCode, bodyStr)
		}
	}
	return nil
}

func isSpecialDockerNetwork(networkName string) bool {
	switch strings.TrimSpace(networkName) {
	case "host", "none", "bridge":
		return true
	default:
		return false
	}
}

// ConnectNetwork attaches an existing container to a Docker network
func (r *DockerRunner) ConnectNetwork(ctx context.Context, containerID string, networkName string) error {
	return r.ConnectNetworkWithAliases(ctx, containerID, networkName, nil)
}

// ConnectNetworkWithAliases attaches an existing container to a Docker network with optional DNS aliases
func (r *DockerRunner) ConnectNetworkWithAliases(ctx context.Context, containerID string, networkName string, aliases []string) error {
	if strings.HasPrefix(r.socket, "mock") || networkName == "" || networkName == "host" || networkName == "none" {
		return nil
	}
	_ = r.EnsureNetwork(ctx, networkName)

	u := fmt.Sprintf("http://localhost/networks/%s/connect", url.PathEscape(networkName))
	payload := map[string]any{
		"Container": containerID,
	}
	if len(aliases) > 0 && !isSpecialDockerNetwork(networkName) {
		payload["EndpointConfig"] = networkEndpointConfig{
			Aliases: dedupeNonEmptyStrings(aliases),
		}
	}
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", u, bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("connect network %s: %w", networkName, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusResetContent && resp.StatusCode != http.StatusNotModified {
		body, _ := io.ReadAll(resp.Body)
		bodyStr := string(body)
		if !strings.Contains(bodyStr, "already exists") && !strings.Contains(bodyStr, "already attached") {
			return fmt.Errorf("connect network %s returned %d: %s", networkName, resp.StatusCode, bodyStr)
		}
	}
	return nil
}

// DisconnectNetwork detaches a container from a Docker network
func (r *DockerRunner) DisconnectNetwork(ctx context.Context, containerID string, networkName string, force bool) error {
	if strings.HasPrefix(r.socket, "mock") || networkName == "" {
		return nil
	}
	u := fmt.Sprintf("http://localhost/networks/%s/disconnect", url.PathEscape(networkName))
	payload := map[string]any{
		"Container": containerID,
		"Force":     force,
	}
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", u, bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("disconnect network %s: %w", networkName, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(resp.Body)
		bodyStr := string(body)
		if !strings.Contains(bodyStr, "is not connected") && !strings.Contains(bodyStr, "not found") {
			return fmt.Errorf("disconnect network %s returned %d: %s", networkName, resp.StatusCode, bodyStr)
		}
	}
	return nil
}

// PromoteNetworkAliases ensures containerID is attached to each target network with all stable service DNS aliases.
// If the container is already attached to a network with all requested aliases, that network is left untouched.
func (r *DockerRunner) PromoteNetworkAliases(ctx context.Context, containerID string, networks []string, aliases []string) error {
	cleanAliases := dedupeNonEmptyStrings(aliases)
	if strings.HasPrefix(r.socket, "mock") || containerID == "" || len(cleanAliases) == 0 {
		return nil
	}

	targetNetworks := dedupeNonEmptyStrings(networks)
	if len(targetNetworks) == 0 {
		targetNetworks = []string{"flarelens-edge"}
	}

	existingNets, _ := r.InspectContainerNetworks(ctx, containerID)

	for _, netName := range targetNetworks {
		if isSpecialDockerNetwork(netName) {
			continue
		}
		existingAliases, connected := existingNets[netName]
		if connected && containsAllStrings(existingAliases, cleanAliases) {
			continue
		}
		mergedAliases := dedupeNonEmptyStrings(append(slices.Clone(existingAliases), cleanAliases...))
		if connected {
			if err := r.DisconnectNetwork(ctx, containerID, netName, false); err != nil {
				return err
			}
		}
		if err := r.ConnectNetworkWithAliases(ctx, containerID, netName, mergedAliases); err != nil {
			return err
		}
	}
	return nil
}

// CreateContainerWithOptions creates a container with multi-network, volumes, custom cmd, and entrypoint
func (r *DockerRunner) CreateContainerWithOptions(ctx context.Context, cfg ContainerConfig) (string, error) {
	primaryNetwork := "flarelens-edge"
	if len(cfg.Networks) > 0 && cfg.Networks[0] != "" {
		primaryNetwork = cfg.Networks[0]
	}
	_ = r.EnsureNetwork(ctx, primaryNetwork)

	var extraHosts []string
	if primaryNetwork != "host" && primaryNetwork != "none" {
		extraHosts = dedupeNonEmptyStrings(append([]string{"host.docker.internal:host-gateway"}, cfg.ExtraHosts...))
	} else if len(cfg.ExtraHosts) > 0 {
		extraHosts = dedupeNonEmptyStrings(cfg.ExtraHosts)
	}

	createCfg := containerCreateConfig{
		Image:       cfg.Image,
		Cmd:         cfg.Cmd,
		Entrypoint:  cfg.Entrypoint,
		Env:         cfg.EnvVars,
		Labels:      cfg.Labels,
		Healthcheck: cfg.Healthcheck,
		HostConfig: containerHostConfig{
			Binds:       cfg.Binds,
			ExtraHosts:  extraHosts,
			NetworkMode: primaryNetwork,
			OomScoreAdj: determineOomScore(cfg.Name),
			RestartPolicy: restartPolicy{
				Name: cmp.Or(strings.TrimSpace(cfg.RestartPolicy), "always"),
			},
		},
	}

	if cleanAliases := dedupeNonEmptyStrings(cfg.Aliases); len(cleanAliases) > 0 && !isSpecialDockerNetwork(primaryNetwork) {
		createCfg.NetworkingConfig = &containerNetworkingConfig{
			EndpointsConfig: map[string]networkEndpointConfig{
				primaryNetwork: {
					Aliases: cleanAliases,
				},
			},
		}
	}

	exposedPorts, portBindings := parsePortMappings(cfg.PortMappings)
	if cfg.ContainerPort > 0 {
		portKey := fmt.Sprintf("%d/tcp", cfg.ContainerPort)
		if exposedPorts == nil {
			exposedPorts = make(map[string]struct{})
		}
		exposedPorts[portKey] = struct{}{}
		if cfg.HostPort > 0 {
			if portBindings == nil {
				portBindings = make(map[string][]portBindingEntry)
			}
			portBindings[portKey] = append(portBindings[portKey], portBindingEntry{
				HostPort: fmt.Sprintf("%d", cfg.HostPort),
			})
		}
	}
	if len(exposedPorts) > 0 {
		createCfg.ExposedPorts = exposedPorts
	}
	if len(portBindings) > 0 {
		createCfg.HostConfig.PortBindings = portBindings
	}

	bodyBytes, err := json.Marshal(createCfg)
	if err != nil {
		return "", err
	}

	u := fmt.Sprintf("http://localhost/containers/create?name=%s", url.QueryEscape(cfg.Name))
	req, err := http.NewRequestWithContext(ctx, "POST", u, bytes.NewReader(bodyBytes))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := r.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("container create request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("container create returned status %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		ID string `json:"Id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	// Connect to secondary networks (e.g. uat or prod) when primary network is a bridge/overlay network
	if len(cfg.Networks) > 1 && primaryNetwork != "host" && primaryNetwork != "none" {
		for _, netName := range cfg.Networks[1:] {
			if netName != "" && netName != primaryNetwork && netName != "host" && netName != "none" {
				if err := r.ConnectNetworkWithAliases(ctx, result.ID, netName, cfg.Aliases); err != nil {
					_ = r.RemoveContainer(ctx, result.ID)
					return "", err
				}
			}
		}
	}

	return result.ID, nil
}

// CreateContainer creates a container with in-memory secrets and port bindings (backwards-compatible wrapper)
func (r *DockerRunner) CreateContainer(
	ctx context.Context,
	name string,
	image string,
	envVars []string,
	hostPort, containerPort int,
	network string,
	labels map[string]string,
) (string, error) {
	networks := []string{}
	if network != "" {
		networks = append(networks, network)
	}
	return r.CreateContainerWithOptions(ctx, ContainerConfig{
		Name:          name,
		Image:         image,
		EnvVars:       envVars,
		HostPort:      hostPort,
		ContainerPort: containerPort,
		Networks:      networks,
		Labels:        labels,
	})
}

// StartContainer launches the created container
func (r *DockerRunner) StartContainer(ctx context.Context, containerID string) error {
	u := fmt.Sprintf("http://localhost/containers/%s/start", containerID)
	req, err := http.NewRequestWithContext(ctx, "POST", u, nil)
	if err != nil {
		return err
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("container start failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotModified {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("container start returned status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// StopContainer stops a container with graceful drain timeout
func (r *DockerRunner) StopContainer(ctx context.Context, containerID string, timeoutSec int) error {
	if timeoutSec <= 0 {
		timeoutSec = 10
	}
	u := fmt.Sprintf("http://localhost/containers/%s/stop?t=%d", containerID, timeoutSec)
	req, err := http.NewRequestWithContext(ctx, "POST", u, nil)
	if err != nil {
		return err
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("container stop failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotModified {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("container stop returned status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// RemoveContainer force removes a stopped or failed container
func (r *DockerRunner) RemoveContainer(ctx context.Context, containerID string) error {
	u := fmt.Sprintf("http://localhost/containers/%s?v=true&force=true", containerID)
	req, err := http.NewRequestWithContext(ctx, "DELETE", u, nil)
	if err != nil {
		return err
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("container remove failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("container remove returned status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// FindContainerIDByName looks up an existing container ID by name
func (r *DockerRunner) FindContainerIDByName(ctx context.Context, name string) (string, error) {
	if strings.HasPrefix(r.socket, "mock") {
		return "", nil
	}
	u := fmt.Sprintf("http://localhost/containers/%s/json", url.PathEscape(name))
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return "", err
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return "", nil // Not found
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("inspect container status %d", resp.StatusCode)
	}

	var data struct {
		ID string `json:"Id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return "", err
	}

	return data.ID, nil
}

// InspectContainerIP retrieves the container's IP address on the primary or edge bridge network
func (r *DockerRunner) InspectContainerIP(ctx context.Context, containerID string) (string, error) {
	if strings.HasPrefix(r.socket, "mock") {
		return "127.0.0.1", nil
	}
	u := fmt.Sprintf("http://localhost/containers/%s/json", url.PathEscape(containerID))
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return "", err
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("inspect container status %d", resp.StatusCode)
	}

	var data struct {
		NetworkSettings struct {
			IPAddress string `json:"IPAddress"`
			Networks  map[string]struct {
				IPAddress string `json:"IPAddress"`
			} `json:"Networks"`
		} `json:"NetworkSettings"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return "", err
	}

	if edgeNet, ok := data.NetworkSettings.Networks["flarelens-edge"]; ok && edgeNet.IPAddress != "" {
		return edgeNet.IPAddress, nil
	}
	netNames := slices.Sorted(maps.Keys(data.NetworkSettings.Networks))
	for _, netName := range netNames {
		if strings.HasSuffix(netName, "-edge") {
			if edgeNet := data.NetworkSettings.Networks[netName]; edgeNet.IPAddress != "" {
				return edgeNet.IPAddress, nil
			}
		}
	}
	if data.NetworkSettings.IPAddress != "" {
		return data.NetworkSettings.IPAddress, nil
	}
	for _, netName := range netNames {
		if netCfg := data.NetworkSettings.Networks[netName]; netCfg.IPAddress != "" {
			return netCfg.IPAddress, nil
		}
	}
	return "", nil
}

// InspectContainerDetail retrieves full state, image, labels, and networks for an existing container (nil, nil if absent)
func (r *DockerRunner) InspectContainerDetail(ctx context.Context, nameOrID string) (*ContainerDetail, error) {
	if strings.HasPrefix(r.socket, "mock") || strings.TrimSpace(nameOrID) == "" {
		return nil, nil
	}
	u := fmt.Sprintf("http://localhost/containers/%s/json", url.PathEscape(nameOrID))
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return nil, err
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("inspect container status %d", resp.StatusCode)
	}

	var data struct {
		ID    string `json:"Id"`
		State struct {
			Running bool `json:"Running"`
		} `json:"State"`
		Config struct {
			Image  string            `json:"Image"`
			Labels map[string]string `json:"Labels"`
		} `json:"Config"`
		NetworkSettings struct {
			Networks map[string]struct {
				Aliases []string `json:"Aliases"`
			} `json:"Networks"`
		} `json:"NetworkSettings"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	nets := make(map[string][]string, len(data.NetworkSettings.Networks))
	for netName, netCfg := range data.NetworkSettings.Networks {
		nets[netName] = slices.Clone(netCfg.Aliases)
	}
	return &ContainerDetail{
		ID:       data.ID,
		Running:  data.State.Running,
		Image:    data.Config.Image,
		Labels:   maps.Clone(data.Config.Labels),
		Networks: nets,
	}, nil
}

func parsePortMappings(specs []string) (map[string]struct{}, map[string][]portBindingEntry) {
	if len(specs) == 0 {
		return nil, nil
	}
	exposed := make(map[string]struct{})
	bindings := make(map[string][]portBindingEntry)

	normalizeContainerPort := func(raw string) string {
		p := strings.TrimSpace(raw)
		if p == "" {
			return ""
		}
		if !strings.Contains(p, "/") {
			return p + "/tcp"
		}
		return p
	}

	for _, rawSpec := range specs {
		spec := strings.TrimSpace(rawSpec)
		if spec == "" {
			continue
		}
		parts := strings.Split(spec, ":")
		switch len(parts) {
		case 1:
			portKey := normalizeContainerPort(parts[0])
			if portKey != "" {
				exposed[portKey] = struct{}{}
			}
		case 2:
			hostPort := strings.TrimSpace(parts[0])
			portKey := normalizeContainerPort(parts[1])
			if portKey != "" {
				exposed[portKey] = struct{}{}
				if hostPort != "" {
					bindings[portKey] = append(bindings[portKey], portBindingEntry{
						HostPort: hostPort,
					})
				}
			}
		default:
			// e.g. "10.77.77.1:5432:5432" or "[::1]:5432:5432/tcp"
			containerPart := parts[len(parts)-1]
			hostPort := strings.TrimSpace(parts[len(parts)-2])
			hostIP := strings.Trim(strings.Join(parts[:len(parts)-2], ":"), "[]")
			portKey := normalizeContainerPort(containerPart)
			if portKey != "" {
				exposed[portKey] = struct{}{}
				if hostPort != "" {
					bindings[portKey] = append(bindings[portKey], portBindingEntry{
						HostIP:   hostIP,
						HostPort: hostPort,
					})
				}
			}
		}
	}
	return exposed, bindings
}

// InspectContainerNetworks returns the map of attached network names to their active DNS aliases
func (r *DockerRunner) InspectContainerNetworks(ctx context.Context, containerID string) (map[string][]string, error) {
	if strings.HasPrefix(r.socket, "mock") || containerID == "" {
		return nil, nil
	}
	u := fmt.Sprintf("http://localhost/containers/%s/json", url.PathEscape(containerID))
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return nil, err
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("inspect container status %d", resp.StatusCode)
	}

	var data struct {
		NetworkSettings struct {
			Networks map[string]struct {
				Aliases []string `json:"Aliases"`
			} `json:"Networks"`
		} `json:"NetworkSettings"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	res := make(map[string][]string, len(data.NetworkSettings.Networks))
	for netName, netCfg := range data.NetworkSettings.Networks {
		res[netName] = slices.Clone(netCfg.Aliases)
	}
	return res, nil
}

// ListRunningContainers returns network, port, mount, and label summaries for running containers on the host
func (r *DockerRunner) ListRunningContainers(ctx context.Context) ([]RunningContainerSummary, error) {
	return r.listContainers(ctx, false)
}

// ListAllContainers returns network, port, mount, and label summaries for all containers (running and stopped) on the host
func (r *DockerRunner) ListAllContainers(ctx context.Context) ([]RunningContainerSummary, error) {
	return r.listContainers(ctx, true)
}

func (r *DockerRunner) listContainers(ctx context.Context, includeStopped bool) ([]RunningContainerSummary, error) {
	if strings.HasPrefix(r.socket, "mock") {
		return nil, nil
	}
	endpoint := "http://localhost/containers/json"
	if includeStopped {
		endpoint += "?all=1"
	}
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, err
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("list containers status %d", resp.StatusCode)
	}

	var raw []struct {
		ID     string            `json:"Id"`
		Names  []string          `json:"Names"`
		Image  string            `json:"Image"`
		State  string            `json:"State"`
		Labels map[string]string `json:"Labels"`
		Ports  []struct {
			IP          string `json:"IP"`
			PrivatePort int    `json:"PrivatePort"`
			PublicPort  int    `json:"PublicPort"`
			Type        string `json:"Type"`
		} `json:"Ports"`
		Mounts []struct {
			Source      string `json:"Source"`
			Destination string `json:"Destination"`
		} `json:"Mounts"`
		NetworkSettings struct {
			Networks map[string]struct {
				Aliases []string `json:"Aliases"`
			} `json:"Networks"`
		} `json:"NetworkSettings"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, err
	}

	out := make([]RunningContainerSummary, 0, len(raw))
	for _, item := range raw {
		nets := make(map[string][]string, len(item.NetworkSettings.Networks))
		for netName, netCfg := range item.NetworkSettings.Networks {
			nets[netName] = slices.Clone(netCfg.Aliases)
		}
		names := make([]string, 0, len(item.Names))
		for _, n := range item.Names {
			names = append(names, strings.TrimPrefix(n, "/"))
		}
		ports := make([]PublishedPort, 0, len(item.Ports))
		for _, p := range item.Ports {
			ports = append(ports, PublishedPort{
				IP:          p.IP,
				PrivatePort: p.PrivatePort,
				PublicPort:  p.PublicPort,
				Type:        p.Type,
			})
		}
		mounts := make([]ContainerMount, 0, len(item.Mounts))
		for _, m := range item.Mounts {
			if m.Source != "" || m.Destination != "" {
				mounts = append(mounts, ContainerMount{
					Source:      m.Source,
					Destination: m.Destination,
				})
			}
		}
		out = append(out, RunningContainerSummary{
			ID:       item.ID,
			Names:    names,
			Image:    item.Image,
			State:    item.State,
			Labels:   item.Labels,
			Ports:    ports,
			Mounts:   mounts,
			Networks: nets,
		})
	}
	return out, nil
}

// DiscoverTraefikRoutesDir inspects running Traefik containers via Docker Engine mounts
// to locate the active dynamic file-provider directory on the host without hardcoded vendor paths.
func (r *DockerRunner) DiscoverTraefikRoutesDir(ctx context.Context) string {
	containers, err := r.ListRunningContainers(ctx)
	if err != nil {
		return ""
	}
	for _, c := range containers {
		isTraefik := strings.Contains(strings.ToLower(c.Image), "traefik")
		if !isTraefik {
			for _, n := range c.Names {
				if strings.Contains(strings.ToLower(n), "traefik") {
					isTraefik = true
					break
				}
			}
		}
		if !isTraefik {
			continue
		}

		// 1. Direct mount targeting a dynamic or routes directory inside Traefik
		for _, m := range c.Mounts {
			dest := strings.ToLower(filepath.ToSlash(m.Destination))
			if (strings.Contains(dest, "routes") || strings.Contains(dest, "dynamic")) && isExistingDir(m.Source) {
				return m.Source
			}
		}

		// 2. Mount targeting /etc/traefik root directory — check standard route subdirectories on host
		for _, m := range c.Mounts {
			dest := strings.TrimSuffix(filepath.ToSlash(m.Destination), "/")
			if dest == "/etc/traefik" && isExistingDir(m.Source) {
				subCandidates := []string{
					filepath.Join(m.Source, "routes"),
					filepath.Join(m.Source, "dynamic", "routes"),
					filepath.Join(m.Source, "dynamic"),
				}
				for _, sub := range subCandidates {
					if isExistingDir(sub) {
						return sub
					}
				}
			}
		}
	}
	return ""
}

func isExistingDir(path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func dedupeNonEmptyStrings(items []string) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		trimmed := strings.TrimSpace(item)
		if trimmed == "" || slices.Contains(out, trimmed) {
			continue
		}
		out = append(out, trimmed)
	}
	return out
}

func containsAllStrings(haystack, needles []string) bool {
	for _, needle := range needles {
		if !slices.Contains(haystack, needle) {
			return false
		}
	}
	return true
}
