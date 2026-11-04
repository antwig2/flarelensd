package deploy

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
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
	Image        string                         `json:"Image"`
	Cmd          []string                       `json:"Cmd,omitempty"`
	Entrypoint   []string                       `json:"Entrypoint,omitempty"`
	Env          []string                       `json:"Env"`
	Labels       map[string]string              `json:"Labels,omitempty"`
	ExposedPorts map[string]struct{}            `json:"ExposedPorts,omitempty"`
	HostConfig   containerHostConfig            `json:"HostConfig"`
}

type containerHostConfig struct {
	Binds         []string                      `json:"Binds,omitempty"`
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
	HostPort      int
	ContainerPort int
	Networks      []string
	Labels        map[string]string
}

// ConnectNetwork attaches an existing container to a Docker network
func (r *DockerRunner) ConnectNetwork(ctx context.Context, containerID string, networkName string) error {
	if strings.HasPrefix(r.socket, "mock") || networkName == "" {
		return nil
	}
	u := fmt.Sprintf("http://localhost/networks/%s/connect", url.PathEscape(networkName))
	payload := map[string]string{
		"Container": containerID,
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

// CreateContainerWithOptions creates a container with multi-network, volumes, custom cmd, and entrypoint
func (r *DockerRunner) CreateContainerWithOptions(ctx context.Context, cfg ContainerConfig) (string, error) {
	primaryNetwork := "flarelens-edge"
	if len(cfg.Networks) > 0 && cfg.Networks[0] != "" {
		primaryNetwork = cfg.Networks[0]
	}

	createCfg := containerCreateConfig{
		Image:      cfg.Image,
		Cmd:        cfg.Cmd,
		Entrypoint: cfg.Entrypoint,
		Env:        cfg.EnvVars,
		Labels:     cfg.Labels,
		HostConfig: containerHostConfig{
			Binds:       cfg.Binds,
			NetworkMode: primaryNetwork,
			OomScoreAdj: determineOomScore(cfg.Name),
			RestartPolicy: restartPolicy{
				Name: "always",
			},
		},
	}

	if cfg.ContainerPort > 0 {
		portKey := fmt.Sprintf("%d/tcp", cfg.ContainerPort)
		createCfg.ExposedPorts = map[string]struct{}{
			portKey: {},
		}
		if cfg.HostPort > 0 {
			createCfg.HostConfig.PortBindings = map[string][]portBindingEntry{
				portKey: {
					{HostPort: fmt.Sprintf("%d", cfg.HostPort)},
				},
			}
		}
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

	// Connect to secondary networks (e.g. uat or prod)
	if len(cfg.Networks) > 1 {
		for _, netName := range cfg.Networks[1:] {
			if netName != "" && netName != primaryNetwork {
				_ = r.ConnectNetwork(ctx, result.ID, netName)
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
	if data.NetworkSettings.IPAddress != "" {
		return data.NetworkSettings.IPAddress, nil
	}
	for _, net := range data.NetworkSettings.Networks {
		if net.IPAddress != "" {
			return net.IPAddress, nil
		}
	}
	return "", nil
}
