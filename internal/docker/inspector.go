package docker

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// ContainerSummary represents container status overview for fleet telemetry
type ContainerSummary struct {
	ID      string   `json:"id"`
	Names   []string `json:"names"`
	Image   string   `json:"image"`
	Status  string   `json:"status"`
	State   string   `json:"state"`
	Created int64    `json:"created"`
}

// Inspector queries Docker Engine via Unix domain socket
type Inspector struct {
	client       *http.Client
	streamClient *http.Client
	socket       string
}

// NewInspector creates a new Docker socket inspector
func NewInspector(socketPath string) *Inspector {
	cleanPath := strings.TrimPrefix(socketPath, "unix://")

	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "unix", cleanPath)
		},
	}

	return &Inspector{
		client: &http.Client{
			Transport: transport,
			Timeout:   5 * time.Second,
		},
		streamClient: &http.Client{
			Transport: transport,
			Timeout:   0, // Unlimited timeout for long-lived log streaming
		},
		socket: cleanPath,
	}
}

// Ping checks if Docker daemon is responsive
func (in *Inspector) Ping(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", "http://localhost/_ping", nil)
	if err != nil {
		return err
	}

	resp, err := in.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("docker ping returned status %d", resp.StatusCode)
	}
	return nil
}

// ListContainers returns active containers running on the host
func (in *Inspector) ListContainers(ctx context.Context, all bool) ([]ContainerSummary, error) {
	url := "http://localhost/containers/json"
	if all {
		url += "?all=true"
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := in.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("docker containers/json returned status %d", resp.StatusCode)
	}

	var raw []struct {
		ID      string   `json:"Id"`
		Names   []string `json:"Names"`
		Image   string   `json:"Image"`
		Status  string   `json:"Status"`
		State   string   `json:"State"`
		Created int64    `json:"Created"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, err
	}

	summaries := make([]ContainerSummary, len(raw))
	for i, c := range raw {
		idShort := c.ID[:min(len(c.ID), 12)]
		// Strip leading slashes from container names
		cleanNames := make([]string, len(c.Names))
		for j, n := range c.Names {
			cleanNames[j] = strings.TrimPrefix(n, "/")
		}

		summaries[i] = ContainerSummary{
			ID:      idShort,
			Names:   cleanNames,
			Image:   c.Image,
			Status:  c.Status,
			State:   c.State,
			Created: c.Created,
		}
	}

	return summaries, nil
}

// StreamLogs returns an io.ReadCloser streaming container stdout and stderr
func (in *Inspector) StreamLogs(ctx context.Context, containerID string, tail string) (io.ReadCloser, error) {
	tailParam := cmp.Or(tail, "50")
	url := fmt.Sprintf("http://localhost/containers/%s/logs?stdout=true&stderr=true&follow=true&tail=%s", containerID, tailParam)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := in.streamClient.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("docker logs request failed with status %d", resp.StatusCode)
	}

	return resp.Body, nil
}
