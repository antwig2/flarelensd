package deploy

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// HealthProber probes candidate containers until they pass healthchecks
type HealthProber struct {
	client *http.Client
}

func NewHealthProber() *HealthProber {
	return &HealthProber{
		client: &http.Client{
			Timeout: 2 * time.Second,
		},
	}
}

// Probe polls candidate URL until healthy or timeout
func (p *HealthProber) Probe(
	ctx context.Context,
	url string,
	timeout time.Duration,
	interval time.Duration,
) error {
	if interval <= 0 {
		interval = 1 * time.Second
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var lastErr error

	for {
		select {
		case <-probeCtx.Done():
			if lastErr != nil {
				return fmt.Errorf("healthcheck timed out after %s: %w", timeout, lastErr)
			}
			return fmt.Errorf("healthcheck timed out after %s for %s", timeout, url)

		case <-ticker.C:
			req, err := http.NewRequestWithContext(probeCtx, "GET", url, nil)
			if err != nil {
				lastErr = err
				continue
			}

			resp, err := p.client.Do(req)
			if err != nil {
				lastErr = err
				continue
			}
			_ = resp.Body.Close()

			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				return nil // Passed healthcheck!
			}

			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
		}
	}
}
