package deploy

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

// TraefikRouteFlipper updates Traefik's dynamic file provider routing atomically
type TraefikRouteFlipper struct {
	dynamicDir string
}

func NewTraefikRouteFlipper(dynamicDir string) *TraefikRouteFlipper {
	if dynamicDir == "" {
		candidates := []string{
			"/etc/flarelens/traefik/routes",
			"/etc/traefik/dynamic/routes",
			"/etc/traefik/dynamic",
		}
		for _, c := range candidates {
			if _, err := os.Stat(c); err == nil {
				dynamicDir = c
				break
			}
		}
		if dynamicDir == "" {
			dynamicDir = "/etc/traefik/dynamic"
		}
	}
	return &TraefikRouteFlipper{
		dynamicDir: dynamicDir,
	}
}

// SwitchRoute atomically points Traefik to the candidate container/port, updating existing route files or creating a new route
func (t *TraefikRouteFlipper) SwitchRoute(stack, service, targetHost string, targetPort int, domain string) error {
	if err := os.MkdirAll(t.dynamicDir, 0755); err != nil {
		return fmt.Errorf("failed to create traefik dynamic config directory: %w", err)
	}

	targetURL := fmt.Sprintf("http://%s:%d", targetHost, targetPort)

	// Check if existing route file exists (e.g. uat-bill-api.yml, prod-bill-api.yml, etc.)
	candidates := []string{
		filepath.Join(t.dynamicDir, fmt.Sprintf("%s-%s.yml", stack, service)),
		filepath.Join(t.dynamicDir, fmt.Sprintf("%s-%s.yaml", stack, service)),
		filepath.Join(t.dynamicDir, fmt.Sprintf("%s.yml", service)),
		filepath.Join(t.dynamicDir, fmt.Sprintf("%s.yaml", service)),
	}

	for _, p := range candidates {
		data, err := os.ReadFile(p)
		if err == nil {
			content := string(data)
			re := regexp.MustCompile(`url:\s*["']?http://[^:\s'"]+:\d+["']?`)
			if re.MatchString(content) {
				updated := re.ReplaceAllString(content, fmt.Sprintf("url: %s", targetURL))
				tmpPath := p + ".tmp"
				if err := os.WriteFile(tmpPath, []byte(updated), 0644); err == nil {
					_ = os.Rename(tmpPath, p)
					return nil
				}
			}
		}
	}

	// Fall back to generating clean Traefik router config
	return t.FlipRoute(fmt.Sprintf("%s-%s", stack, service), domain, targetPort)
}

// FlipRoute atomically points Traefik domain traffic to the target port
func (t *TraefikRouteFlipper) FlipRoute(service, domain string, targetPort int) error {
	if err := os.MkdirAll(t.dynamicDir, 0755); err != nil {
		return fmt.Errorf("failed to create traefik dynamic config directory: %w", err)
	}

	content := fmt.Sprintf(`http:
  routers:
    %s-router:
      rule: "Host(%s)"
      service: "%s-svc"
      entryPoints:
        - "websecure"
  services:
    %s-svc:
      loadBalancer:
        servers:
          - url: "http://127.0.0.1:%d"
`, service, fmt.Sprintf("`%s`", domain), service, service, targetPort)

	finalPath := filepath.Join(t.dynamicDir, fmt.Sprintf("%s.yaml", service))
	tmpPath := filepath.Join(t.dynamicDir, fmt.Sprintf("%s.yaml.tmp", service))

	// Write to temporary file first
	if err := os.WriteFile(tmpPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write temporary traefik route file: %w", err)
	}

	// Atomic rename ensures Traefik inotify picks up complete valid YAML instantly
	if err := os.Rename(tmpPath, finalPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to atomically rename traefik route: %w", err)
	}

	return nil
}

// SetCanaryRoute sets up Traefik weighted round-robin splitting between active and candidate ports
func (t *TraefikRouteFlipper) SetCanaryRoute(service, domain string, activePort, candidatePort int, candidateWeight int) error {
	if candidateWeight <= 0 {
		return t.FlipRoute(service, domain, activePort)
	}
	if candidateWeight >= 100 {
		return t.FlipRoute(service, domain, candidatePort)
	}

	activeWeight := 100 - candidateWeight

	if err := os.MkdirAll(t.dynamicDir, 0755); err != nil {
		return fmt.Errorf("failed to create traefik dynamic config directory: %w", err)
	}

	content := fmt.Sprintf(`http:
  routers:
    %s-router:
      rule: "Host(%s)"
      service: "%s-wrr"
      entryPoints:
        - "websecure"
  services:
    %s-wrr:
      weighted:
        services:
          - name: "%s-active"
            weight: %d
          - name: "%s-candidate"
            weight: %d
    %s-active:
      loadBalancer:
        servers:
          - url: "http://127.0.0.1:%d"
    %s-candidate:
      loadBalancer:
        servers:
          - url: "http://127.0.0.1:%d"
`, service, fmt.Sprintf("`%s`", domain), service, service, service, activeWeight, service, candidateWeight, service, activePort, service, candidatePort)

	finalPath := filepath.Join(t.dynamicDir, fmt.Sprintf("%s.yaml", service))
	tmpPath := filepath.Join(t.dynamicDir, fmt.Sprintf("%s.yaml.tmp", service))

	if err := os.WriteFile(tmpPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write temporary traefik canary route file: %w", err)
	}

	if err := os.Rename(tmpPath, finalPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to atomically rename traefik canary route: %w", err)
	}

	return nil
}

// RemoveRoute removes the dynamic Traefik route file for an ephemeral preview or retired service
func (t *TraefikRouteFlipper) RemoveRoute(service string) error {
	path := filepath.Join(t.dynamicDir, fmt.Sprintf("%s.yaml", service))
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove traefik route file: %w", err)
	}
	return nil
}
