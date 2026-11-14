package deploy

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
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

var (
	traefikUpstreamURLRe = regexp.MustCompile(`url:\s*["']?http://[^:\s'"]+:\d+["']?`)
	traefikRuleLineRe    = regexp.MustCompile(`(?m)^(\s*rule:\s*)(["']?)(.*?)(["']?)\s*$`)
)

// FormatHostRule formats one or more domains into a Traefik Host(...) expression.
func FormatHostRule(domains ...string) string {
	clean := dedupeNonEmptyStrings(domains)
	if len(clean) == 0 {
		return ""
	}
	parts := make([]string, 0, len(clean))
	for _, d := range clean {
		parts = append(parts, fmt.Sprintf("Host(`%s`)", d))
	}
	return strings.Join(parts, " || ")
}

// SwitchRoute atomically points Traefik to the candidate container/port, updating existing route files or creating a new route
func (t *TraefikRouteFlipper) SwitchRoute(stack, service, targetHost string, targetPort int, domain string, aliases ...string) error {
	return t.SwitchRouteWithDomains(stack, service, targetHost, targetPort, []string{domain}, aliases...)
}

// SwitchRouteWithDomains atomically points Traefik to targetHost:targetPort and ensures all declared domains are routed.
func (t *TraefikRouteFlipper) SwitchRouteWithDomains(stack, service, targetHost string, targetPort int, domains []string, aliases ...string) error {
	if err := os.MkdirAll(t.dynamicDir, 0755); err != nil {
		return fmt.Errorf("failed to create traefik dynamic config directory: %w", err)
	}

	cleanDomains := dedupeNonEmptyStrings(domains)
	targetURL := fmt.Sprintf("http://%s:%d", targetHost, targetPort)

	names := dedupeNonEmptyStrings(append([]string{service}, aliases...))
	candidates := make([]string, 0, len(names)*4)
	for _, name := range names {
		candidates = append(candidates,
			filepath.Join(t.dynamicDir, fmt.Sprintf("%s-%s.yml", stack, name)),
			filepath.Join(t.dynamicDir, fmt.Sprintf("%s-%s.yaml", stack, name)),
			filepath.Join(t.dynamicDir, fmt.Sprintf("%s.yml", name)),
			filepath.Join(t.dynamicDir, fmt.Sprintf("%s.yaml", name)),
		)
	}

	for _, p := range candidates {
		if updated, err := updateTraefikRouteFileURL(p, targetURL, cleanDomains...); err == nil && updated {
			// Clean up any stray fallback route file previously written in parent dir when dynamicDir ends with /routes
			if filepath.Base(t.dynamicDir) == "routes" {
				_ = os.Remove(filepath.Join(filepath.Dir(t.dynamicDir), fmt.Sprintf("%s-%s.yaml", stack, service)))
			}
			return nil
		}
	}

	// Fallback: scan existing dynamic route files for matching Host(`domain`) rule
	if len(cleanDomains) > 0 {
		if entries, err := os.ReadDir(t.dynamicDir); err == nil {
			for _, entry := range entries {
				if entry.IsDir() {
					continue
				}
				name := entry.Name()
				if !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml") {
					continue
				}
				fullPath := filepath.Join(t.dynamicDir, name)
				data, err := os.ReadFile(fullPath)
				if err != nil {
					continue
				}
				text := string(data)
				matched := false
				for _, d := range cleanDomains {
					if strings.Contains(text, d) {
						matched = true
						break
					}
				}
				if matched {
					if updated, err := updateTraefikRouteFileURL(fullPath, targetURL, cleanDomains...); err == nil && updated {
						return nil
					}
				}
			}
		}
	}

	// Fall back to generating clean Traefik router config pointing directly at targetHost:targetPort
	if len(cleanDomains) == 0 {
		return fmt.Errorf("cannot create Traefik route for %s-%s: domain is empty", stack, service)
	}
	if targetHost != "" && targetHost != "127.0.0.1" {
		return t.flipRouteURLWithDomains(fmt.Sprintf("%s-%s", stack, service), cleanDomains, targetURL)
	}
	return t.FlipRouteWithDomains(fmt.Sprintf("%s-%s", stack, service), cleanDomains, targetPort)
}

func ensureDomainsInTraefikRule(content string, domains []string) string {
	missing := make([]string, 0, len(domains))
	for _, d := range dedupeNonEmptyStrings(domains) {
		if !strings.Contains(content, d) {
			missing = append(missing, fmt.Sprintf("Host(`%s`)", d))
		}
	}
	if len(missing) == 0 {
		return content
	}
	loc := traefikRuleLineRe.FindStringSubmatchIndex(content)
	if loc == nil {
		return content
	}
	prefix := content[loc[2]:loc[3]]
	openQuote := content[loc[4]:loc[5]]
	expr := strings.TrimSpace(content[loc[6]:loc[7]])
	closeQuote := content[loc[8]:loc[9]]

	if openQuote == "" {
		openQuote = `"`
		closeQuote = `"`
	}
	if strings.Contains(expr, "&&") {
		expr = fmt.Sprintf("(%s)", expr)
	}
	updatedLine := fmt.Sprintf("%s%s%s || %s%s", prefix, openQuote, expr, strings.Join(missing, " || "), closeQuote)
	return content[:loc[0]] + updatedLine + content[loc[1]:]
}

func updateTraefikRouteFileURL(path, targetURL string, requiredDomains ...string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	content := string(data)
	if !traefikUpstreamURLRe.MatchString(content) {
		return false, nil
	}
	updated := traefikUpstreamURLRe.ReplaceAllString(content, fmt.Sprintf("url: %s", targetURL))
	if len(requiredDomains) > 0 {
		updated = ensureDomainsInTraefikRule(updated, requiredDomains)
	}
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, []byte(updated), 0644); err != nil {
		return false, err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return false, err
	}
	return true, nil
}

func (t *TraefikRouteFlipper) detectDefaultEntryPoint() string {
	entries, err := os.ReadDir(t.dynamicDir)
	if err != nil {
		return "websecure"
	}
	sawWeb := false
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(t.dynamicDir, name))
		if err != nil {
			continue
		}
		text := string(data)
		if strings.Contains(text, "websecure") {
			return "websecure"
		}
		if strings.Contains(text, "- web") || strings.Contains(text, `- "web"`) {
			sawWeb = true
		}
	}
	if sawWeb {
		return "web"
	}
	return "websecure"
}

// FlipRoute atomically points Traefik domain traffic to the target host port on loopback
func (t *TraefikRouteFlipper) FlipRoute(service, domain string, targetPort int) error {
	return t.FlipRouteWithDomains(service, []string{domain}, targetPort)
}

// FlipRouteWithDomains atomically points one or more Traefik domains to the target host port on loopback
func (t *TraefikRouteFlipper) FlipRouteWithDomains(service string, domains []string, targetPort int) error {
	return t.flipRouteURLWithDomains(service, domains, fmt.Sprintf("http://127.0.0.1:%d", targetPort))
}

func (t *TraefikRouteFlipper) flipRouteURL(service, domain, upstreamURL string) error {
	return t.flipRouteURLWithDomains(service, []string{domain}, upstreamURL)
}

func (t *TraefikRouteFlipper) flipRouteURLWithDomains(service string, domains []string, upstreamURL string) error {
	rule := FormatHostRule(domains...)
	if rule == "" {
		return fmt.Errorf("cannot flip Traefik route for %s: domain is empty", service)
	}
	if err := os.MkdirAll(t.dynamicDir, 0755); err != nil {
		return fmt.Errorf("failed to create traefik dynamic config directory: %w", err)
	}

	entryPoint := t.detectDefaultEntryPoint()

	content := fmt.Sprintf(`http:
  routers:
    %s-router:
      rule: %q
      service: "%s-svc"
      entryPoints:
        - %q
  services:
    %s-svc:
      loadBalancer:
        servers:
          - url: %q
`, service, rule, service, entryPoint, service, upstreamURL)

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
	return t.SetCanaryRouteWithDomains(service, []string{domain}, activePort, candidatePort, candidateWeight)
}

// SetCanaryRouteWithDomains sets up Traefik weighted round-robin splitting across one or more domains
func (t *TraefikRouteFlipper) SetCanaryRouteWithDomains(service string, domains []string, activePort, candidatePort int, candidateWeight int) error {
	if candidateWeight <= 0 {
		return t.FlipRouteWithDomains(service, domains, activePort)
	}
	if candidateWeight >= 100 {
		return t.FlipRouteWithDomains(service, domains, candidatePort)
	}

	rule := FormatHostRule(domains...)
	if rule == "" {
		return fmt.Errorf("cannot set canary route for %s: domain is empty", service)
	}

	activeWeight := 100 - candidateWeight

	if err := os.MkdirAll(t.dynamicDir, 0755); err != nil {
		return fmt.Errorf("failed to create traefik dynamic config directory: %w", err)
	}

	entryPoint := t.detectDefaultEntryPoint()

	content := fmt.Sprintf(`http:
  routers:
    %s-router:
      rule: %q
      service: "%s-wrr"
      entryPoints:
        - %q
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
`, service, rule, service, entryPoint, service, service, activeWeight, service, candidateWeight, service, activePort, service, candidatePort)

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
