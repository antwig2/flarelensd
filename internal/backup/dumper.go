package backup

import (
	"cmp"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os/exec"
	"slices"
	"strconv"
	"strings"
)

type deployEnvContextKey struct{}
type containerOverrideContextKey struct{}

// WithContainerName attaches an explicit database container name override (e.g. from manifest `container_name`) to ctx.
func WithContainerName(ctx context.Context, containerName string) context.Context {
	trimmed := strings.TrimSpace(containerName)
	if trimmed == "" {
		return ctx
	}
	return context.WithValue(ctx, containerOverrideContextKey{}, trimmed)
}

// ContainerNameFromContext retrieves an optional explicit container name override from ctx.
func ContainerNameFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(containerOverrideContextKey{}).(string); ok {
		return v
	}
	return ""
}

// WithDeployEnv attaches an optional deployment environment hint (e.g. "uat", "prod") to ctx
// so multi-environment hosts resolve the matching database container automatically.
func WithDeployEnv(ctx context.Context, envName string) context.Context {
	trimmed := strings.ToLower(strings.TrimSpace(envName))
	if trimmed == "production" {
		trimmed = "prod"
	}
	if trimmed == "" {
		return ctx
	}
	return context.WithValue(ctx, deployEnvContextKey{}, trimmed)
}

// DeployEnvFromContext retrieves an optional deployment environment hint from ctx.
func DeployEnvFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(deployEnvContextKey{}).(string); ok {
		return v
	}
	return ""
}

// PostgresDumper handles zero-disk streaming pg_dump and psql restore
type PostgresDumper struct {
	mode        string // "container" or "host_native"
	serviceName string // container name if container mode
	host        string
	port        int
	user        string
	database    string
}

func NewPostgresDumper(mode, serviceName, host string, port int, user, database string) *PostgresDumper {
	if user == "" {
		user = "postgres"
	}
	if database == "" {
		database = "postgres"
	}
	if port <= 0 {
		port = 5432
	}
	return &PostgresDumper{
		mode:        mode,
		serviceName: serviceName,
		host:        host,
		port:        port,
		user:        user,
		database:    database,
	}
}

// ResolveContainerCandidates returns prioritized Postgres container name candidates
// when multiple environments share a single host node.
func ResolveContainerCandidates(baseServiceName, envHint, targetDB string) []string {
	env := strings.ToLower(strings.TrimSpace(envHint))
	if env == "production" {
		env = "prod"
	}
	if env == "" {
		lowerDB := strings.ToLower(strings.TrimSpace(targetDB))
		for _, known := range []string{"prod", "uat", "staging", "dev"} {
			if strings.HasSuffix(lowerDB, "_"+known) || strings.HasSuffix(lowerDB, "-"+known) {
				env = known
				break
			}
		}
	}
	if env == "" {
		if baseServiceName != "" {
			return []string{baseServiceName}
		}
		return nil
	}

	candidates := make([]string, 0, 4)
	addUnique := func(name string) {
		if name != "" && !slices.Contains(candidates, name) {
			candidates = append(candidates, name)
		}
	}

	if baseServiceName != "" {
		swapped := swapEnvTokenInContainerName(baseServiceName, env)
		addUnique(swapped)
	}
	addUnique(fmt.Sprintf("postgres-%s", env))
	addUnique(fmt.Sprintf("%s-postgres", env))
	addUnique(baseServiceName)
	return candidates
}

func swapEnvTokenInContainerName(name, targetEnv string) string {
	for _, token := range []string{"uat", "prod", "production", "staging", "dev"} {
		mid := "-" + token + "-"
		if strings.Contains(name, mid) {
			return strings.Replace(name, mid, "-"+targetEnv+"-", 1)
		}
		if prefix, ok := strings.CutSuffix(name, "-"+token); ok {
			return prefix + "-" + targetEnv
		}
		if suffix, ok := strings.CutPrefix(name, token+"-"); ok {
			return targetEnv + "-" + suffix
		}
	}
	return name
}

func (d *PostgresDumper) resolveActiveContainer(ctx context.Context, targetDB string) string {
	if explicit := ContainerNameFromContext(ctx); explicit != "" {
		return explicit
	}
	envHint := DeployEnvFromContext(ctx)
	candidates := ResolveContainerCandidates(d.serviceName, envHint, targetDB)
	if len(candidates) <= 1 {
		return cmp.Or(d.serviceName, "postgres")
	}
	for _, c := range candidates {
		out, err := exec.CommandContext(ctx, "docker", "inspect", "-f", "{{.State.Running}}", c).Output()
		if err == nil && strings.TrimSpace(string(out)) == "true" {
			return c
		}
	}
	return d.serviceName
}

// StreamDump launches pg_dump and streams gzipped bytes through an io.PipeReader
func (d *PostgresDumper) StreamDump(ctx context.Context) (io.ReadCloser, error) {
	return d.StreamDumpDB(ctx, d.database)
}

// StreamDumpDB launches pg_dump for a target database and streams gzipped bytes through an io.PipeReader
func (d *PostgresDumper) StreamDumpDB(ctx context.Context, targetDB string) (io.ReadCloser, error) {
	if targetDB == "" {
		targetDB = d.database
	}
	var cmd *exec.Cmd

	if d.mode == "container" {
		container := d.resolveActiveContainer(ctx, targetDB)
		cmd = exec.CommandContext(ctx, "docker", "exec", "-i", container, "pg_dump", "-U", d.user, targetDB)
	} else {
		cmd = exec.CommandContext(ctx, "pg_dump", "-h", d.host, "-p", strconv.Itoa(d.port), "-U", d.user, targetDB)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to open pg_dump stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start pg_dump: %w", err)
	}

	pr, pw := io.Pipe()

	// Compress and pipe in background goroutine
	go func() {
		gw := gzip.NewWriter(pw)
		_, copyErr := io.Copy(gw, stdout)
		closeErr := gw.Close()

		waitErr := cmd.Wait()

		if copyErr != nil {
			_ = pw.CloseWithError(copyErr)
		} else if closeErr != nil {
			_ = pw.CloseWithError(closeErr)
		} else if waitErr != nil {
			_ = pw.CloseWithError(fmt.Errorf("pg_dump process failed: %w", waitErr))
		} else {
			_ = pw.Close()
		}
	}()

	return pr, nil
}

// Restore streams a gzipped SQL snapshot into psql
func (d *PostgresDumper) Restore(ctx context.Context, source io.Reader, targetDB string) error {
	if targetDB == "" {
		targetDB = d.database
	}

	gzReader, err := gzip.NewReader(source)
	if err != nil {
		return fmt.Errorf("failed to create gzip reader for restore: %w", err)
	}
	defer gzReader.Close()

	var cmd *exec.Cmd
	if d.mode == "container" {
		container := d.resolveActiveContainer(ctx, targetDB)
		cmd = exec.CommandContext(ctx, "docker", "exec", "-i", container, "psql", "-U", d.user, targetDB)
	} else {
		cmd = exec.CommandContext(ctx, "psql", "-h", d.host, "-p", strconv.Itoa(d.port), "-U", d.user, targetDB)
	}

	cmd.Stdin = gzReader

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("psql restore failed: %w (output: %s)", err, string(output))
	}

	return nil
}
