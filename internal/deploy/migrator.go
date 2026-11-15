package deploy

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
)

// MigrationRunner executes isolated database migrations inside an ephemeral container
type MigrationRunner struct {
	logger *slog.Logger
}

func NewMigrationRunner(logger *slog.Logger) *MigrationRunner {
	if logger == nil {
		logger = slog.Default()
	}
	return &MigrationRunner{logger: logger}
}

// Run executes a database migration command inside an ephemeral container with in-memory secrets and optional read-only volume binds
func (m *MigrationRunner) Run(
	ctx context.Context,
	image string,
	command string,
	envVars []string,
	network string,
	binds ...string,
) (string, error) {
	return m.RunWithExtraHosts(ctx, image, command, envVars, network, nil, binds...)
}

// RunWithExtraHosts executes a database migration command with cross-node WireGuard ExtraHosts (--add-host) injected.
func (m *MigrationRunner) RunWithExtraHosts(
	ctx context.Context,
	image string,
	command string,
	envVars []string,
	network string,
	extraHosts []string,
	binds ...string,
) (string, error) {
	return m.RunWithNetworkOptions(ctx, image, command, envVars, network, extraHosts, nil, nil, binds...)
}

// RunWithNetworkOptions executes a database migration command inside an ephemeral container with dynamic mesh DNS and/or ExtraHosts.
func (m *MigrationRunner) RunWithNetworkOptions(
	ctx context.Context,
	image string,
	command string,
	envVars []string,
	network string,
	extraHosts []string,
	dnsServers []string,
	dnsSearch []string,
	binds ...string,
) (string, error) {
	if command == "" {
		command = "migrate up"
	}

	cmdArgs := []string{"run", "--rm"}
	if network != "" {
		cmdArgs = append(cmdArgs, "--network", network)
	}

	if network != "host" && network != "none" {
		for _, srv := range dnsServers {
			if trimmed := strings.TrimSpace(srv); trimmed != "" {
				cmdArgs = append(cmdArgs, "--dns", trimmed)
			}
		}
		for _, dom := range dnsSearch {
			if trimmed := strings.TrimSpace(dom); trimmed != "" {
				cmdArgs = append(cmdArgs, "--dns-search", trimmed)
			}
		}
	}

	for _, hostMap := range extraHosts {
		if trimmed := strings.TrimSpace(hostMap); trimmed != "" {
			cmdArgs = append(cmdArgs, "--add-host", trimmed)
		}
	}

	for _, b := range binds {
		if strings.TrimSpace(b) != "" {
			cmdArgs = append(cmdArgs, "-v", b)
		}
	}

	// Inject in-memory environment secrets
	for _, env := range envVars {
		cmdArgs = append(cmdArgs, "-e", env)
	}

	parts := strings.Fields(command)
	if len(parts) > 0 && strings.HasPrefix(parts[0], "/") {
		cmdArgs = append(cmdArgs, "--entrypoint", parts[0], image)
		cmdArgs = append(cmdArgs, parts[1:]...)
	} else {
		cmdArgs = append(cmdArgs, image)
		cmdArgs = append(cmdArgs, parts...)
	}

	m.logger.Info("Executing database migration in ephemeral container",
		"image", image,
		"command", command,
		"network", network,
	)

	cmd := exec.CommandContext(ctx, "docker", cmdArgs...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	output := strings.TrimSpace(stdout.String())
	errOut := strings.TrimSpace(stderr.String())
	if errOut != "" {
		if output != "" {
			output += "\n"
		}
		output += errOut
	}

	if err != nil {
		m.logger.Error("Database migration failed",
			"error", err,
			"output", output,
		)
		return output, fmt.Errorf("migration command failed (%w): %s", err, output)
	}

	m.logger.Info("Database migration completed successfully", "output", output)
	return output, nil
}
