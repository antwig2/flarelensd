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

// Run executes a database migration command inside an ephemeral container with in-memory secrets
func (m *MigrationRunner) Run(
	ctx context.Context,
	image string,
	command string,
	envVars []string,
	network string,
) (string, error) {
	if command == "" {
		command = "migrate up"
	}

	cmdArgs := []string{"run", "--rm"}
	if network != "" {
		cmdArgs = append(cmdArgs, "--network", network)
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
