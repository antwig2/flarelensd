package backup

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os/exec"
	"strconv"
)

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
		cmd = exec.CommandContext(ctx, "docker", "exec", "-i", d.serviceName, "pg_dump", "-U", d.user, targetDB)
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
		cmd = exec.CommandContext(ctx, "docker", "exec", "-i", d.serviceName, "psql", "-U", d.user, targetDB)
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
