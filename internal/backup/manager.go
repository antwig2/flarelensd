package backup

import (
	"cmp"
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/antwig2/flarelens/internal/config"
	"github.com/antwig2/flarelens/internal/transport"
)

// BackupMetadata describes an uploaded database snapshot
type BackupMetadata struct {
	Key       string    `json:"key"`
	Bucket    string    `json:"bucket"`
	Timestamp time.Time `json:"timestamp"`
	Tag       string    `json:"tag"`
	NodeID    string    `json:"node_id"`
	Service   string    `json:"service"`
	Database  string    `json:"database,omitempty"`
}

// BackupTriggerRequest represents on-demand backup trigger payload
type BackupTriggerRequest struct {
	Tag string `json:"tag"`
}

// RestoreTriggerRequest represents database restore payload
type RestoreTriggerRequest struct {
	Key      string `json:"key"`
	TargetDB string `json:"target_db"`
}

// Manager coordinates zero-disk database backups to Cloudflare R2 and automated cron schedules
type Manager struct {
	dumper     *PostgresDumper
	r2Client   *R2Client
	natsClient *transport.NATSClient
	cfg        *config.Config
	logger     *slog.Logger
	mu         sync.Mutex
}

func NewManager(
	dumper *PostgresDumper,
	r2Client *R2Client,
	natsClient *transport.NATSClient,
	cfg *config.Config,
	logger *slog.Logger,
) *Manager {
	if logger == nil {
		logger = slog.Default()
	}
	return &Manager{
		dumper:     dumper,
		r2Client:   r2Client,
		natsClient: natsClient,
		cfg:        cfg,
		logger:     logger,
	}
}

// CreateBackup streams a pg_dump to Cloudflare R2 using the default database
func (m *Manager) CreateBackup(ctx context.Context, tag string, targetKey ...string) (*BackupMetadata, error) {
	return m.CreateBackupForDB(ctx, tag, "", targetKey...)
}

// CreateBackupForDB streams a pg_dump to Cloudflare R2 for a specific target database
func (m *Manager) CreateBackupForDB(ctx context.Context, tag, targetDB string, targetKey ...string) (*BackupMetadata, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	bucket := m.cfg.Database.Backup.R2Bucket
	if bucket == "" {
		bucket = "flarelens-backups"
	}

	prefix := cmp.Or(m.cfg.Database.Backup.Prefix, "postgres/prod")
	now := time.Now().UTC()
	safeTag := cmp.Or(tag, "scheduled")

	if targetDB == "" {
		targetDB = m.cfg.Database.Database
	}

	key := fmt.Sprintf("%s/%s_%s.sql.gz", prefix, now.Format("20060102-150405"), safeTag)
	if len(targetKey) > 0 && targetKey[0] != "" {
		key = targetKey[0]
	}

	m.logger.Info("Starting zero-disk streaming backup to Cloudflare R2",
		"bucket", bucket,
		"key", key,
		"tag", safeTag,
		"database", targetDB,
	)

	stream, err := m.dumper.StreamDumpDB(ctx, targetDB)
	if err != nil {
		return nil, fmt.Errorf("failed to initiate pg_dump stream: %w", err)
	}
	defer stream.Close()

	if err := m.r2Client.PutObject(ctx, bucket, key, stream, -1, "application/gzip"); err != nil {
		m.logger.Error("Failed to upload database snapshot to R2", "error", err)
		return nil, err
	}

	meta := &BackupMetadata{
		Key:       key,
		Bucket:    bucket,
		Timestamp: now,
		Tag:       safeTag,
		NodeID:    m.cfg.Identity.NodeID,
		Service:   m.cfg.Database.ServiceName,
		Database:  targetDB,
	}

	m.logger.Info("Database snapshot uploaded successfully to Cloudflare R2",
		"key", key,
		"bucket", bucket,
		"database", targetDB,
	)

	// Broadcast backup completion event via NATS
	if m.natsClient != nil && m.natsClient.IsConnected() {
		subject := fmt.Sprintf("flarelens.node.%s.backup.completed", m.cfg.Identity.NodeID)
		_ = m.natsClient.PublishJSON(subject, meta)
	}

	return meta, nil
}

// RestoreBackup streams a snapshot from R2 and applies it to target database
func (m *Manager) RestoreBackup(ctx context.Context, key, targetDB string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	bucket := cmp.Or(m.cfg.Database.Backup.R2Bucket, "flarelens-backups")

	m.logger.Info("Starting database restore from Cloudflare R2",
		"bucket", bucket,
		"key", key,
		"target_db", targetDB,
	)

	stream, err := m.r2Client.GetObject(ctx, bucket, key)
	if err != nil {
		return fmt.Errorf("failed to fetch snapshot from R2: %w", err)
	}
	defer stream.Close()

	if err := m.dumper.Restore(ctx, stream, targetDB); err != nil {
		return fmt.Errorf("failed to restore snapshot into database: %w", err)
	}

	m.logger.Info("Database restored successfully from R2 snapshot", "key", key)
	return nil
}

// ListBackups lists available R2 database snapshots
func (m *Manager) ListBackups(ctx context.Context) ([]S3Object, error) {
	bucket := cmp.Or(m.cfg.Database.Backup.R2Bucket, "flarelens-backups")
	prefix := cmp.Or(m.cfg.Database.Backup.Prefix, "postgres/")

	return m.r2Client.ListObjects(ctx, bucket, prefix)
}

// RestoreLatestMatchingTag finds the most recent snapshot matching the given tag and restores it
func (m *Manager) RestoreLatestMatchingTag(ctx context.Context, tag, targetDB string) error {
	objs, err := m.ListBackups(ctx)
	if err != nil {
		return fmt.Errorf("failed to list snapshots for rollback: %w", err)
	}

	for i := len(objs) - 1; i >= 0; i-- {
		if strings.Contains(objs[i].Key, tag) {
			m.logger.Info("Found matching snapshot for automated rollback",
				"key", objs[i].Key,
				"tag", tag,
			)
			return m.RestoreBackup(ctx, objs[i].Key, targetDB)
		}
	}

	return fmt.Errorf("no snapshot found matching tag: %s", tag)
}

// StartCron launches periodic backup schedule (daily at 02:00 UTC)
func (m *Manager) StartCron(ctx context.Context) {
	if !m.cfg.Database.Backup.Enabled {
		return
	}

	m.logger.Info("Starting automated database backup scheduler",
		"schedule", m.cfg.Database.Backup.Schedule,
		"bucket", m.cfg.Database.Backup.R2Bucket,
	)

	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				now := time.Now().UTC()
				// Run daily at 02:00 UTC
				if now.Hour() == 2 {
					backupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
					_, _ = m.CreateBackup(backupCtx, "daily")
					cancel()
				}
			}
		}
	}()
}
