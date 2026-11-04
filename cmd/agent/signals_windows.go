//go:build windows

package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func waitForShutdown(cancel context.CancelFunc, logger *slog.Logger, onReload func()) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	sig := <-sigChan
	logger.Info("Received shutdown signal, terminating gracefully...", "signal", sig.String())
	cancel()
	time.Sleep(500 * time.Millisecond)
	logger.Info("FlareLens Agent stopped")
}
