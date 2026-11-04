package transport

import (
	"context"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

func TestEmbeddedNATSInProcess(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	client := NewNATSClient("", "", logger)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 1. Launch in-process embedded NATS with DontListen: true
	err := client.StartEmbedded(ctx, EmbeddedOptions{
		DontListen: true, // Zero TCP ports opened; pure in-memory net.Pipe
	})
	if err != nil {
		t.Fatalf("Failed to start embedded NATS: %v", err)
	}
	defer client.Close()

	if !client.IsConnected() {
		t.Fatalf("Expected NATS client to be connected via in-process pipe")
	}

	// 2. Test pub/sub in-process
	subject := "flarelens.node.test-node.telemetry"
	received := make(chan string, 1)

	var wg sync.WaitGroup
	wg.Add(1)

	_, err = client.Subscribe(subject, func(msg *nats.Msg) {
		received <- string(msg.Data)
		wg.Done()
	})
	if err != nil {
		t.Fatalf("Failed to subscribe: %v", err)
	}

	payload := map[string]string{
		"node_id": "test-node",
		"status":  "Healthy",
	}

	if err := client.PublishJSON(subject, payload); err != nil {
		t.Fatalf("Failed to publish JSON: %v", err)
	}

	select {
	case data := <-received:
		if data == "" {
			t.Errorf("Expected non-empty payload received")
		}
		t.Logf("Successfully received in-process message: %s", data)
	case <-time.After(3 * time.Second):
		t.Fatalf("Timed out waiting for in-process NATS message")
	}
}
