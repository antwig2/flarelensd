package deploy

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func buildDockerLogFrame(streamType byte, msg string) []byte {
	var out bytes.Buffer
	var hdr [8]byte
	hdr[0] = streamType
	binary.BigEndian.PutUint32(hdr[4:], uint32(len(msg)))
	out.Write(hdr[:])
	out.WriteString(msg)
	return out.Bytes()
}

func TestResolveServiceContainerAndStreamLogSession(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "docker.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen unix socket: %v", err)
	}
	defer ln.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/containers/json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{
				"Id":    "aaaa1111bbbb2222cccc3333",
				"Names": []string{"/app-uat-postgres"},
				"Image": "postgres:18",
				"State": "running",
			},
			{
				"Id":    "dddd4444eeee5555ffff6666",
				"Names": []string{"/app-prod-postgres"},
				"Image": "postgres:18",
				"State": "running",
			},
			{
				"Id":    "7777888899990000aaaabbbb",
				"Names": []string{"/checkout-api-blue"},
				"Image": "ghcr.io/example/checkout:1.0",
				"State": "running",
				"Labels": map[string]string{
					"flarelens.service": "checkout-api",
					"flarelens.env":     "uat",
					"flarelens.slot":    "blue",
				},
			},
			{
				"Id":    "ccccddddeeeeffff11112222",
				"Names": []string{"/checkout-api-green"},
				"Image": "ghcr.io/example/checkout:1.1",
				"State": "running",
				"Labels": map[string]string{
					"flarelens.service": "checkout-api",
					"flarelens.env":     "uat",
					"flarelens.slot":    "green",
				},
			},
		})
	})

	mux.HandleFunc("/containers/ccccddddeeeeffff11112222/logs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.docker.raw-stream")
		flusher, _ := w.(http.Flusher)
		_, _ = w.Write(buildDockerLogFrame(1, "2026-11-28T06:00:00Z INFO server listening on :8080\n"))
		if flusher != nil {
			flusher.Flush()
		}
		if r.URL.Query().Get("follow") == "true" {
			time.Sleep(80 * time.Millisecond)
			_, _ = w.Write(buildDockerLogFrame(2, "2026-11-28T06:00:01Z WARN slow query 142ms\n"))
			if flusher != nil {
				flusher.Flush()
			}
			// Wait until viewer stops session
			<-r.Context().Done()
		}
	})

	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	runner := NewDockerRunner(sockPath)
	orch := NewOrchestrator(runner, NewHealthProber(), NewTraefikRouteFlipper(t.TempDir()), nil, "node-test-1", nil)
	orch.mu.Lock()
	orch.activeSlots["checkout-api"] = SlotGreen
	orch.mu.Unlock()

	// 1. Multi-env singleton resolution (`uat/postgres` vs `prod/postgres`)
	uatID, uatName, err := orch.ResolveServiceContainer(t.Context(), "uat", "postgres")
	if err != nil || uatID != "aaaa1111bbbb2222cccc3333" || uatName != "app-uat-postgres" {
		t.Fatalf("expected uat postgres container, got id=%q name=%q err=%v", uatID, uatName, err)
	}
	prodID, prodName, err := orch.ResolveServiceContainer(t.Context(), "prod", "postgres")
	if err != nil || prodID != "dddd4444eeee5555ffff6666" || prodName != "app-prod-postgres" {
		t.Fatalf("expected prod postgres container, got id=%q name=%q err=%v", prodID, prodName, err)
	}

	// 2. Active Blue/Green slot resolution + live follow stream + viewer stop cancellation
	var mu sync.Mutex
	var received []ContainerLogPushPayload
	orch.StreamContainerLogSession(t.Context(), ContainerLogStreamRequest{
		SessionID:       "lsess_1",
		Env:             "uat",
		Service:         "checkout-api",
		TailLines:       100,
		Follow:          true,
		DurationSeconds: 10,
	}, func(p ContainerLogPushPayload) (bool, error) {
		mu.Lock()
		received = append(received, p)
		var combined strings.Builder
		for _, item := range received {
			combined.WriteString(item.Chunk)
		}
		hasBoth := strings.Contains(combined.String(), "server listening on :8080") &&
			strings.Contains(combined.String(), "slow query 142ms")
		mu.Unlock()
		return hasBoth, nil // Signal viewer closed modal once both lines arrived
	})

	mu.Lock()
	defer mu.Unlock()
	if len(received) == 0 {
		t.Fatal("expected pushed log chunks")
	}
	if received[0].ContainerName != "checkout-api-green" {
		t.Fatalf("expected active green slot container, got %q", received[0].ContainerName)
	}
	if !received[len(received)-1].EOF {
		t.Fatal("expected final payload to carry EOF=true")
	}
}
