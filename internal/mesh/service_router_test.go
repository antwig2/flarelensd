package mesh

import (
	"context"
	"io"
	"net"
	"slices"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

func TestServiceRouterExtraHostsAndRemoteUpstreams(t *testing.T) {
	router := NewServiceRouter("node-2", nil, nil)
	router.UpdateEndpoints("100.64.0.2", []ClusterEndpoint{
		{
			Env:           "prod",
			Service:       "postgres",
			Mode:          "singleton",
			NodeID:        "node-1",
			MeshIP:        "100.64.0.1",
			MeshPort:      5432,
			ContainerPort: 5432,
			ContainerName: "postgres-prod",
			Aliases:       []string{"db-primary"},
			Healthy:       true,
		},
		{
			Env:           "prod",
			Service:       "dragonfly",
			Mode:          "singleton",
			NodeID:        "node-1",
			MeshIP:        "100.64.0.1",
			MeshPort:      6379,
			ContainerPort: 6379,
			Healthy:       true,
		},
		{
			Env:        "prod",
			Service:    "checkout-api",
			Mode:       "blue_green",
			NodeID:     "node-1",
			MeshIP:     "100.64.0.1",
			MeshPort:   28080,
			Domains:    []string{"api.example.com"},
			HealthPath: "/health",
			Healthy:    true,
		},
		{
			Env:        "prod",
			Service:    "checkout-api",
			Mode:       "blue_green",
			NodeID:     "node-2",
			MeshIP:     "100.64.0.2",
			MeshPort:   28080,
			Domains:    []string{"api.example.com"},
			HealthPath: "/health",
			Healthy:    true,
		},
		{
			Env:        "prod",
			Service:    "checkout-api",
			Mode:       "blue_green",
			NodeID:     "node-3",
			MeshIP:     "100.64.0.3",
			MeshPort:   28080,
			Domains:    []string{"api.example.com"},
			HealthPath: "/health",
			Healthy:    false, // Unhealthy replica must not be included in Traefik upstreams
		},
	})

	extraHosts := router.ExtraHostsForEnv("prod")
	for _, want := range []string{
		"postgres:100.64.0.1",
		"postgres-prod:100.64.0.1",
		"db-primary:100.64.0.1",
		"dragonfly:100.64.0.1",
		"redis:100.64.0.1",
		"redis-prod:100.64.0.1",
	} {
		if !slices.Contains(extraHosts, want) {
			t.Fatalf("expected ExtraHosts %v to contain %q", extraHosts, want)
		}
	}
	// checkout-api runs locally on node-2 too, so local Docker bridge alias must NOT be shadowed by ExtraHosts
	for _, entry := range extraHosts {
		if entry == "checkout-api:100.64.0.1" {
			t.Fatalf("expected local service checkout-api not to be shadowed in ExtraHosts, got %v", extraHosts)
		}
	}

	remoteURLs := router.RemoteUpstreamURLs("prod", "checkout-api")
	wantRemote := []string{"http://100.64.0.1:28080"}
	if !slices.Equal(remoteURLs, wantRemote) {
		t.Fatalf("expected RemoteUpstreamURLs=%v, got %v", wantRemote, remoteURLs)
	}
}

func TestServiceRouterTCPForwarderDynamicSlotFlipAndCleanup(t *testing.T) {
	ctx := t.Context()

	// Start two mock local backend containers ("blue" and "green")
	blueLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen blue: %v", err)
	}
	defer blueLn.Close()

	greenLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen green: %v", err)
	}
	defer greenLn.Close()

	serveBanner := func(ln net.Listener, banner string) {
		for {
			c, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = conn.Write([]byte(banner))
			}(c)
		}
	}
	go serveBanner(blueLn, "slot=blue")
	go serveBanner(greenLn, "slot=green")

	// Reserve a free local port to simulate the WireGuard mesh port
	probeLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probe port: %v", err)
	}
	meshPort := probeLn.Addr().(*net.TCPAddr).Port
	_ = probeLn.Close()

	var activeTarget atomic.Pointer[string]
	activeTarget.Store(new(blueLn.Addr().String()))
	router := NewServiceRouter("node-1", func(_ context.Context, _ ClusterEndpoint) (string, error) {
		return *activeTarget.Load(), nil
	}, nil)
	defer router.Close()

	router.UpdateEndpoints("127.0.0.1", []ClusterEndpoint{
		{
			Env:      "prod",
			Service:  "checkout-api",
			Mode:     "blue_green",
			NodeID:   "node-1",
			MeshIP:   "127.0.0.1",
			MeshPort: meshPort,
			Healthy:  true,
		},
	})

	dialAndRead := func() string {
		t.Helper()
		var d net.Dialer
		dialCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		conn, dialErr := d.DialContext(dialCtx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(meshPort)))
		if dialErr != nil {
			t.Fatalf("dial mesh forwarder: %v", dialErr)
		}
		defer conn.Close()
		raw, readErr := io.ReadAll(conn)
		if readErr != nil {
			t.Fatalf("read mesh forwarder: %v", readErr)
		}
		return string(raw)
	}

	if got := dialAndRead(); got != "slot=blue" {
		t.Fatalf("expected slot=blue, got %q", got)
	}

	// Simulate Blue -> Green cutover without changing the WireGuard mesh port!
	activeTarget.Store(new(greenLn.Addr().String()))
	if got := dialAndRead(); got != "slot=green" {
		t.Fatalf("expected slot=green after dynamic target switch, got %q", got)
	}

	// Evict service from node-1 -> listener must close immediately
	router.UpdateEndpoints("127.0.0.1", nil)
	if addrs := router.ActiveListenerAddrs(); len(addrs) != 0 {
		t.Fatalf("expected 0 active mesh listeners after eviction, got %v", addrs)
	}
}
