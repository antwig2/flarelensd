package transport

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

// NATSClient manages connection and subscriptions to the NATS event fabric,
// supporting both external brokers and embedded in-process servers.
type NATSClient struct {
	nc       *nats.Conn
	embedded *natsserver.Server
	url      string
	token    string
	logger   *slog.Logger
	mu       sync.RWMutex
	subs     []*nats.Subscription
}

// EmbeddedOptions defines configuration for in-process embedded NATS
type EmbeddedOptions struct {
	DontListen bool   // If true, operates entirely in-memory with zero open TCP ports via net.Pipe
	Port       int    // Optional TCP listener port (e.g. 4222)
	WSPort     int    // Optional WebSocket listener port (e.g. 8080) for Cloudflare Tunnel
	AuthToken  string // Shared token or NKey
}

// NewNATSClient creates a new NATS client manager
func NewNATSClient(url, token string, logger *slog.Logger) *NATSClient {
	if logger == nil {
		logger = slog.Default()
	}
	return &NATSClient{
		url:    url,
		token:  token,
		logger: logger,
	}
}

// StartEmbedded launches an embedded NATS server in-process and connects via in-memory pipe.
// As detailed in https://gosuda.org/blog/posts/how-embedded-nats-communicate-with-go-application-z36089af0,
// setting DontListen: true bypasses the TCP AcceptLoop and nats.InProcessServer(ns) provides zero-hop communication.
func (c *NATSClient) StartEmbedded(ctx context.Context, embedOpts EmbeddedOptions) error {
	opts := &natsserver.Options{
		ServerName: "flarelens-embedded",
		DontListen: embedOpts.DontListen,
	}

	if embedOpts.Port > 0 && !embedOpts.DontListen {
		opts.Port = embedOpts.Port
	}
	if embedOpts.WSPort > 0 && !embedOpts.DontListen {
		opts.Websocket.Port = embedOpts.WSPort
		opts.Websocket.NoTLS = true // Handled upstream by Cloudflare Tunnel / Traefik
	}
	if embedOpts.AuthToken != "" {
		opts.Authorization = embedOpts.AuthToken
	}

	ns, err := natsserver.NewServer(opts)
	if err != nil {
		return fmt.Errorf("failed to initialize embedded NATS server: %w", err)
	}

	// Start server in background goroutine
	go ns.Start()

	// Wait for server to be ready for connections (up to 10s)
	if !ns.ReadyForConnections(10 * time.Second) {
		ns.Shutdown()
		return fmt.Errorf("embedded NATS server failed to become ready within 10s")
	}

	// Connect client to embedded server via InProcessServer option (in-memory net.Pipe)
	clientOpts := []nats.Option{
		nats.Name("flarelens-agent-inproc"),
		nats.InProcessServer(ns),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(1 * time.Second),
	}
	if embedOpts.AuthToken != "" {
		clientOpts = append(clientOpts, nats.Token(embedOpts.AuthToken))
	}

	nc, err := nats.Connect(ns.ClientURL(), clientOpts...)
	if err != nil {
		ns.Shutdown()
		return fmt.Errorf("failed to connect in-process client to embedded NATS: %w", err)
	}

	c.mu.Lock()
	c.embedded = ns
	c.nc = nc
	c.mu.Unlock()

	c.logger.Info("Embedded NATS server started successfully",
		"in_process", true,
		"dont_listen", embedOpts.DontListen,
		"tcp_port", opts.Port,
		"ws_port", opts.Websocket.Port,
	)
	return nil
}

// Connect establishes connection to a remote/external NATS server
func (c *NATSClient) Connect(ctx context.Context) error {
	opts := []nats.Option{
		nats.Name("flarelens-agent"),
		nats.MaxReconnects(-1), // Reconnect indefinitely
		nats.ReconnectWait(2 * time.Second),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			if err != nil {
				c.logger.Warn("NATS disconnected", "error", err)
			}
		}),
		nats.ReconnectHandler(func(nc *nats.Conn) {
			c.logger.Info("NATS reconnected", "server", nc.ConnectedUrl())
		}),
		nats.ClosedHandler(func(nc *nats.Conn) {
			c.logger.Warn("NATS connection closed")
		}),
	}

	if c.token != "" {
		opts = append(opts, nats.Token(c.token))
	}

	nc, err := nats.Connect(c.url, opts...)
	if err != nil {
		return fmt.Errorf("failed to connect to NATS at %s: %w", c.url, err)
	}

	c.mu.Lock()
	c.nc = nc
	c.mu.Unlock()

	c.logger.Info("NATS transport connected", "url", nc.ConnectedUrl())
	return nil
}

// IsConnected returns whether the NATS connection is active
func (c *NATSClient) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.nc != nil && c.nc.IsConnected()
}

// PublishJSON serializes data as JSON and publishes to the subject
func (c *NATSClient) PublishJSON(subject string, v any) error {
	c.mu.RLock()
	nc := c.nc
	c.mu.RUnlock()

	if nc == nil || !nc.IsConnected() {
		return fmt.Errorf("nats is not connected")
	}

	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("failed to marshal payload for %s: %w", subject, err)
	}

	return nc.Publish(subject, data)
}

// Subscribe listens for messages on the specified subject
func (c *NATSClient) Subscribe(subject string, handler func(msg *nats.Msg)) (*nats.Subscription, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.nc == nil {
		return nil, fmt.Errorf("nats is not connected")
	}

	sub, err := c.nc.Subscribe(subject, handler)
	if err != nil {
		return nil, err
	}

	c.subs = append(c.subs, sub)
	c.logger.Debug("Subscribed to NATS subject", "subject", subject)
	return sub, nil
}

// Close gracefully shuts down subscriptions, client connection, and embedded server
func (c *NATSClient) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, sub := range c.subs {
		_ = sub.Unsubscribe()
	}
	clear(c.subs)
	c.subs = nil

	if c.nc != nil {
		_ = c.nc.Drain()
		c.nc.Close()
		c.nc = nil
	}

	if c.embedded != nil {
		c.logger.Info("Shutting down embedded NATS server")
		c.embedded.Shutdown()
		c.embedded.WaitForShutdown()
		c.embedded = nil
	}
}
