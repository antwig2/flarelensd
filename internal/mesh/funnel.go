package mesh

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// FunnelOptions configures `flarelensd http <port>` (Mesh + Traefik Funnel).
type FunnelOptions struct {
	LocalHost   string // Default: "127.0.0.1"
	LocalPort   int    // Required: e.g. 3000
	ListenIP    string // Defaults to MeshState.OverlayIP (e.g. "100.64.0.99")
	ListenPort  int    // Optional explicit mesh port (0 = ephemeral OS port)
	Subdomain   string // Optional requested subdomain (e.g. "billing-webhook")
	Domain      string // Optional full domain override (e.g. "dev-api.example.com")
	BasicAuth   string // Optional "username:password" Basic Auth guard
	HostHeader  string // "rewrite" (default: Host=localhost:<port>), "preserve", or explicit host string
	GatewayNode string // Optional target gateway node_id override
	ControlURL  string
	AuthToken   string
	PeerID      string
	PublicKey   string
	SSHKeyPath  string
	Quiet       bool
	Output      io.Writer
	HTTPClient  *http.Client
	Logger      *slog.Logger
}

// TunnelCreateResponse represents the Control Plane response from POST /api/v1/control/tunnels
type TunnelCreateResponse struct {
	Status string `json:"status"`
	Tunnel struct {
		TunnelID   string `json:"tunnel_id"`
		Domain     string `json:"domain"`
		PublicURL  string `json:"public_url"`
		NodeID     string `json:"node_id"`
		TargetIP   string `json:"target_ip"`
		TargetPort int    `json:"target_port"`
		LocalPort  int    `json:"local_port"`
		ExpiresAt  string `json:"expires_at"`
	} `json:"tunnel"`
	Error string `json:"error"`
}

// SignMeshTunnelProof signs "flarelens-mesh-tunnel:<action>:<wg_pub>:<ts>" using the peer's
// Ed25519 sovereign SSH keypair (~/.flarelens/id_ed25519) so workstation users can open/close
// tunnels without root or INGEST_SECRET after running `sudo flarelensd login`.
func SignMeshTunnelProof(sshPrivKeyPath, action, wgPublicKey, timestamp string) (string, error) {
	if strings.TrimSpace(sshPrivKeyPath) == "" || strings.TrimSpace(wgPublicKey) == "" {
		return "", errors.New("missing ssh private key path or wireguard public key")
	}
	pemBytes, err := os.ReadFile(sshPrivKeyPath)
	if err != nil {
		return "", err
	}
	rawKey, err := ssh.ParseRawPrivateKey(pemBytes)
	if err != nil {
		return "", err
	}

	var edKey ed25519.PrivateKey
	switch k := rawKey.(type) {
	case *ed25519.PrivateKey:
		edKey = *k
	case ed25519.PrivateKey:
		edKey = k
	default:
		return "", errors.New("ssh private key is not ed25519")
	}

	msg := fmt.Sprintf("flarelens-mesh-tunnel:%s:%s:%s",
		strings.TrimSpace(action),
		strings.TrimSpace(wgPublicKey),
		strings.TrimSpace(timestamp),
	)
	sig := ed25519.Sign(edKey, []byte(msg))
	return base64.StdEncoding.EncodeToString(sig), nil
}

// ParseFunnelTarget parses "3000", ":3000", "localhost:3000", or "http://127.0.0.1:8080" into (host, port).
func ParseFunnelTarget(raw string) (string, int, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", 0, errors.New("target port is required (e.g. flarelensd http 3000)")
	}
	if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
		u, err := url.Parse(s)
		if err != nil {
			return "", 0, fmt.Errorf("invalid target URL %q: %w", raw, err)
		}
		s = u.Host
	}
	if strings.HasPrefix(s, ":") {
		s = "127.0.0.1" + s
	}
	if !strings.Contains(s, ":") {
		port, err := strconv.Atoi(s)
		if err != nil || port < 1 || port > 65535 {
			return "", 0, fmt.Errorf("invalid port %q (must be 1..65535)", raw)
		}
		return "127.0.0.1", port, nil
	}
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return "", 0, fmt.Errorf("invalid host:port %q: %w", raw, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("invalid port %q (must be 1..65535)", portStr)
	}
	return cmp.Or(strings.TrimSpace(host), "127.0.0.1"), port, nil
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := r.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("underlying ResponseWriter does not support hijacking")
	}
	return hj.Hijack()
}

func (r *statusRecorder) Flush() {
	if fl, ok := r.ResponseWriter.(http.Flusher); ok {
		fl.Flush()
	}
}

// NewLocalFunnelHandler constructs an HTTP/WebSocket reverse proxy targeting http://<localHost>:<localPort>
// with optional constant-time Basic Auth, Host header rewriting, and live request logging.
func NewLocalFunnelHandler(
	localHost string,
	localPort int,
	basicAuth string,
	hostHeaderMode string,
	logOut io.Writer,
) (http.Handler, error) {
	targetURL, err := url.Parse(fmt.Sprintf("http://%s", net.JoinHostPort(cmp.Or(localHost, "127.0.0.1"), strconv.Itoa(localPort))))
	if err != nil {
		return nil, err
	}

	var wantUser, wantPass string
	hasAuth := false
	if trimmedAuth := strings.TrimSpace(basicAuth); trimmedAuth != "" {
		u, p, ok := strings.Cut(trimmedAuth, ":")
		if !ok || u == "" || p == "" {
			return nil, errors.New("--auth must be formatted as username:password")
		}
		wantUser, wantPass, hasAuth = u, p, true
	}

	rp := httputil.NewSingleHostReverseProxy(targetURL)
	baseDirector := rp.Director
	mode := strings.TrimSpace(hostHeaderMode)
	rp.Director = func(req *http.Request) {
		origHost := req.Host
		baseDirector(req)
		if origHost != "" && req.Header.Get("X-Forwarded-Host") == "" {
			req.Header.Set("X-Forwarded-Host", origHost)
		}
		if req.Header.Get("X-Forwarded-Proto") == "" {
			req.Header.Set("X-Forwarded-Proto", "https")
		}
		switch strings.ToLower(mode) {
		case "preserve":
			req.Host = origHost
		case "", "rewrite":
			req.Host = fmt.Sprintf("localhost:%d", localPort)
		default:
			req.Host = mode
		}
	}
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, proxyErr error) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = fmt.Fprintf(w, "FlareLens Funnel: local server at %s:%d is unreachable (%v)\n", cmp.Or(localHost, "127.0.0.1"), localPort, proxyErr)
	}
	logOut = wrapSyncWriter(logOut)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		if hasAuth {
			gotUser, gotPass, ok := r.BasicAuth()
			userOK := subtle.ConstantTimeCompare([]byte(gotUser), []byte(wantUser)) == 1
			passOK := subtle.ConstantTimeCompare([]byte(gotPass), []byte(wantPass)) == 1
			if !ok || !userOK || !passOK {
				w.Header().Set("WWW-Authenticate", `Basic realm="FlareLens Tunnel"`)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				if logOut != nil {
					_, _ = fmt.Fprintf(logOut, "  %s  %-6s %-34s %d Unauthorized  (%.1fms)\n",
						start.Format("15:04:05"), r.Method, truncatePath(r.URL.RequestURI(), 34), http.StatusUnauthorized, float64(time.Since(start).Microseconds())/1000.0)
				}
				return
			}
		}

		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		rp.ServeHTTP(rec, r)
		if logOut != nil {
			_, _ = fmt.Fprintf(logOut, "  %s  %-6s %-34s %d %s  (%.1fms)\n",
				start.Format("15:04:05"),
				r.Method,
				truncatePath(r.URL.RequestURI(), 34),
				rec.status,
				http.StatusText(rec.status),
				float64(time.Since(start).Microseconds())/1000.0,
			)
		}
	}), nil
}

type syncWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (sw *syncWriter) Write(p []byte) (int, error) {
	sw.mu.Lock()
	defer sw.mu.Unlock()
	return sw.w.Write(p)
}

func wrapSyncWriter(w io.Writer) io.Writer {
	if w == nil {
		return nil
	}
	if _, ok := w.(*syncWriter); ok {
		return w
	}
	return &syncWriter{w: w}
}

func truncatePath(p string, maxLen int) string {
	if len(p) <= maxLen {
		return p
	}
	return p[:maxLen-1] + "…"
}

// RunFunnel binds a WireGuard-scoped reverse proxy on the workstation, registers an ephemeral Traefik
// public HTTPS route on the Control Plane, renews the tunnel lease, and tears it down cleanly on ctx cancellation.
func RunFunnel(ctx context.Context, opts FunnelOptions) error {
	rawOut := opts.Output
	if rawOut == nil {
		rawOut = os.Stdout
	}
	out := wrapSyncWriter(rawOut)
	var logOut io.Writer
	if !opts.Quiet {
		logOut = out
	}

	localHost := cmp.Or(strings.TrimSpace(opts.LocalHost), "127.0.0.1")
	if opts.LocalPort < 1 || opts.LocalPort > 65535 {
		return fmt.Errorf("invalid local port %d", opts.LocalPort)
	}

	// Hydrate missing fields from saved MeshState (`sudo flarelensd login`)
	state, _ := LoadState()
	controlURL := strings.TrimRight(strings.TrimSpace(opts.ControlURL), "/")
	listenIP := strings.TrimSpace(opts.ListenIP)
	pubKey := strings.TrimSpace(opts.PublicKey)
	peerID := strings.TrimSpace(opts.PeerID)
	sshKeyPath := strings.TrimSpace(opts.SSHKeyPath)

	if state != nil {
		controlURL = cmp.Or(controlURL, strings.TrimRight(state.ControlURL, "/"))
		listenIP = cmp.Or(listenIP, state.OverlayIP)
		pubKey = cmp.Or(pubKey, state.PublicKey)
		peerID = cmp.Or(peerID, state.DeviceName)
		if sshKeyPath == "" {
			sshKeyPath = resolveDefaultSSHKeyPath(state.PrivateKeyPath)
		}
	}
	if sshKeyPath == "" {
		sshKeyPath = resolveDefaultSSHKeyPath("")
	}

	if controlURL == "" {
		return errors.New("not logged into FlareLens mesh (run 'sudo flarelensd login --control https://<your-control-plane>' first, or pass --control)")
	}
	if listenIP == "" {
		return errors.New("no WireGuard overlay IP found (run 'sudo flarelensd login' first to bring up flarelens0)")
	}

	handler, err := NewLocalFunnelHandler(localHost, opts.LocalPort, opts.BasicAuth, opts.HostHeader, logOut)
	if err != nil {
		return err
	}

	bindAddr := net.JoinHostPort(listenIP, strconv.Itoa(opts.ListenPort))
	ln, err := net.Listen("tcp", bindAddr)
	if err != nil {
		return fmt.Errorf("failed to bind WireGuard tunnel listener on %s (is flarelens0 active? try 'sudo flarelensd login'): %w", bindAddr, err)
	}
	defer ln.Close()

	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	assignedMeshPort, _ := strconv.Atoi(portStr)

	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 15 * time.Second,
	}
	go func() {
		_ = srv.Serve(ln)
	}()
	defer func() {
		shutCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()

	httpClient := opts.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 12 * time.Second}
	}

	// Register tunnel on Control Plane
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	createBody := map[string]any{
		"peer_id":     peerID,
		"public_key":  pubKey,
		"target_ip":   listenIP,
		"target_port": assignedMeshPort,
		"local_port":  opts.LocalPort,
		"subdomain":   strings.TrimSpace(opts.Subdomain),
		"domain":      strings.TrimSpace(opts.Domain),
		"node_id":     strings.TrimSpace(opts.GatewayNode),
		"has_auth":    strings.TrimSpace(opts.BasicAuth) != "",
		"timestamp":   ts,
	}
	if opts.AuthToken == "" && sshKeyPath != "" && pubKey != "" {
		if sig, sigErr := SignMeshTunnelProof(sshKeyPath, "open", pubKey, ts); sigErr == nil {
			createBody["ssh_signature"] = sig
		}
	}

	rawCreate, _ := json.Marshal(createBody)
	createReq, err := http.NewRequestWithContext(ctx, http.MethodPost, controlURL+"/api/v1/control/tunnels", bytes.NewReader(rawCreate))
	if err != nil {
		return err
	}
	createReq.Header.Set("Content-Type", "application/json")
	if opts.AuthToken != "" {
		createReq.Header.Set("Authorization", "Bearer "+opts.AuthToken)
	}

	resp, err := httpClient.Do(createReq)
	if err != nil {
		return fmt.Errorf("failed to register tunnel with Control Plane (%s): %w", controlURL, err)
	}
	var createRes TunnelCreateResponse
	_ = json.NewDecoder(resp.Body).Decode(&createRes)
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("tunnel registration rejected (HTTP %d): %s", resp.StatusCode, cmp.Or(createRes.Error, resp.Status))
	}

	tunnelID := createRes.Tunnel.TunnelID
	publicURL := cmp.Or(createRes.Tunnel.PublicURL, "https://"+createRes.Tunnel.Domain)

	// Guarantee clean tunnel teardown on Ctrl+C / SIGTERM
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		defer cancel()
		_ = closeTunnelRemote(closeCtx, httpClient, controlURL, opts.AuthToken, tunnelID, peerID, pubKey, sshKeyPath)
	}()

	authSummary := "open (public)"
	if strings.TrimSpace(opts.BasicAuth) != "" {
		authSummary = "HTTP Basic Auth enabled"
	}

	_, _ = fmt.Fprintln(out, "================================================================")
	_, _ = fmt.Fprintln(out, "  🌐 FlareLens Public HTTPS Funnel (WireGuard + Traefik)")
	_, _ = fmt.Fprintln(out, "================================================================")
	_, _ = fmt.Fprintf(out, "  • Public URL   : %s\n", publicURL)
	_, _ = fmt.Fprintf(out, "  • Forwarding   : %s -> http://%s:%d\n", publicURL, localHost, opts.LocalPort)
	_, _ = fmt.Fprintf(out, "  • Mesh Socket  : %s:%d (gateway: %s)\n", listenIP, assignedMeshPort, cmp.Or(createRes.Tunnel.NodeID, "auto"))
	_, _ = fmt.Fprintf(out, "  • Access Guard : %s\n", authSummary)
	_, _ = fmt.Fprintln(out, "----------------------------------------------------------------")
	_, _ = fmt.Fprintln(out, "  Press Ctrl+C to close tunnel and remove public route.")
	_, _ = fmt.Fprintln(out, "================================================================")

	ticker := time.NewTicker(45 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			_, _ = fmt.Fprintln(out, "\nClosing FlareLens tunnel and cleaning up Traefik route...")
			return nil
		case <-ticker.C:
			_ = renewTunnelRemote(ctx, httpClient, controlURL, opts.AuthToken, tunnelID, peerID, pubKey, sshKeyPath)
		}
	}
}

func renewTunnelRemote(
	ctx context.Context,
	client *http.Client,
	controlURL, authToken, tunnelID, peerID, pubKey, sshKeyPath string,
) error {
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	payload := map[string]string{
		"peer_id":    peerID,
		"public_key": pubKey,
		"timestamp":  ts,
	}
	if authToken == "" && sshKeyPath != "" && pubKey != "" {
		if sig, err := SignMeshTunnelProof(sshKeyPath, "renew", pubKey, ts); err == nil {
			payload["ssh_signature"] = sig
		}
	}
	body, _ := json.Marshal(payload)
	u := fmt.Sprintf("%s/api/v1/control/tunnels/%s/heartbeat", controlURL, url.PathEscape(tunnelID))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if authToken != "" {
		req.Header.Set("Authorization", "Bearer "+authToken)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	return nil
}

func closeTunnelRemote(
	ctx context.Context,
	client *http.Client,
	controlURL, authToken, tunnelID, peerID, pubKey, sshKeyPath string,
) error {
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	payload := map[string]string{
		"peer_id":    peerID,
		"public_key": pubKey,
		"timestamp":  ts,
	}
	if authToken == "" && sshKeyPath != "" && pubKey != "" {
		if sig, err := SignMeshTunnelProof(sshKeyPath, "close", pubKey, ts); err == nil {
			payload["ssh_signature"] = sig
		}
	}
	body, _ := json.Marshal(payload)
	u := fmt.Sprintf("%s/api/v1/control/tunnels/%s", controlURL, url.PathEscape(tunnelID))
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, u, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if authToken != "" {
		req.Header.Set("Authorization", "Bearer "+authToken)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	return nil
}
