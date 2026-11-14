package mesh

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ClusterEndpoint describes a placed service replica or singleton across the WireGuard mesh.
type ClusterEndpoint struct {
	Env           string   `json:"env"`
	Service       string   `json:"service"`
	Mode          string   `json:"mode,omitempty"` // "blue_green" | "singleton"
	NodeID        string   `json:"node_id"`
	MeshIP        string   `json:"mesh_ip,omitempty"`
	MeshPort      int      `json:"mesh_port,omitzero"`
	ContainerPort int      `json:"container_port,omitzero"`
	ActivePort    int      `json:"active_port,omitzero"`
	ContainerName string   `json:"container_name,omitempty"`
	Aliases       []string `json:"aliases,omitempty"`
	Domains       []string `json:"domains,omitempty"`
	HealthPath    string   `json:"health_path,omitempty"`
	Healthy       bool     `json:"healthy,omitzero"`
}

// ClusterRouteGroup summarizes all healthy upstream URLs and domains for a multi-node HTTP service.
type ClusterRouteGroup struct {
	Env          string
	Service      string
	Domains      []string
	HealthPath   string
	HasLocalNode bool
	RemoteURLs   []string
}

// LocalTargetResolver resolves the local TCP dial address ("host:port") for a replica hosted on this node.
type LocalTargetResolver func(ctx context.Context, ep ClusterEndpoint) (string, error)

type activeMeshListener struct {
	addr     string
	listener net.Listener
	cancel   context.CancelFunc
}

// ServiceRouter exposes local container ports strictly on the encrypted WireGuard overlay interface
// and computes cross-node ExtraHosts and Traefik mesh upstream URLs for multi-node scheduling.
type ServiceRouter struct {
	localNodeID string
	resolver    LocalTargetResolver
	dialTimeout time.Duration
	logger      *slog.Logger

	mu        sync.RWMutex
	overlayIP string
	endpoints []ClusterEndpoint
	listeners map[string]*activeMeshListener // key: "<overlayIP>:<meshPort>"
}

// NewServiceRouter creates a cross-node WireGuard service router for localNodeID.
func NewServiceRouter(localNodeID string, resolver LocalTargetResolver, logger *slog.Logger) *ServiceRouter {
	if logger == nil {
		logger = slog.Default()
	}
	return &ServiceRouter{
		localNodeID: strings.TrimSpace(localNodeID),
		resolver:    resolver,
		dialTimeout: 5 * time.Second,
		logger:      logger,
		listeners:   make(map[string]*activeMeshListener),
	}
}

// SetOverlayIP updates the local WireGuard overlay IP used for mesh-only port listeners.
func (r *ServiceRouter) SetOverlayIP(ip string) {
	clean := strings.TrimSpace(ip)
	if idx := strings.IndexByte(clean, '/'); idx != -1 {
		clean = clean[:idx]
	}
	r.mu.Lock()
	r.overlayIP = clean
	eps := slices.Clone(r.endpoints)
	r.mu.Unlock()

	r.reconcileListeners(clean, eps)
}

// UpdateEndpoints updates the cluster-wide placement map and reconciles local WireGuard TCP forwarders.
func (r *ServiceRouter) UpdateEndpoints(overlayIP string, endpoints []ClusterEndpoint) {
	cleanIP := strings.TrimSpace(overlayIP)
	if idx := strings.IndexByte(cleanIP, '/'); idx != -1 {
		cleanIP = cleanIP[:idx]
	}

	cloned := make([]ClusterEndpoint, len(endpoints))
	for i, ep := range endpoints {
		ep.Env = normalizeMeshEnv(ep.Env)
		ep.Service = strings.ToLower(strings.TrimSpace(ep.Service))
		ep.Aliases = slices.Clone(ep.Aliases)
		ep.Domains = slices.Clone(ep.Domains)
		cloned[i] = ep
	}

	r.mu.Lock()
	if cleanIP != "" {
		r.overlayIP = cleanIP
	}
	effectiveIP := r.overlayIP
	r.endpoints = cloned
	r.mu.Unlock()

	r.reconcileListeners(effectiveIP, cloned)
}

// Close shuts down all active WireGuard mesh listeners cleanly.
func (r *ServiceRouter) Close() {
	r.mu.Lock()
	toClose := slices.Collect(maps.Values(r.listeners))
	clear(r.listeners)
	r.mu.Unlock()

	for _, l := range toClose {
		l.cancel()
		_ = l.listener.Close()
	}
}

// ActiveListenerAddrs returns the sorted list of currently bound mesh listener addresses (for diagnostics/tests).
func (r *ServiceRouter) ActiveListenerAddrs() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.listeners))
	for _, l := range r.listeners {
		out = append(out, l.listener.Addr().String())
	}
	slices.Sort(out)
	return out
}

// ExtraHostsForEnv builds Docker HostConfig.ExtraHosts ("alias:mesh_ip") for services placed on remote nodes
// so containers on this node reach remote databases, caches, and internal APIs over WireGuard without config changes.
func (r *ServiceRouter) ExtraHostsForEnv(env string) []string {
	normEnv := normalizeMeshEnv(env)

	r.mu.RLock()
	eps := slices.Clone(r.endpoints)
	selfIP := r.overlayIP
	r.mu.RUnlock()

	if len(eps) == 0 {
		return nil
	}

	// Track services that already have a replica on this node so local Docker DNS aliases take priority.
	localServices := make(map[string]bool)
	for _, ep := range eps {
		if ep.NodeID == r.localNodeID && (ep.Env == normEnv || ep.Env == "infra") {
			localServices[ep.Service] = true
		}
	}

	hostToIP := make(map[string]string)
	for _, ep := range eps {
		if ep.Env != normEnv && ep.Env != "infra" {
			continue
		}
		if ep.NodeID == r.localNodeID || localServices[ep.Service] {
			continue
		}
		ip := strings.TrimSpace(ep.MeshIP)
		if ip == "" || ip == selfIP || net.ParseIP(ip) == nil {
			continue
		}

		candidates := []string{
			ep.Service,
			fmt.Sprintf("%s-%s", ep.Service, ep.Env),
		}
		if ep.Service == "dragonfly" {
			candidates = append(candidates, "redis", fmt.Sprintf("redis-%s", ep.Env))
		}
		if ep.ContainerName != "" {
			candidates = append(candidates, ep.ContainerName)
		}
		candidates = append(candidates, ep.Aliases...)

		for _, rawHost := range candidates {
			host := strings.ToLower(strings.TrimSpace(rawHost))
			if !isValidExtraHostName(host) {
				continue
			}
			if _, exists := hostToIP[host]; !exists {
				hostToIP[host] = ip
			}
		}
	}

	if len(hostToIP) == 0 {
		return nil
	}

	out := make([]string, 0, len(hostToIP))
	for _, host := range slices.Sorted(maps.Keys(hostToIP)) {
		out = append(out, fmt.Sprintf("%s:%s", host, hostToIP[host]))
	}
	return out
}

// RemoteUpstreamURLs returns sorted HTTP upstream URLs ("http://<mesh_ip>:<mesh_port>") for healthy remote replicas.
func (r *ServiceRouter) RemoteUpstreamURLs(env, service string) []string {
	normEnv := normalizeMeshEnv(env)
	cleanSvc := strings.ToLower(strings.TrimSpace(service))

	r.mu.RLock()
	eps := slices.Clone(r.endpoints)
	selfIP := r.overlayIP
	r.mu.RUnlock()

	var urls []string
	for _, ep := range eps {
		if ep.Env != normEnv || ep.Service != cleanSvc {
			continue
		}
		if ep.NodeID == r.localNodeID || !ep.Healthy {
			continue
		}
		ip := strings.TrimSpace(ep.MeshIP)
		port := cmp.Or(ep.MeshPort, ep.ActivePort)
		if ip == "" || ip == selfIP || net.ParseIP(ip) == nil || port <= 0 {
			continue
		}
		u := fmt.Sprintf("http://%s:%d", ip, port)
		if !slices.Contains(urls, u) {
			urls = append(urls, u)
		}
	}
	slices.Sort(urls)
	return urls
}

// RouteGroups returns domain-bearing cluster services so ingress nodes can route to remote mesh replicas.
func (r *ServiceRouter) RouteGroups() []ClusterRouteGroup {
	r.mu.RLock()
	eps := slices.Clone(r.endpoints)
	selfIP := r.overlayIP
	r.mu.RUnlock()

	type key struct {
		env     string
		service string
	}
	groups := make(map[key]*ClusterRouteGroup)

	for _, ep := range eps {
		if len(ep.Domains) == 0 {
			continue
		}
		k := key{env: ep.Env, service: ep.Service}
		g, ok := groups[k]
		if !ok {
			g = &ClusterRouteGroup{
				Env:        ep.Env,
				Service:    ep.Service,
				HealthPath: cmp.Or(strings.TrimSpace(ep.HealthPath), "/health"),
			}
			groups[k] = g
		}
		for _, d := range ep.Domains {
			trimmed := strings.TrimSpace(d)
			if trimmed != "" && !slices.Contains(g.Domains, trimmed) {
				g.Domains = append(g.Domains, trimmed)
			}
		}
		if ep.NodeID == r.localNodeID {
			g.HasLocalNode = true
			continue
		}
		if !ep.Healthy {
			continue
		}
		ip := strings.TrimSpace(ep.MeshIP)
		port := cmp.Or(ep.MeshPort, ep.ActivePort)
		if ip != "" && ip != selfIP && net.ParseIP(ip) != nil && port > 0 {
			u := fmt.Sprintf("http://%s:%d", ip, port)
			if !slices.Contains(g.RemoteURLs, u) {
				g.RemoteURLs = append(g.RemoteURLs, u)
			}
		}
	}

	out := make([]ClusterRouteGroup, 0, len(groups))
	for _, g := range groups {
		slices.Sort(g.RemoteURLs)
		out = append(out, *g)
	}
	slices.SortFunc(out, func(a, b ClusterRouteGroup) int {
		return cmp.Or(cmp.Compare(a.Env, b.Env), cmp.Compare(a.Service, b.Service))
	})
	return out
}

func (r *ServiceRouter) reconcileListeners(overlayIP string, endpoints []ClusterEndpoint) {
	desired := make(map[string]ClusterEndpoint)
	if overlayIP != "" && net.ParseIP(overlayIP) != nil && r.resolver != nil {
		for _, ep := range endpoints {
			if ep.NodeID != r.localNodeID || ep.MeshPort <= 0 {
				continue
			}
			bindAddr := net.JoinHostPort(overlayIP, strconv.Itoa(ep.MeshPort))
			desired[bindAddr] = ep
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	for addr, existing := range r.listeners {
		if _, keep := desired[addr]; !keep {
			existing.cancel()
			_ = existing.listener.Close()
			delete(r.listeners, addr)
			r.logger.Info("Closed retired WireGuard mesh service listener", "listen_addr", addr)
		}
	}

	for addr, ep := range desired {
		if _, exists := r.listeners[addr]; exists {
			continue
		}
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			if isAddrInUseOrUnavailable(err) {
				r.logger.Debug("WireGuard mesh port already bound or interface pending", "listen_addr", addr, "service", ep.Service, "detail", err)
				continue
			}
			r.logger.Warn("Failed to bind WireGuard mesh service listener", "listen_addr", addr, "service", ep.Service, "error", err)
			continue
		}

		ctx, cancel := context.WithCancel(context.Background())
		entry := &activeMeshListener{
			addr:     addr,
			listener: ln,
			cancel:   cancel,
		}
		r.listeners[addr] = entry
		r.logger.Info("Bound WireGuard mesh service forwarder",
			"listen_addr", ln.Addr().String(),
			"service", ep.Service,
			"env", ep.Env,
		)
		go r.acceptLoop(ctx, ln, ep.Env, ep.Service)
	}
}

func (r *ServiceRouter) acceptLoop(ctx context.Context, ln net.Listener, env, service string) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		go r.proxyConnection(ctx, conn, env, service)
	}
}

func (r *ServiceRouter) findLocalEndpoint(env, service string) (ClusterEndpoint, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, ep := range r.endpoints {
		if ep.NodeID == r.localNodeID && ep.Env == env && ep.Service == service {
			return ep, true
		}
	}
	return ClusterEndpoint{}, false
}

func (r *ServiceRouter) proxyConnection(ctx context.Context, downstream net.Conn, env, service string) {
	defer downstream.Close()

	ep, ok := r.findLocalEndpoint(env, service)
	if !ok || r.resolver == nil {
		return
	}

	resolveCtx, cancel := context.WithTimeout(ctx, r.dialTimeout)
	targetAddr, err := r.resolver(resolveCtx, ep)
	cancel()
	if err != nil || targetAddr == "" {
		r.logger.Debug("Mesh forwarder could not resolve local container target", "service", service, "env", env, "error", err)
		return
	}

	upstream, err := net.DialTimeout("tcp", targetAddr, r.dialTimeout)
	if err != nil {
		r.logger.Debug("Mesh forwarder failed dialing local container target", "service", service, "target", targetAddr, "error", err)
		return
	}
	defer upstream.Close()

	var wg sync.WaitGroup
	wg.Go(func() {
		_, _ = io.Copy(upstream, downstream)
		if tcpUp, ok := upstream.(*net.TCPConn); ok {
			_ = tcpUp.CloseWrite()
		}
	})
	wg.Go(func() {
		_, _ = io.Copy(downstream, upstream)
		if tcpDown, ok := downstream.(*net.TCPConn); ok {
			_ = tcpDown.CloseWrite()
		}
	})
	wg.Wait()
}

func normalizeMeshEnv(env string) string {
	e := strings.ToLower(strings.TrimSpace(env))
	switch e {
	case "", "uat":
		return "uat"
	case "production", "prod":
		return "prod"
	case "infrastructure", "infra":
		return "infra"
	default:
		return e
	}
}

func isValidExtraHostName(host string) bool {
	if host == "" || host == "localhost" || host == "host.docker.internal" {
		return false
	}
	if strings.ContainsAny(host, " :\t\r\n/") {
		return false
	}
	return net.ParseIP(host) == nil
}

func isAddrInUseOrUnavailable(err error) bool {
	if err == nil {
		return false
	}
	lower := strings.ToLower(err.Error())
	return strings.Contains(lower, "address already in use") ||
		strings.Contains(lower, "only one usage of each socket address") ||
		strings.Contains(lower, "cannot assign requested address") ||
		strings.Contains(lower, "requested address is not valid")
}
