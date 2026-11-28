package deploy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

// FunnelTunnelSpec describes an ephemeral developer localhost tunnel (`flarelensd http <port>`)
// routed from Traefik on this gateway node across the WireGuard mesh (`100.64.0.0/10`) to the developer's device.
type FunnelTunnelSpec struct {
	TunnelID   string `json:"tunnel_id"`
	Domain     string `json:"domain"`
	TargetIP   string `json:"target_ip"`   // Must belong to 100.64.0.0/10 WireGuard mesh subnet
	TargetPort int    `json:"target_port"` // Ephemeral listener port on developer's WireGuard interface
}

type funnelBridgeRelay struct {
	tunnelID   string
	targetAddr string
	listenAddr string
	ln         net.Listener
	cancel     context.CancelFunc
}

func (r *funnelBridgeRelay) close() {
	if r == nil {
		return
	}
	if r.cancel != nil {
		r.cancel()
	}
	if r.ln != nil {
		_ = r.ln.Close()
	}
}

// SyncFunnelTunnel validates the WireGuard CGNAT target, optionally starts a local Docker-bridge-to-WireGuard
// TCP forwarder when Traefik runs inside a bridge container, and atomically writes `funnel-<id>.yaml` in Traefik.
func (o *Orchestrator) SyncFunnelTunnel(ctx context.Context, spec FunnelTunnelSpec) (string, error) {
	if o.traefik == nil {
		return "", errors.New("traefik route flipper is not configured on this node")
	}
	tunnelID := strings.TrimSpace(spec.TunnelID)
	domain := strings.ToLower(strings.TrimSpace(spec.Domain))
	if tunnelID == "" || domain == "" {
		return "", errors.New("funnel tunnel requires non-empty tunnel_id and domain")
	}
	if spec.TargetPort < 1 || spec.TargetPort > 65535 {
		return "", fmt.Errorf("invalid target_port %d", spec.TargetPort)
	}

	targetAddrIP, err := netip.ParseAddr(strings.TrimSpace(spec.TargetIP))
	if err != nil || !meshCGNATPrefix.Contains(targetAddrIP) {
		return "", fmt.Errorf("funnel target_ip %q must reside within WireGuard CGNAT subnet 100.64.0.0/10", spec.TargetIP)
	}

	meshTarget := net.JoinHostPort(targetAddrIP.String(), strconv.Itoa(spec.TargetPort))
	upstreamURL := "http://" + meshTarget

	// When Traefik runs inside a Docker bridge network (e.g. kiwid-edge / flarelens-edge), bind a host-side
	// relay on that bridge's gateway IP so Traefik reaches the host's WireGuard flarelens0 interface cleanly
	// without requiring permissive iptables FORWARD rules between Docker bridges and flarelens0.
	var bridgeGatewayIP string
	if o.runner != nil {
		bridgeGatewayIP = o.runner.DiscoverTraefikBridgeGatewayIP(ctx)
	}

	o.mu.Lock()
	if o.funnelRelays == nil {
		o.funnelRelays = make(map[string]*funnelBridgeRelay)
	}
	existing := o.funnelRelays[tunnelID]
	if existing != nil && existing.targetAddr == meshTarget && (bridgeGatewayIP == "" || strings.HasPrefix(existing.listenAddr, bridgeGatewayIP+":")) {
		if existing.listenAddr != "" {
			upstreamURL = "http://" + existing.listenAddr
		}
		o.mu.Unlock()
		if err := o.traefik.WriteFunnelRoute(tunnelID, domain, upstreamURL); err != nil {
			return "", err
		}
		return upstreamURL, nil
	}
	if existing != nil {
		existing.close()
		delete(o.funnelRelays, tunnelID)
	}
	o.mu.Unlock()

	if bridgeGatewayIP != "" {
		if relay, relayErr := startFunnelBridgeRelay(tunnelID, bridgeGatewayIP, meshTarget); relayErr == nil {
			o.mu.Lock()
			o.funnelRelays[tunnelID] = relay
			o.mu.Unlock()
			upstreamURL = "http://" + relay.listenAddr
		}
	}

	if err := o.traefik.WriteFunnelRoute(tunnelID, domain, upstreamURL); err != nil {
		o.RemoveFunnelTunnel(tunnelID)
		return "", err
	}

	o.logger.Info("Activated WireGuard Funnel tunnel route",
		"tunnel_id", tunnelID,
		"domain", domain,
		"mesh_target", meshTarget,
		"traefik_upstream", upstreamURL,
	)
	return upstreamURL, nil
}

// RemoveFunnelTunnel tears down any bridge TCP forwarder and removes `funnel-<id>.yaml` from Traefik.
func (o *Orchestrator) RemoveFunnelTunnel(tunnelID string) {
	cleanID := strings.TrimSpace(tunnelID)
	if cleanID == "" {
		return
	}
	o.mu.Lock()
	if relay, ok := o.funnelRelays[cleanID]; ok {
		relay.close()
		delete(o.funnelRelays, cleanID)
	}
	o.mu.Unlock()

	if o.traefik != nil {
		_ = o.traefik.RemoveFunnelRoute(cleanID)
	}
	o.logger.Info("Removed WireGuard Funnel tunnel route", "tunnel_id", cleanID)
}

// CloseAllFunnelTunnels stops all active bridge forwarders on daemon shutdown.
func (o *Orchestrator) CloseAllFunnelTunnels() {
	o.mu.Lock()
	defer o.mu.Unlock()
	for id, relay := range o.funnelRelays {
		relay.close()
		delete(o.funnelRelays, id)
	}
}

func startFunnelBridgeRelay(tunnelID, bindIP, targetAddr string) (*funnelBridgeRelay, error) {
	ln, err := net.Listen("tcp", net.JoinHostPort(bindIP, "0"))
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &funnelBridgeRelay{
		tunnelID:   tunnelID,
		targetAddr: targetAddr,
		listenAddr: ln.Addr().String(),
		ln:         ln,
		cancel:     cancel,
	}

	go func() {
		for {
			srcConn, acceptErr := ln.Accept()
			if acceptErr != nil {
				if ctx.Err() != nil || errors.Is(acceptErr, net.ErrClosed) {
					return
				}
				continue
			}
			go pipeFunnelConn(ctx, srcConn, targetAddr)
		}
	}()
	return r, nil
}

func pipeFunnelConn(ctx context.Context, src net.Conn, targetAddr string) {
	defer src.Close()
	dialer := &net.Dialer{Timeout: 6 * time.Second}
	dst, err := dialer.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		return
	}
	defer dst.Close()

	var wg sync.WaitGroup
	wg.Go(func() {
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	})
	wg.Go(func() {
		_, _ = io.Copy(src, dst)
		if cw, ok := src.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	})
	wg.Wait()
}
