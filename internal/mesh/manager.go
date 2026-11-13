package mesh

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// CommandExecutor defines the interface for running system commands (mockable for tests)
type CommandExecutor interface {
	Run(ctx context.Context, cmd string, args ...string) ([]byte, error)
}

// OSCommandExecutor executes real Linux kernel commands
type OSCommandExecutor struct{}

func (e *OSCommandExecutor) Run(ctx context.Context, cmd string, args ...string) ([]byte, error) {
	c := exec.CommandContext(ctx, cmd, args...)
	return c.CombinedOutput()
}

// WireGuardController abstracts wgctrl.Client for testing and production
type WireGuardController interface {
	ConfigureDevice(name string, cfg wgtypes.Config) error
	Device(name string) (*wgtypes.Device, error)
	Close() error
}

// Manager orchestrates the kernel WireGuard interface and peer synchronization
type Manager struct {
	cfg        Config
	privKey    string
	pubKey     string
	executor   CommandExecutor
	wgCtrl     WireGuardController
	logger     *slog.Logger
	knownPeers map[string]Peer // key: public_key
	mu         sync.RWMutex
}

// NewManager creates a new WireGuard mesh manager
func NewManager(cfg Config, privKey, pubKey string, executor CommandExecutor, logger *slog.Logger) *Manager {
	if cfg.InterfaceName == "" {
		cfg.InterfaceName = "flarelens0"
	}
	if cfg.ListenPort == 0 {
		cfg.ListenPort = 51820
	}
	if cfg.Subnet == "" {
		cfg.Subnet = "100.64.0.0/10"
	}
	if executor == nil {
		executor = &OSCommandExecutor{}
	}
	if logger == nil {
		logger = slog.Default()
	}

	return &Manager{
		cfg:        cfg,
		privKey:    privKey,
		pubKey:     pubKey,
		executor:   executor,
		logger:     logger,
		knownPeers: make(map[string]Peer),
	}
}

// SetWGController overrides the default wgctrl client (primarily for tests)
func (m *Manager) SetWGController(controller WireGuardController) {
	m.mu.Lock()
	m.wgCtrl = controller
	m.mu.Unlock()
}

func (m *Manager) getWGClient() (WireGuardController, func(), error) {
	ctrl := m.wgCtrl
	if ctrl != nil {
		return ctrl, func() {}, nil
	}

	c, err := wgctrl.New()
	if err != nil {
		return nil, nil, err
	}
	return c, func() { _ = c.Close() }, nil
}

// PublicKey returns the agent's local WireGuard public key
func (m *Manager) PublicKey() string {
	return m.pubKey
}

// OverlayIP returns the assigned overlay IP
func (m *Manager) OverlayIP() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cfg.OverlayIP
}

// SetOverlayIP updates the local overlay IP if assigned by control plane
func (m *Manager) SetOverlayIP(ip string) {
	m.mu.Lock()
	m.cfg.OverlayIP = ip
	m.mu.Unlock()
}

// InitInterface initializes the Linux WireGuard kernel interface (flarelens0)
func (m *Manager) InitInterface(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	iface := m.cfg.InterfaceName
	m.logger.Info("Initializing FlareLens WireGuard mesh interface", "interface", iface, "port", m.cfg.ListenPort)

	// 1. Check if interface exists; if not, create it
	_, err := m.executor.Run(ctx, "ip", "link", "show", iface)
	if err != nil {
		out, addErr := m.executor.Run(ctx, "ip", "link", "add", "dev", iface, "type", "wireguard")
		if addErr != nil {
			return fmt.Errorf("failed to create wireguard interface %s: %s (%w)", iface, strings.TrimSpace(string(out)), addErr)
		}
	}

	// 2. Configure interface listen port and private key using native Netlink wgctrl
	parsedPriv, parseErr := wgtypes.ParseKey(m.privKey)
	if parseErr != nil {
		return fmt.Errorf("invalid wireguard private key: %w", parseErr)
	}

	c, cleanup, clientErr := m.getWGClient()
	if clientErr != nil {
		return fmt.Errorf("failed to open wireguard netlink client: %w", clientErr)
	}
	defer cleanup()

	port := m.cfg.ListenPort
	devCfg := wgtypes.Config{
		PrivateKey: &parsedPriv,
		ListenPort: &port,
	}
	if cfgErr := c.ConfigureDevice(iface, devCfg); cfgErr != nil {
		return fmt.Errorf("failed to configure wireguard device %s via netlink: %w", iface, cfgErr)
	}
	m.logger.Debug("Configured WireGuard interface via native Netlink wgctrl", "interface", iface)

	// 3. Assign IP address if configured
	if m.cfg.OverlayIP != "" {
		cidr := fmt.Sprintf("%s/10", m.cfg.OverlayIP)
		out, err := m.executor.Run(ctx, "ip", "addr", "replace", cidr, "dev", iface)
		if err != nil {
			return fmt.Errorf("failed to assign overlay ip %s to %s: %s (%w)", cidr, iface, strings.TrimSpace(string(out)), err)
		}
	}

	// 4. Set MTU to 1200 (optimal for cross-ISP, cellular, and multi-cloud encapsulation) and bring interface up
	out, err := m.executor.Run(ctx, "ip", "link", "set", "dev", iface, "mtu", "1200", "up")
	if err != nil {
		return fmt.Errorf("failed to bring up interface %s: %s (%w)", iface, strings.TrimSpace(string(out)), err)
	}

	m.logger.Info("FlareLens WireGuard mesh interface is UP", "interface", iface, "overlay_ip", m.cfg.OverlayIP)
	return nil
}

// SyncPeers dynamically adds, updates, or removes peers in the kernel without restarting the interface
func (m *Manager) SyncPeers(ctx context.Context, peers []Peer) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	iface := m.cfg.InterfaceName
	newPeerMap := make(map[string]Peer)
	var peerConfigs []wgtypes.PeerConfig

	for _, p := range peers {
		// Do not add self as a peer
		if p.PublicKey == m.pubKey || p.OverlayIP == "" {
			continue
		}
		newPeerMap[p.PublicKey] = p

		pubKey, err := wgtypes.ParseKey(p.PublicKey)
		if err != nil {
			continue
		}

		var allowedNets []net.IPNet
		if _, ipNet, err := net.ParseCIDR(fmt.Sprintf("%s/32", p.OverlayIP)); err == nil {
			allowedNets = append(allowedNets, *ipNet)
		}

		for _, extraIP := range p.AllowedIPs {
			cidr := extraIP
			if !strings.Contains(cidr, "/") {
				cidr = fmt.Sprintf("%s/32", cidr)
			}
			if _, extraNet, err := net.ParseCIDR(cidr); err == nil {
				dup := false
				for _, an := range allowedNets {
					if an.String() == extraNet.String() {
						dup = true
						break
					}
				}
				if !dup {
					allowedNets = append(allowedNets, *extraNet)
				}
			}
		}

		if len(allowedNets) == 0 {
			continue
		}

		keepalive := 25 * time.Second
		pc := wgtypes.PeerConfig{
			PublicKey:                   pubKey,
			AllowedIPs:                  allowedNets,
			PersistentKeepaliveInterval: &keepalive,
			ReplaceAllowedIPs:           true,
		}

		if p.Endpoint != "" {
			if udpAddr, err := net.ResolveUDPAddr("udp", p.Endpoint); err == nil {
				pc.Endpoint = udpAddr
			}
		}

		peerConfigs = append(peerConfigs, pc)
	}

	// Atomic peer sync via native Netlink wgctrl
	c, cleanup, err := m.getWGClient()
	if err != nil {
		return fmt.Errorf("failed to open wireguard netlink client: %w", err)
	}
	defer cleanup()

	cfg := wgtypes.Config{
		ReplacePeers: true,
		Peers:        peerConfigs,
	}
	if err := c.ConfigureDevice(iface, cfg); err != nil {
		return fmt.Errorf("failed to sync wireguard peers via netlink: %w", err)
	}

	// Ensure kernel routing table directs traffic for each peer's AllowedIPs to the WireGuard interface
	for _, pc := range peerConfigs {
		for _, ipNet := range pc.AllowedIPs {
			_, _ = m.executor.Run(ctx, "ip", "route", "replace", ipNet.String(), "dev", iface)
		}
	}

	m.knownPeers = newPeerMap
	m.logger.Debug("Synced WireGuard peers via native Netlink wgctrl", "peers", len(peerConfigs))
	return nil
}

// GetPeerStats returns real-time kernel peer telemetry via native Netlink wgctrl
func (m *Manager) GetPeerStats(ctx context.Context) (map[string]PeerStats, error) {
	m.mu.RLock()
	iface := m.cfg.InterfaceName
	m.mu.RUnlock()

	c, cleanup, err := m.getWGClient()
	if err != nil {
		return nil, fmt.Errorf("failed to open wireguard netlink client: %w", err)
	}
	defer cleanup()

	dev, err := c.Device(iface)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect wireguard device %s via netlink: %w", iface, err)
	}

	stats := make(map[string]PeerStats)
	now := time.Now()
	for _, p := range dev.Peers {
		pubStr := p.PublicKey.String()
		overlayIP := ""
		if len(p.AllowedIPs) > 0 {
			overlayIP = p.AllowedIPs[0].IP.String()
		}
		stats[pubStr] = PeerStats{
			PublicKey:       pubStr,
			OverlayIP:       overlayIP,
			LatestHandshake: p.LastHandshakeTime.Unix(),
			BytesRx:         p.ReceiveBytes,
			BytesTx:         p.TransmitBytes,
			Active:          p.LastHandshakeTime.After(now.Add(-3 * time.Minute)),
		}
	}
	return stats, nil
}

// ParseWGDump parses the tab-delimited output of `wg show <iface> dump`
func ParseWGDump(dump string) (map[string]PeerStats, error) {
	lines := strings.Split(dump, "\n")
	stats := make(map[string]PeerStats)
	now := time.Now().Unix()

	// Skip line 0 (interface header line)
	for i := 1; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		// Format: public_key, preshared_key, endpoint, allowed_ips, latest_handshake, transfer_rx, transfer_tx, persistent_keepalive
		if len(fields) < 7 {
			continue
		}

		pubKey := fields[0]
		allowedIPs := fields[3]
		latestHandshake, _ := strconv.ParseInt(fields[4], 10, 64)
		rxBytes, _ := strconv.ParseInt(fields[5], 10, 64)
		txBytes, _ := strconv.ParseInt(fields[6], 10, 64)

		cleanIP := strings.TrimSuffix(allowedIPs, "/32")

		stats[pubKey] = PeerStats{
			PublicKey:       pubKey,
			OverlayIP:       cleanIP,
			LatestHandshake: latestHandshake,
			BytesRx:         rxBytes,
			BytesTx:         txBytes,
			Active:          latestHandshake > 0 && (now-latestHandshake) < 180,
		}
	}

	return stats, nil
}
