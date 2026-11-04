package mesh

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// ConnectOptions defines parameters for joining the sovereign mesh from a laptop/workstation
type ConnectOptions struct {
	ControlURL    string
	EnrollToken   string
	NodeName      string
	KeyPath       string
	InterfaceName string
	ExportOnly    bool
	OutputPath    string
}

// GenerateWireGuardConfig builds a standard WireGuard (.conf) format configuration string
func GenerateWireGuardConfig(privKey string, localIP string, peers []Peer) string {
	var b strings.Builder
	b.WriteString("# ========================================================\n")
	b.WriteString("# FlareLens Sovereign Zero-Trust Mesh Client Configuration\n")
	b.WriteString(fmt.Sprintf("# Allocated IP: %s/10 | Subnet: 100.64.0.0/10\n", localIP))
	b.WriteString("# ========================================================\n\n")

	b.WriteString("[Interface]\n")
	b.WriteString(fmt.Sprintf("PrivateKey = %s\n", privKey))
	b.WriteString(fmt.Sprintf("Address = %s/10\n", localIP))
	b.WriteString("DNS = 1.1.1.1, 8.8.8.8\n\n")

	for _, peer := range peers {
		// Don't add self or peers without public keys
		peerIP := peer.OverlayIP
		if peerIP == "" {
			peerIP = peer.TailscaleIP
		}
		if peerIP == "" || peerIP == localIP || peer.PublicKey == "" {
			continue
		}

		b.WriteString(fmt.Sprintf("# Peer: %s (%s)\n", peer.Name, peer.ID))
		b.WriteString("[Peer]\n")
		b.WriteString(fmt.Sprintf("PublicKey = %s\n", peer.PublicKey))
		if peer.Endpoint != "" {
			b.WriteString(fmt.Sprintf("Endpoint = %s\n", peer.Endpoint))
		}
		allowedList := []string{fmt.Sprintf("%s/32", peerIP)}
		for _, extra := range peer.AllowedIPs {
			cidr := extra
			if !strings.Contains(cidr, "/") {
				cidr = fmt.Sprintf("%s/32", cidr)
			}
			found := false
			for _, a := range allowedList {
				if a == cidr {
					found = true
					break
				}
			}
			if !found {
				allowedList = append(allowedList, cidr)
			}
		}
		b.WriteString(fmt.Sprintf("AllowedIPs = %s\n", strings.Join(allowedList, ", ")))
		b.WriteString("PersistentKeepalive = 25\n\n")
	}

	return b.String()
}

// RunConnect handles mesh enrollment and local interface activation for client devices
func RunConnect(ctx context.Context, opts ConnectOptions, logger *slog.Logger) error {
	if logger == nil {
		logger = slog.Default()
	}

	// 1. Resolve Node Name
	if opts.NodeName == "" {
		host, err := os.Hostname()
		if err != nil {
			host = "client-laptop"
		}
		opts.NodeName = strings.ToLower(strings.ReplaceAll(host, ".", "-"))
	}

	// 2. Resolve Key Path
	if opts.KeyPath == "" {
		usr, err := user.Current()
		if err == nil && usr.HomeDir != "" {
			opts.KeyPath = filepath.Join(usr.HomeDir, ".flarelens", "mesh.key")
		} else {
			opts.KeyPath = filepath.Join(".", ".flarelens-mesh.key")
		}
	}

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(opts.KeyPath), 0700); err != nil {
		logger.Warn("Failed to create key directory; using working directory", "error", err)
		opts.KeyPath = "flarelens-mesh.key"
	}

	// 3. Load or generate WireGuard Curve25519 keypair
	privKey, pubKey, err := LoadOrGenerateKeypair(opts.KeyPath)
	if err != nil {
		return fmt.Errorf("failed to generate WireGuard keypair: %w", err)
	}

	opts.ControlURL = strings.TrimRight(opts.ControlURL, "/")
	if opts.ControlURL == "" {
		opts.ControlURL = "https://control.flarelens.dev"
	}

	fmt.Printf("🛡️  FlareLens Sovereign Mesh Connector\n")
	fmt.Printf("• Device Name : %s\n", opts.NodeName)
	fmt.Printf("• Public Key  : %s\n", pubKey)
	fmt.Printf("• Coordinator : %s\n", opts.ControlURL)
	fmt.Printf("[*] Registering with FlareLens Control Plane...\n")

	// 4. Register with Control Plane
	regURL := fmt.Sprintf("%s/api/v1/control/mesh/register", opts.ControlURL)
	payload := map[string]any{
		"node_id":         fmt.Sprintf("client-%s", opts.NodeName),
		"name":            opts.NodeName,
		"hostname":        opts.NodeName,
		"public_key":      pubKey,
		"type":            "client",
		"os":              runtime.GOOS,
		"client_version":  "flarelens-agent/v1.0",
		"connection_type": "direct_p2p",
	}
	bodyBytes, _ := json.Marshal(payload)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, regURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if opts.EnrollToken != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", opts.EnrollToken))
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to connect to coordinator at %s: %w", opts.ControlURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errResp map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&errResp)
		return fmt.Errorf("control plane enrollment failed (HTTP %d): %v", resp.StatusCode, errResp["error"])
	}

	var regResp MeshRegisterResponse
	if err := json.NewDecoder(resp.Body).Decode(&regResp); err != nil {
		return fmt.Errorf("failed to decode coordinator response: %w", err)
	}

	assignedIP := regResp.Peer.OverlayIP
	if assignedIP == "" {
		assignedIP = regResp.Peer.TailscaleIP
	}
	if assignedIP == "" {
		assignedIP = "100.64.0.2"
	}

	confContent := GenerateWireGuardConfig(privKey, assignedIP, regResp.Peers)

	// If export-only mode requested, save/print and exit cleanly
	if opts.ExportOnly {
		if opts.OutputPath != "" {
			if err := os.WriteFile(opts.OutputPath, []byte(confContent), 0600); err != nil {
				return fmt.Errorf("failed to write config to %s: %w", opts.OutputPath, err)
			}
			fmt.Printf("✅ WireGuard profile written to: %s\n", opts.OutputPath)
			fmt.Printf("👉 Import this file into your WireGuard app (Mac, Windows, iOS, Android) to connect.\n")
			return nil
		}
		fmt.Println(confContent)
		return nil
	}

	// Always write the latest .conf file for convenience
	confPath := opts.OutputPath
	if confPath == "" {
		confPath = filepath.Join(filepath.Dir(opts.KeyPath), "flarelens-mesh.conf")
	}
	_ = os.WriteFile(confPath, []byte(confContent), 0600)

	fmt.Printf("\n================================================================\n")
	fmt.Printf("  [✓] Successfully Enrolled in FlareLens Sovereign Mesh!\n")
	fmt.Printf("  • Allocated Mesh IP : %s/10 (CGNAT)\n", assignedIP)
	fmt.Printf("  • Mesh Subnet       : %s\n", regResp.Subnet)
	fmt.Printf("  • Active Peer Nodes : %d node(s)\n", len(regResp.Peers))
	for _, p := range regResp.Peers {
		pIP := p.OverlayIP
		if pIP == "" {
			pIP = p.TailscaleIP
		}
		if pIP != assignedIP {
			fmt.Printf("    - %s (%s) -> %s\n", p.Name, p.ID, pIP)
		}
	}
	fmt.Printf("  • WireGuard Profile : %s\n", confPath)
	fmt.Printf("================================================================\n\n")

	// 5. Interface Activation
	activated := false

	// If root on Linux, try kernel wireguard interface
	if runtime.GOOS == "linux" && os.Geteuid() == 0 {
		if opts.InterfaceName == "" {
			opts.InterfaceName = "flarelens0"
		}
		meshCfg := Config{
			Enabled:       true,
			InterfaceName: opts.InterfaceName,
			ListenPort:    51820,
			OverlayIP:     assignedIP,
			Subnet:        "100.64.0.0/10",
		}
		mgr := NewManager(meshCfg, privKey, pubKey, nil, logger)
		if err := mgr.InitInterface(ctx); err == nil {
			_ = mgr.SyncPeers(ctx, regResp.Peers)
			dnsCfg := MagicDNSConfig{
				DomainSuffix:  ".mesh",
				InterfaceName: opts.InterfaceName,
				SyncHostsFile: true,
			}
			dnsServer := NewMagicDNSServer(dnsCfg, logger)
			dnsServer.UpdatePeers(regResp.Peers, assignedIP, opts.NodeName)
			fmt.Printf("🚀 Kernel WireGuard interface [%s] is UP and ACTIVE!\n", opts.InterfaceName)
			fmt.Printf("🔮 In-Memory MagicDNS is ACTIVE (*.mesh zero-latency resolution)!\n")
			activated = true
		}
	}

	if !activated {
		fmt.Printf("\n🔒 Run with sudo for automated interface activation: sudo flarelens-agent login\n\n")
	}

	fmt.Printf("[*] Mesh agent running. Polling for network changes (Press Ctrl+C to exit)...\n")

	// 6. Background synchronization loop
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			fmt.Printf("\nShutting down FlareLens Mesh connection...\n")
			return nil
		case <-ticker.C:
			// Poll latest peer list from control plane
			pollURL := fmt.Sprintf("%s/api/v1/control/mesh/peers", opts.ControlURL)
			pollReq, err := http.NewRequestWithContext(ctx, http.MethodGet, pollURL, nil)
			if err == nil {
				if opts.EnrollToken != "" {
					pollReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s", opts.EnrollToken))
				}
				pResp, err := client.Do(pollReq)
				if err == nil && pResp.StatusCode == http.StatusOK {
					var listResp struct {
						Peers []Peer `json:"peers"`
					}
					if err := json.NewDecoder(pResp.Body).Decode(&listResp); err == nil {
						// Update local .conf file with latest peers
						updatedConf := GenerateWireGuardConfig(privKey, assignedIP, listResp.Peers)
						_ = os.WriteFile(confPath, []byte(updatedConf), 0600)
					}
					pResp.Body.Close()
				}
			}
		}
	}
}
