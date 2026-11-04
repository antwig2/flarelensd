package mesh

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// DeviceCodeResponse represents the payload returned by the control plane to initiate device auth
type DeviceCodeResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// DeviceTokenResponse represents the polling response from the control plane
type DeviceTokenResponse struct {
	Status     string `json:"status"`
	ApprovedBy string `json:"approved_by"`
	Peer       Peer   `json:"peer"`
	Peers      []Peer `json:"peers"`
	Subnet     string `json:"subnet"`
	Error      string `json:"error"`
	Message    string `json:"message"`
}

// openBrowser attempts to launch the system default web browser with the given URL
func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "linux":
		cmd = exec.Command("xdg-open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	}
	if cmd != nil {
		_ = cmd.Start()
	}
}

// RunLogin initiates the browser SSO login flow via Cloudflare Access and configures WireGuard
func RunLogin(ctx context.Context, controlURL string, nodeName string, keyPath string, logger *slog.Logger) error {
	if logger == nil {
		logger = slog.Default()
	}

	controlURL = strings.TrimRight(controlURL, "/")
	if controlURL == "" {
		controlURL = "https://control.flarelens.dev"
	}

	// 1. Resolve Node Name
	if nodeName == "" {
		host, err := os.Hostname()
		if err != nil {
			host = "workstation"
		}
		nodeName = strings.ToLower(strings.ReplaceAll(host, ".", "-"))
	}

	// 2. Resolve Key Path
	if keyPath == "" {
		usr, err := user.Current()
		if err == nil && usr.HomeDir != "" {
			keyPath = filepath.Join(usr.HomeDir, ".flarelens", "mesh.key")
		} else {
			keyPath = filepath.Join(".", ".flarelens-mesh.key")
		}
	}
	_ = os.MkdirAll(filepath.Dir(keyPath), 0700)

	// 3. Load or generate WireGuard Curve25519 keypair
	privKey, pubKey, err := LoadOrGenerateKeypair(keyPath)
	if err != nil {
		return fmt.Errorf("failed to generate WireGuard keypair: %w", err)
	}

	// 3b. Ensure Sovereign SSH Keypair
	_, sshPub, sshErr := EnsureSSHKeypair(filepath.Dir(keyPath))
	if sshErr != nil {
		logger.Debug("Could not initialize sovereign SSH keypair during login", "error", sshErr)
	}

	// 4. Request Device Code from Control Plane
	codeURL := fmt.Sprintf("%s/api/v1/auth/device/code", controlURL)
	payload := map[string]any{
		"public_key":     pubKey,
		"ssh_public_key": sshPub,
		"hostname":       nodeName,
		"name":           nodeName,
		"os":             fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
	}
	bodyBytes, _ := json.Marshal(payload)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, codeURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to contact coordinator at %s: %w", controlURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errData map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&errData)
		return fmt.Errorf("device flow initiation failed (HTTP %d): %v", resp.StatusCode, errData["error"])
	}

	var codeResp DeviceCodeResponse
	if err := json.NewDecoder(resp.Body).Decode(&codeResp); err != nil {
		return fmt.Errorf("failed to parse device code response: %w", err)
	}

	authURL := codeResp.VerificationURIComplete
	if authURL == "" {
		authURL = fmt.Sprintf("%s?code=%s", codeResp.VerificationURI, codeResp.UserCode)
	}

	fmt.Println()
	fmt.Println("================================================================")
	fmt.Println("  🛡️  FlareLens Sovereign Mesh SSO Login")
	fmt.Println("================================================================")
	fmt.Println("  To authenticate this device with Cloudflare Access, visit:")
	fmt.Println()
	fmt.Printf("    👉 %s\n", authURL)
	fmt.Println()
	fmt.Printf("  • Verification Code : %s\n", codeResp.UserCode)
	fmt.Printf("  • Device Name       : %s\n", nodeName)
	fmt.Println("================================================================")
	fmt.Println("Opening your default browser...")
	openBrowser(authURL)

	fmt.Println("\nWaiting for approval in your browser (Press Ctrl+C to cancel)...")

	// 5. Polling Loop
	pollInterval := time.Duration(codeResp.Interval) * time.Second
	if pollInterval < time.Second {
		pollInterval = 2 * time.Second
	}
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	tokenURL := fmt.Sprintf("%s/api/v1/auth/device/token", controlURL)
	pollPayload, _ := json.Marshal(map[string]string{"device_code": codeResp.DeviceCode})

	spinnerChars := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	spinIdx := 0

	for {
		select {
		case <-ctx.Done():
			fmt.Println("\nCancelled authentication.")
			return nil
		case <-ticker.C:
			fmt.Printf("\r  %s Awaiting approval...", spinnerChars[spinIdx%len(spinnerChars)])
			spinIdx++

			pReq, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, bytes.NewReader(pollPayload))
			if err != nil {
				continue
			}
			pReq.Header.Set("Content-Type", "application/json")

			pResp, err := client.Do(pReq)
			if err != nil {
				continue
			}

			var tokenResp DeviceTokenResponse
			_ = json.NewDecoder(pResp.Body).Decode(&tokenResp)
			pResp.Body.Close()

			if tokenResp.Status == "approved" {
				fmt.Print("\r                                      \r")
				return handleSuccessfulLogin(ctx, tokenResp, privKey, pubKey, nodeName, keyPath, controlURL, logger)
			}

			if tokenResp.Error == "access_denied" {
				fmt.Print("\r                                      \r")
				return fmt.Errorf("access denied: device was rejected by the approving administrator")
			}

			if tokenResp.Error == "expired_token" {
				fmt.Print("\r                                      \r")
				return fmt.Errorf("device authorization timed out; please run 'flarelens-agent login' again")
			}
		}
	}
}

func handleSuccessfulLogin(
	ctx context.Context,
	resp DeviceTokenResponse,
	privKey string,
	pubKey string,
	nodeName string,
	keyPath string,
	controlURL string,
	logger *slog.Logger,
) error {
	assignedIP := resp.Peer.OverlayIP
	if assignedIP == "" {
		assignedIP = resp.Peer.TailscaleIP
	}
	if assignedIP == "" {
		assignedIP = "100.64.0.2"
	}

	confContent := GenerateWireGuardConfig(privKey, assignedIP, resp.Peers)
	confPath := filepath.Join(filepath.Dir(keyPath), "flarelens-mesh.conf")
	_ = os.WriteFile(confPath, []byte(confContent), 0600)

	// Persist state for status CLI and background daemon
	state := &MeshState{
		DeviceName:     nodeName,
		PublicKey:      pubKey,
		PrivateKeyPath: keyPath,
		OverlayIP:      assignedIP,
		Subnet:         resp.Subnet,
		ControlURL:     controlURL,
		ApprovedBy:     resp.ApprovedBy,
		Interface:      "flarelens0",
		ConfigPath:     confPath,
		Peers:          resp.Peers,
	}
	_ = SaveState(state)

	userLabel := resp.ApprovedBy
	if userLabel == "" {
		userLabel = "Cloudflare Access"
	}

	fmt.Println("================================================================")
	fmt.Printf("  [✓] Authenticated successfully via %s!\n", userLabel)
	fmt.Println("================================================================")
	fmt.Printf("  • Allocated Mesh IP : %s/10 (Carrier-Grade NAT)\n", assignedIP)
	fmt.Printf("  • Subnet Overlay    : %s\n", resp.Subnet)
	fmt.Printf("  • Active Mesh Peers : %d node(s)\n", len(resp.Peers))
	for _, p := range resp.Peers {
		pIP := p.OverlayIP
		if pIP == "" {
			pIP = p.TailscaleIP
		}
		if pIP != assignedIP {
			endpoint := p.Endpoint
			if endpoint != "" {
				fmt.Printf("    - %s (%s) -> %s (Endpoint: %s)\n", p.Name, p.ID, pIP, endpoint)
			} else {
				fmt.Printf("    - %s (%s) -> %s\n", p.Name, p.ID, pIP)
			}
		}
	}
	fmt.Printf("  • WireGuard Profile : %s\n", confPath)
	fmt.Println("================================================================")

	// Linux Kernel Root Native Activation (Zero external tools required)
	if runtime.GOOS == "linux" {
		if os.Geteuid() == 0 {
			meshCfg := Config{
				Enabled:       true,
				InterfaceName: "flarelens0",
				ListenPort:    51820,
				OverlayIP:     assignedIP,
				Subnet:        "100.64.0.0/10",
			}
			mgr := NewManager(meshCfg, privKey, pubKey, nil, logger)
			if err := mgr.InitInterface(ctx); err == nil {
				_ = mgr.SyncPeers(ctx, resp.Peers)
				fmt.Println("🚀 WireGuard kernel interface [flarelens0] is UP and ACTIVE!")

				// Initialize and activate MagicDNS for *.mesh resolution
				dnsCfg := MagicDNSConfig{
					DomainSuffix:  ".mesh",
					InterfaceName: "flarelens0",
					SyncHostsFile: true,
				}
				dnsServer := NewMagicDNSServer(dnsCfg, logger)
				dnsServer.UpdatePeers(resp.Peers, assignedIP, nodeName)
				fmt.Println("🔮 In-Memory MagicDNS is ACTIVE (*.mesh zero-latency resolution)!")

				fmt.Println("\n✅ Connected to FlareLens Sovereign Mesh!")
				fmt.Println("   Run 'flarelens-agent status' anytime to inspect mesh peers and stats.")

				// Check if systemd service exists and restart it
				if _, lookErr := exec.LookPath("systemctl"); lookErr == nil {
					if checkErr := exec.Command("systemctl", "status", "flarelens-agent").Run(); checkErr == nil {
						_ = exec.Command("systemctl", "restart", "flarelens-agent").Run()
						fmt.Println("⚙️  Restarted background systemd service: flarelens-agent")
					}
				}
			} else {
				logger.Warn("Failed to configure native WireGuard interface", "error", err)
			}
		} else {
			fmt.Println("\n🔒 Run with sudo for automated interface activation: sudo flarelens-agent login")
		}
	} else {
		fmt.Printf("\n[✓] WireGuard profile saved to: %s\n", confPath)
	}

	return nil
}
