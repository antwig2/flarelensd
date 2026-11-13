package mesh

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// FormatBytes formats byte counts into human-readable strings (e.g. 1.4 MB)
func FormatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

// FormatTimeAgo formats a past time into a human-friendly duration (e.g. 14s ago)
func FormatTimeAgo(t time.Time) string {
	if t.IsZero() || t.Unix() <= 0 {
		return "never"
	}
	diff := time.Since(t)
	if diff < 0 {
		return "just now"
	}
	if diff < time.Minute {
		return fmt.Sprintf("%ds ago", int(diff.Seconds()))
	}
	if diff < time.Hour {
		return fmt.Sprintf("%dm ago", int(diff.Minutes()))
	}
	if diff < 24*time.Hour {
		return fmt.Sprintf("%dh ago", int(diff.Hours()))
	}
	return fmt.Sprintf("%dd ago", int(diff.Hours()/24))
}

// RunStatus inspects the active WireGuard interface and prints real-time telemetry
func RunStatus(ctx context.Context, logger *slog.Logger) error {
	if logger == nil {
		logger = slog.Default()
	}

	state, stateErr := LoadState()

	ifaceName := "flarelens0"
	if state != nil && state.Interface != "" {
		ifaceName = state.Interface
	}

	// 1. Check if interface exists in the OS kernel (works without root/sudo)
	var ifaceUp bool
	var detectedIP string
	if netIface, err := net.InterfaceByName(ifaceName); err == nil {
		ifaceUp = (netIface.Flags & net.FlagUp) != 0
		if addrs, err := netIface.Addrs(); err == nil {
			for _, a := range addrs {
				if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
					detectedIP = ipnet.IP.String()
					break
				}
			}
		}
	}

	// 2. Try to inspect WireGuard interface via native Netlink wgctrl (requires root / CAP_NET_ADMIN)
	var dev *wgtypes.Device
	c, err := wgctrl.New()
	if err == nil {
		defer c.Close()
		d, devErr := c.Device(ifaceName)
		if devErr == nil {
			dev = d
		}
	}

	fmt.Println()
	fmt.Println("================================================================")
	fmt.Println("  🛡️  FlareLens Sovereign Mesh Status")
	fmt.Println("================================================================")

	// If root and device info accessible via Netlink
	if dev != nil {
		overlayIP := ""
		if state != nil && state.OverlayIP != "" {
			overlayIP = state.OverlayIP
		}

		fmt.Println("  • Status         : 🟢 ACTIVE (Kernel WireGuard Line-Rate)")
		fmt.Printf("  • Interface      : %s\n", dev.Name)
		if overlayIP != "" {
			fmt.Printf("  • Mesh Overlay IP: %s/10 (CGNAT Subnet)\n", overlayIP)
		}
		if state != nil && state.DeviceName != "" {
			fmt.Printf("  • Device Name    : %s\n", state.DeviceName)
		}
		if state != nil && state.ControlURL != "" {
			fmt.Printf("  • Coordinator    : %s\n", state.ControlURL)
		}
		if state != nil && state.ApprovedBy != "" {
			fmt.Printf("  • Approved By    : %s\n", state.ApprovedBy)
		}
		fmt.Printf("  • Public Key     : %s\n", dev.PublicKey.String())
		fmt.Printf("  • Listen Port    : %d\n", dev.ListenPort)
		fmt.Println("================================================================")

		// Map peer public keys to known names
		knownMap := make(map[string]Peer)
		if state != nil {
			for _, p := range state.Peers {
				knownMap[p.PublicKey] = p
			}
		}

		fmt.Printf("  Mesh Peers (%d connected):\n", len(dev.Peers))
		if len(dev.Peers) == 0 {
			fmt.Println("    (No other peers currently attached to mesh)")
		} else {
			now := time.Now()
			for _, p := range dev.Peers {
				pubKey := p.PublicKey.String()
				name := pubKey[:10] + "..."
				peerIP := ""
				if len(p.AllowedIPs) > 0 {
					peerIP = p.AllowedIPs[0].IP.String()
				}

				if kp, exists := knownMap[pubKey]; exists {
					name = kp.Name
					if peerIP == "" {
						peerIP = kp.OverlayIP
					}
				}

				endpoint := "direct / roaming"
				if p.Endpoint != nil {
					endpoint = p.Endpoint.String()
				}

				handshakeStr := FormatTimeAgo(p.LastHandshakeTime)
				active := !p.LastHandshakeTime.IsZero() && now.Sub(p.LastHandshakeTime) < 3*time.Minute
				statusBadge := "⚪ IDLE"
				if active {
					statusBadge = "🟢 ONLINE"
				}

				fmt.Printf("\n    [%s] %s (%s)\n", statusBadge, name, peerIP)
				fmt.Printf("      • Endpoint       : %s\n", endpoint)
				fmt.Printf("      • Last Handshake : %s\n", handshakeStr)
				fmt.Printf("      • Network Traffic: Rx: %s | Tx: %s\n",
					FormatBytes(p.ReceiveBytes), FormatBytes(p.TransmitBytes))
			}
		}
		fmt.Println("================================================================")
		return nil
	}

	// If interface is UP in the Linux kernel (even without sudo)
	if ifaceUp {
		overlayIP := detectedIP
		if overlayIP == "" && state != nil && state.OverlayIP != "" {
			overlayIP = state.OverlayIP
		}

		fmt.Println("  • Status         : 🟢 ACTIVE (WireGuard Kernel Interface UP)")
		fmt.Printf("  • Interface      : %s\n", ifaceName)
		if overlayIP != "" {
			fmt.Printf("  • Mesh Overlay IP: %s/10 (CGNAT Subnet)\n", overlayIP)
		}
		if state != nil && state.DeviceName != "" {
			fmt.Printf("  • Device Name    : %s\n", state.DeviceName)
		}
		if state != nil && state.ControlURL != "" {
			fmt.Printf("  • Coordinator    : %s\n", state.ControlURL)
		}
		if state != nil && state.ApprovedBy != "" {
			fmt.Printf("  • Approved By    : %s\n", state.ApprovedBy)
		}
		if state != nil && len(state.Peers) > 0 {
			fmt.Printf("  • Mesh Peers     : %d configured node(s)\n", len(state.Peers))
			for _, p := range state.Peers {
				fmt.Printf("    - %s (%s) -> %s\n", p.Name, p.ID, p.OverlayIP)
			}
		}
		fmt.Println("================================================================")
		fmt.Println("  💡 Note: Run 'sudo flarelens-agent status' to inspect real-time peer handshakes & live byte telemetry.")
		fmt.Println("================================================================")
		return nil
	}

	// If interface is not currently active:
	if stateErr == nil && state != nil {
		fmt.Println("  • Status         : 🔴 INACTIVE / DISCONNECTED")
		fmt.Printf("  • Configured Node: %s\n", state.DeviceName)
		fmt.Printf("  • Allocated IP   : %s/10\n", state.OverlayIP)
		fmt.Printf("  • Coordinator    : %s\n", state.ControlURL)
		if state.ApprovedBy != "" {
			fmt.Printf("  • Authenticated  : %s\n", state.ApprovedBy)
		}
		if state.ConfigPath != "" {
			fmt.Printf("  • WireGuard File : %s\n", state.ConfigPath)
		}
		fmt.Println("================================================================")
		fmt.Println("  💡 To connect to the FlareLens Sovereign Mesh:")
		fmt.Println("     • sudo flarelens-agent login")
		fmt.Println("================================================================")
		return nil
	}

	// Device not logged in
	fmt.Println("  • Status         : ⚪ NOT ENROLLED")
	fmt.Println("================================================================")
	fmt.Println("  💡 To enroll this device in FlareLens Sovereign Mesh:")
	fmt.Println("     • Run: sudo flarelens-agent login")
	fmt.Println("================================================================")
	return nil
}
