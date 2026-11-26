package mesh

import (
	"bytes"
	"cmp"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

var validIfaceNameRe = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,15}$`)

// DisconnectOptions configures mesh interface teardown and optional Control Plane peer revocation.
type DisconnectOptions struct {
	InterfaceName string
	ControlURL    string
	AuthToken     string
	PeerID        string
	PublicKey     string
	KeyPath       string
	SSHKeyPath    string
	HostsPath     string
	GOOS          string
	RevokeRemote  bool
	PurgeState    bool
	PurgeKeys     bool
	Executor      CommandExecutor
	HTTPClient    *http.Client
}

// DisconnectResult summarizes actions performed during mesh disconnect or logout.
type DisconnectResult struct {
	Interface        string   `json:"interface"`
	InterfaceRemoved bool     `json:"interface_removed,omitzero"`
	HostsCleaned     bool     `json:"hosts_cleaned,omitzero"`
	RemoteRevoked    bool     `json:"remote_revoked,omitzero"`
	RemovedFiles     []string `json:"removed_files,omitempty"`
	Warnings         []string `json:"warnings,omitempty"`
}

// ValidateInterfaceName rejects malformed or flag-like network interface names.
func ValidateInterfaceName(iface string) error {
	trimmed := strings.TrimSpace(iface)
	if trimmed == "" {
		return errors.New("interface name cannot be empty")
	}
	if strings.HasPrefix(trimmed, "-") || !validIfaceNameRe.MatchString(trimmed) {
		return fmt.Errorf("invalid network interface name %q", trimmed)
	}
	return nil
}

// TeardownWireGuardInterface removes the WireGuard interface if present on the host.
func TeardownWireGuardInterface(ctx context.Context, iface string, goos string, executor CommandExecutor) (bool, error) {
	iface = cmp.Or(strings.TrimSpace(iface), "flarelens0")
	if err := ValidateInterfaceName(iface); err != nil {
		return false, err
	}
	if executor == nil {
		executor = &OSCommandExecutor{}
	}
	targetOS := cmp.Or(goos, runtime.GOOS)

	switch targetOS {
	case "linux":
		if _, showErr := executor.Run(ctx, "ip", "link", "show", iface); showErr != nil {
			return false, nil
		}
		out, delErr := executor.Run(ctx, "ip", "link", "delete", "dev", iface)
		if delErr != nil {
			msg := strings.TrimSpace(string(out))
			lower := strings.ToLower(msg)
			if strings.Contains(lower, "cannot find device") || strings.Contains(lower, "does not exist") {
				return false, nil
			}
			return false, fmt.Errorf("failed to delete wireguard interface %s: %s (%w)", iface, msg, delErr)
		}
		return true, nil

	case "darwin":
		out, err := executor.Run(ctx, "ifconfig", iface, "destroy")
		if err != nil {
			lower := strings.ToLower(string(out))
			if strings.Contains(lower, "does not exist") || strings.Contains(lower, "invalid") {
				return false, nil
			}
			return false, nil
		}
		return true, nil

	case "windows":
		_, _ = executor.Run(ctx, "wireguard.exe", "/uninstalltunnelservice", iface)
		return true, nil

	default:
		return false, nil
	}
}

// SignMeshLeaveProof produces a base64 Ed25519 signature over "flarelens-mesh-leave:<wg_pub>:<ts>"
// using the operator's sovereign SSH keypair (~/.flarelens/id_ed25519) so SSO workstation peers
// can revoke themselves without holding INGEST_SECRET.
func SignMeshLeaveProof(sshPrivKeyPath, wgPublicKey, timestamp string) (string, error) {
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

	msg := fmt.Sprintf("flarelens-mesh-leave:%s:%s", strings.TrimSpace(wgPublicKey), strings.TrimSpace(timestamp))
	sig := ed25519.Sign(edKey, []byte(msg))
	return base64.StdEncoding.EncodeToString(sig), nil
}

// DeregisterMeshPeer notifies the Control Plane (/api/v1/control/mesh/leave) to remove this peer.
func DeregisterMeshPeer(
	ctx context.Context,
	controlURL string,
	authToken string,
	peerID string,
	publicKey string,
	sshKeyPath string,
	httpClient *http.Client,
) error {
	endpoint := strings.TrimRight(strings.TrimSpace(controlURL), "/")
	if endpoint == "" {
		return errors.New("control plane URL is empty")
	}
	if strings.TrimSpace(peerID) == "" && strings.TrimSpace(publicKey) == "" {
		return errors.New("peer_id or public_key required to deregister mesh peer")
	}

	ts := strconv.FormatInt(time.Now().Unix(), 10)
	payload := map[string]string{
		"peer_id":    strings.TrimSpace(peerID),
		"public_key": strings.TrimSpace(publicKey),
		"timestamp":  ts,
	}
	if sig, err := SignMeshLeaveProof(sshKeyPath, publicKey, ts); err == nil && sig != "" {
		payload["ssh_signature"] = sig
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	reqCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, endpoint+"/api/v1/control/mesh/leave", bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if tok := strings.TrimSpace(authToken); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}

	client := cmp.Or(httpClient, &http.Client{Timeout: 8 * time.Second})
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil // Already absent on control plane
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("control plane returned HTTP %d", resp.StatusCode)
	}
	return nil
}

func resolveDefaultSSHKeyPath(wgKeyPath string) string {
	if wgKeyPath != "" {
		cand := filepath.Join(filepath.Dir(wgKeyPath), DefaultSSHKeyName)
		if _, err := os.Stat(cand); err == nil {
			return cand
		}
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		cand := filepath.Join(home, DefaultSSHKeyDir, DefaultSSHKeyName)
		if _, err := os.Stat(cand); err == nil {
			return cand
		}
	}
	if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" && sudoUser != "root" {
		if usr, err := user.Lookup(sudoUser); err == nil && usr.HomeDir != "" {
			cand := filepath.Join(usr.HomeDir, DefaultSSHKeyDir, DefaultSSHKeyName)
			if _, err := os.Stat(cand); err == nil {
				return cand
			}
		}
	}
	return ""
}

// RunDisconnect tears down the local WireGuard overlay, reverts MagicDNS host entries,
// and optionally revokes the peer from the Control Plane and purges local state/keys.
func RunDisconnect(ctx context.Context, opts DisconnectOptions, logger *slog.Logger) (*DisconnectResult, error) {
	if logger == nil {
		logger = slog.Default()
	}
	execImpl := opts.Executor
	if execImpl == nil {
		execImpl = &OSCommandExecutor{}
	}

	state, _ := LoadState()
	iface := cmp.Or(
		strings.TrimSpace(opts.InterfaceName),
		func() string {
			if state != nil {
				return strings.TrimSpace(state.Interface)
			}
			return ""
		}(),
		"flarelens0",
	)

	controlURL := cmp.Or(
		strings.TrimSpace(opts.ControlURL),
		func() string {
			if state != nil {
				return strings.TrimSpace(state.ControlURL)
			}
			return ""
		}(),
	)
	pubKey := cmp.Or(
		strings.TrimSpace(opts.PublicKey),
		func() string {
			if state != nil {
				return strings.TrimSpace(state.PublicKey)
			}
			return ""
		}(),
	)
	keyPath := cmp.Or(
		strings.TrimSpace(opts.KeyPath),
		func() string {
			if state != nil {
				return strings.TrimSpace(state.PrivateKeyPath)
			}
			return ""
		}(),
	)
	if pubKey == "" && keyPath != "" {
		if _, loadedPub, err := LoadOrGenerateKeypair(keyPath); err == nil {
			pubKey = loadedPub
		}
	}
	peerID := cmp.Or(
		strings.TrimSpace(opts.PeerID),
		func() string {
			if state != nil && state.DeviceName != "" {
				return "client-" + state.DeviceName
			}
			return ""
		}(),
	)
	sshKeyPath := cmp.Or(strings.TrimSpace(opts.SSHKeyPath), resolveDefaultSSHKeyPath(keyPath))

	res := &DisconnectResult{
		Interface: iface,
	}

	// 1. Optional remote peer revocation (logout / --revoke)
	if opts.RevokeRemote && controlURL != "" && (peerID != "" || pubKey != "") {
		if err := DeregisterMeshPeer(ctx, controlURL, opts.AuthToken, peerID, pubKey, sshKeyPath, opts.HTTPClient); err != nil {
			warn := fmt.Sprintf("remote mesh deregistration skipped (%v)", err)
			logger.Warn("Control plane mesh leave warning", "error", err)
			res.Warnings = append(res.Warnings, warn)
		} else {
			res.RemoteRevoked = true
		}
	}

	// 2. Clean host DNS (/etc/hosts block + systemd-resolved revert) BEFORE deleting interface so resolvectl sees the link
	res.HostsCleaned = CleanHostDNS(ctx, iface, opts.HostsPath, func(c context.Context, cmd string, args ...string) ([]byte, error) {
		return execImpl.Run(c, cmd, args...)
	})

	// 3. Tear down WireGuard kernel/userspace interface
	removedIface, ifaceErr := TeardownWireGuardInterface(ctx, iface, opts.GOOS, execImpl)
	if ifaceErr != nil {
		return res, ifaceErr
	}
	res.InterfaceRemoved = removedIface

	// 4. Purge state & WireGuard .conf on logout
	if opts.PurgeState {
		var extra []string
		if state != nil && state.ConfigPath != "" {
			extra = append(extra, state.ConfigPath)
		}
		if keyPath != "" {
			extra = append(extra, filepath.Join(filepath.Dir(keyPath), "flarelens-mesh.conf"))
		}
		res.RemovedFiles = append(res.RemovedFiles, ClearState(extra...)...)
	}

	// 5. Optional cryptographic key wipe (--purge-keys)
	if opts.PurgeKeys {
		var keyCandidates []string
		if keyPath != "" {
			keyCandidates = append(keyCandidates, keyPath)
		}
		if sshKeyPath != "" {
			keyCandidates = append(keyCandidates, sshKeyPath, sshKeyPath+".pub")
		}
		for _, kp := range keyCandidates {
			if err := os.Remove(kp); err == nil {
				res.RemovedFiles = append(res.RemovedFiles, kp)
			}
		}
	}

	return res, nil
}
