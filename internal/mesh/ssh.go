package mesh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

const (
	OpenSSHConfigPath   = "/etc/ssh/sshd_config.d/99-flarelens-ssh.conf"
	DefaultSSHKeyDir    = ".flarelens"
	DefaultSSHKeyName   = "id_ed25519"
)

// EnsureSSHKeypair checks for existing Ed25519 keypair or generates a new one
// Returns private key path and OpenSSH authorized_key public string
func EnsureSSHKeypair(dir string) (privPath string, pubAuthorized string, err error) {
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", "", fmt.Errorf("failed to resolve user home: %w", err)
		}
		dir = filepath.Join(home, DefaultSSHKeyDir)
	}

	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", "", fmt.Errorf("failed to create ssh key directory %s: %w", dir, err)
	}

	privPath = filepath.Join(dir, DefaultSSHKeyName)
	pubPath := privPath + ".pub"

	// If keys already exist, load and return
	if _, err := os.Stat(privPath); err == nil {
		pubData, err := os.ReadFile(pubPath)
		if err == nil && len(pubData) > 0 {
			return privPath, strings.TrimSpace(string(pubData)), nil
		}
	}

	// Generate new Ed25519 keypair
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate ed25519 keypair: %w", err)
	}

	// Encode private key to OpenSSH PEM format
	privBlock, err := ssh.MarshalPrivateKey(privKey, "flarelens-mesh-key")
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal private key: %w", err)
	}
	privPem := pem.EncodeToMemory(privBlock)
	if err := os.WriteFile(privPath, privPem, 0600); err != nil {
		return "", "", fmt.Errorf("failed to save private key to %s: %w", privPath, err)
	}

	// Encode public key to OpenSSH authorized_keys format
	sshPub, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to parse ssh public key: %w", err)
	}
	pubBytes := ssh.MarshalAuthorizedKey(sshPub)
	pubStr := strings.TrimSpace(string(pubBytes)) + " flarelens-mesh"
	if err := os.WriteFile(pubPath, []byte(pubStr+"\n"), 0644); err != nil {
		return "", "", fmt.Errorf("failed to save public key to %s: %w", pubPath, err)
	}

	return privPath, pubStr, nil
}

// RunSSHAuth is invoked by OpenSSH AuthorizedKeysCommand to dynamically validate keys
func RunSSHAuth(requestedUser, incomingKey, keyType string, statePath string, out io.Writer, logger *slog.Logger) error {
	if logger == nil {
		logger = slog.Default()
	}
	if out == nil {
		out = os.Stdout
	}

	// Load mesh state to inspect approved peers
	var state *MeshState
	var err error
	if statePath != "" {
		state, err = LoadStateFromPath(statePath)
	} else {
		state, err = LoadState()
	}

	if err != nil || state == nil {
		logger.Debug("No mesh state found during ssh-auth query", "error", err)
		return nil // Return empty output -> OpenSSH moves to next auth method
	}

	incomingKey = strings.TrimSpace(incomingKey)

	// Emit all authorized peer SSH keys
	for _, p := range state.Peers {
		key := strings.TrimSpace(p.SSHPublicKey)
		if key == "" {
			continue
		}

		// If OpenSSH passed a specific key argument (%k), filter by match
		if incomingKey != "" {
			fields := strings.Fields(key)
			if len(fields) >= 2 && fields[1] == incomingKey {
				_, _ = fmt.Fprintln(out, key)
				logger.Debug("SSH key authorized for peer", "peer", p.Name, "id", p.ID)
				return nil
			}
		} else {
			// Print all approved operator keys
			_, _ = fmt.Fprintln(out, key)
		}
	}

	return nil
}

// RunSSH launches an SSH session to a target using the sovereign mesh identity
func RunSSH(ctx context.Context, target string, extraArgs []string, logger *slog.Logger) error {
	if logger == nil {
		logger = slog.Default()
	}

	privPath, _, err := EnsureSSHKeypair("")
	if err != nil {
		return fmt.Errorf("failed to verify local ssh keypair: %w", err)
	}

	if target == "" {
		return fmt.Errorf("target node required (e.g. root@node-1.mesh)")
	}

	// Default user to root if not specified
	if !strings.Contains(target, "@") {
		target = "root@" + target
	}

	home, _ := os.UserHomeDir()
	knownHostsPath := filepath.Join(home, DefaultSSHKeyDir, "known_hosts")

	args := []string{
		"-i", privPath,
		"-o", "StrictHostKeyChecking=accept-new",
		"-o", fmt.Sprintf("UserKnownHostsFile=%s", knownHostsPath),
		"-o", "ConnectTimeout=10",
		target,
	}
	args = append(args, extraArgs...)

	sshBinary, err := exec.LookPath("ssh")
	if err != nil {
		return fmt.Errorf("ssh client not found on system: %w", err)
	}

	cmd := exec.CommandContext(ctx, sshBinary, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	logger.Debug("Executing sovereign SSH session", "command", cmd.String())
	return cmd.Run()
}

// ConfigureOpenSSHServer dynamically configures OpenSSH to use FlareLens AuthorizedKeysCommand
func ConfigureOpenSSHServer(enable bool) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("root privileges required to configure sshd")
	}

	if !enable {
		if err := os.Remove(OpenSSHConfigPath); err != nil && !os.IsNotExist(err) {
			return err
		}
		_ = reloadSSHD()
		return nil
	}

	sshdConfigDir := filepath.Dir(OpenSSHConfigPath)
	if err := os.MkdirAll(sshdConfigDir, 0755); err != nil {
		return err
	}

	flarelensBinary, err := exec.LookPath("flarelens-agent")
	if err != nil {
		flarelensBinary = "/usr/local/bin/flarelens-agent"
	}

	content := fmt.Sprintf(`# Managed dynamically by FlareLens Sovereign Mesh
# Dynamic Zero-Trust SSH Authentication via Cloudflare Access
AuthorizedKeysCommand %s ssh-auth %%u %%k %%t
AuthorizedKeysCommandUser root
`, flarelensBinary)

	if err := os.WriteFile(OpenSSHConfigPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write %s: %w", OpenSSHConfigPath, err)
	}

	return reloadSSHD()
}

func reloadSSHD() error {
	if _, err := exec.LookPath("systemctl"); err == nil {
		if err := exec.Command("systemctl", "reload", "sshd").Run(); err == nil {
			return nil
		}
		if err := exec.Command("systemctl", "reload", "ssh").Run(); err == nil {
			return nil
		}
	}
	return nil
}
