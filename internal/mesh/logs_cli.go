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
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// RemoteLogsOptions configures `flarelensd logs <service>` over the FlareLens Control Plane.
type RemoteLogsOptions struct {
	Target      string // Service name (e.g. `postgres`, `benthos-cdc`) or explicit container name
	Env         string // Optional environment filter (`uat`, `prod`, `infra`)
	NodeID      string // Optional target node_id
	TailLines   int    // Number of initial tail lines (default 200)
	Follow      bool   // Stream live output until Ctrl+C
	Timestamps  bool   // Include Docker RFC3339Nano timestamps
	ControlURL  string
	AuthToken   string
	PeerID      string
	PublicKey   string
	SSHKeyPath  string
	Output      io.Writer
	HTTPClient  *http.Client
	PollEvery   time.Duration
}

// SignContainerLogsProof signs `flarelens-container-logs:<action>:<public_key>:<timestamp>`
// using the workstation's OpenSSH Ed25519 key (`~/.flarelens/id_ed25519`).
func SignContainerLogsProof(sshPrivKeyPath, action, wgPublicKey, timestamp string) (string, error) {
	pemBytes, err := os.ReadFile(sshPrivKeyPath)
	if err != nil {
		return "", err
	}
	rawKey, err := ssh.ParseRawPrivateKey(pemBytes)
	if err != nil {
		return "", err
	}
	var edPriv ed25519.PrivateKey
	switch k := rawKey.(type) {
	case ed25519.PrivateKey:
		edPriv = k
	case *ed25519.PrivateKey:
		if k != nil {
			edPriv = *k
		}
	default:
		return "", fmt.Errorf("unsupported SSH private key type %T", rawKey)
	}
	if len(edPriv) != ed25519.PrivateKeySize {
		return "", errors.New("invalid Ed25519 private key length")
	}
	msg := fmt.Sprintf("flarelens-container-logs:%s:%s:%s", action, wgPublicKey, timestamp)
	sig := ed25519.Sign(edPriv, []byte(msg))
	return base64.StdEncoding.EncodeToString(sig), nil
}

// RunRemoteLogsCLI opens a zero-SSH container log session via the Control Plane and streams output to stdout.
func RunRemoteLogsCLI(ctx context.Context, opts RemoteLogsOptions) error {
	out := opts.Output
	if out == nil {
		out = os.Stdout
	}

	target := strings.TrimSpace(opts.Target)
	if target == "" {
		return errors.New("service or container name is required")
	}

	state, _ := LoadState()
	controlURL := strings.TrimRight(strings.TrimSpace(opts.ControlURL), "/")
	pubKey := strings.TrimSpace(opts.PublicKey)
	peerID := strings.TrimSpace(opts.PeerID)
	sshKeyPath := strings.TrimSpace(opts.SSHKeyPath)

	if state != nil {
		controlURL = cmp.Or(controlURL, strings.TrimRight(state.ControlURL, "/"))
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
		return errors.New("control plane URL not configured (run 'sudo flarelensd login --control https://<control-plane>' or pass --control)")
	}

	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	pollEvery := cmp.Or(opts.PollEvery, 450*time.Millisecond)
	tailLines := opts.TailLines
	if tailLines == 0 {
		tailLines = 200
	}

	ts := strconv.FormatInt(time.Now().Unix(), 10)
	openBody := map[string]any{
		"service":     target,
		"env":         strings.TrimSpace(opts.Env),
		"node_id":     strings.TrimSpace(opts.NodeID),
		"tail_lines":  tailLines,
		"follow":      opts.Follow,
		"timestamps":  opts.Timestamps,
		"peer_id":     peerID,
		"public_key":  pubKey,
		"timestamp":   ts,
	}
	if opts.AuthToken == "" && sshKeyPath != "" && pubKey != "" {
		if sig, err := SignContainerLogsProof(sshKeyPath, "open", pubKey, ts); err == nil {
			openBody["ssh_signature"] = sig
		}
	}

	rawOpen, _ := json.Marshal(openBody)
	openReq, err := http.NewRequestWithContext(ctx, http.MethodPost, controlURL+"/api/v1/control/containers/logs/sessions", bytes.NewReader(rawOpen))
	if err != nil {
		return err
	}
	openReq.Header.Set("Content-Type", "application/json")
	if opts.AuthToken != "" {
		openReq.Header.Set("Authorization", "Bearer "+opts.AuthToken)
	}

	resp, err := client.Do(openReq)
	if err != nil {
		return fmt.Errorf("failed to request container logs from Control Plane: %w", err)
	}
	var openRes struct {
		Session struct {
			SessionID string `json:"session_id"`
			NodeID    string `json:"node_id"`
		} `json:"session"`
		Error string `json:"error"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&openRes)
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("log session rejected (HTTP %d): %s", resp.StatusCode, cmp.Or(openRes.Error, resp.Status))
	}
	sessionID := openRes.Session.SessionID
	if sessionID == "" {
		return errors.New("control plane returned empty log session_id")
	}

	defer func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		closeTs := strconv.FormatInt(time.Now().Unix(), 10)
		closeBody := map[string]string{
			"peer_id":    peerID,
			"public_key": pubKey,
			"timestamp":  closeTs,
		}
		if opts.AuthToken == "" && sshKeyPath != "" && pubKey != "" {
			if sig, err := SignContainerLogsProof(sshKeyPath, "close", pubKey, closeTs); err == nil {
				closeBody["ssh_signature"] = sig
			}
		}
		rawClose, _ := json.Marshal(closeBody)
		delURL := fmt.Sprintf("%s/api/v1/control/containers/logs/sessions/%s", controlURL, url.PathEscape(sessionID))
		if delReq, reqErr := http.NewRequestWithContext(closeCtx, http.MethodDelete, delURL, bytes.NewReader(rawClose)); reqErr == nil {
			delReq.Header.Set("Content-Type", "application/json")
			if opts.AuthToken != "" {
				delReq.Header.Set("Authorization", "Bearer "+opts.AuthToken)
			}
			if r, doErr := client.Do(delReq); doErr == nil {
				_ = r.Body.Close()
			}
		}
	}()

	afterSeq := 0
	ticker := time.NewTicker(pollEvery)
	defer ticker.Stop()

	pollOnce := func() (done bool, err error) {
		readTs := strconv.FormatInt(time.Now().Unix(), 10)
		q := url.Values{}
		q.Set("after", strconv.Itoa(afterSeq))
		if opts.AuthToken == "" && sshKeyPath != "" && pubKey != "" {
			if sig, sigErr := SignContainerLogsProof(sshKeyPath, "read", pubKey, readTs); sigErr == nil {
				q.Set("peer_id", peerID)
				q.Set("public_key", pubKey)
				q.Set("timestamp", readTs)
				q.Set("ssh_signature", sig)
			}
		}
		pollURL := fmt.Sprintf("%s/api/v1/control/containers/logs/sessions/%s?%s", controlURL, url.PathEscape(sessionID), q.Encode())
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, pollURL, nil)
		if err != nil {
			return false, err
		}
		if opts.AuthToken != "" {
			req.Header.Set("Authorization", "Bearer "+opts.AuthToken)
		}
		pResp, err := client.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return true, nil
			}
			return false, err
		}
		var pollBody struct {
			Session struct {
				Status        string `json:"status"`
				ContainerName string `json:"container_name"`
				Error         string `json:"error"`
			} `json:"session"`
			Chunks []struct {
				Seq  int    `json:"seq"`
				Text string `json:"text"`
			} `json:"chunks"`
			Error string `json:"error"`
		}
		_ = json.NewDecoder(pResp.Body).Decode(&pollBody)
		_ = pResp.Body.Close()

		if pResp.StatusCode != http.StatusOK {
			return true, fmt.Errorf("log stream failed (HTTP %d): %s", pResp.StatusCode, cmp.Or(pollBody.Error, pResp.Status))
		}

		for _, ch := range pollBody.Chunks {
			if ch.Seq > afterSeq {
				afterSeq = ch.Seq
				if ch.Text != "" {
					_, _ = io.WriteString(out, ch.Text)
				}
			}
		}

		if pollBody.Session.Error != "" {
			return true, errors.New(pollBody.Session.Error)
		}
		if pollBody.Session.Status == "eof" || pollBody.Session.Status == "closed" || (!opts.Follow && afterSeq > 0) {
			return true, nil
		}
		return false, nil
	}

	if done, err := pollOnce(); err != nil || done {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			done, err := pollOnce()
			if err != nil || done {
				return err
			}
		}
	}
}
