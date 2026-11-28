package deploy

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"
)

// ContainerLogStreamRequest describes a live or snapshot container log stream command from the Control Plane.
type ContainerLogStreamRequest struct {
	SessionID       string `json:"session_id"`
	Env             string `json:"env,omitempty"`
	Service         string `json:"service,omitempty"`
	ContainerName   string `json:"container_name,omitempty"`
	TailLines       int    `json:"tail_lines,omitzero"`
	Follow          bool   `json:"follow,omitzero"`
	Timestamps      bool   `json:"timestamps,omitzero"`
	DurationSeconds int    `json:"duration_seconds,omitzero"`
}

// ContainerLogPushPayload is posted by the agent to `/api/v1/control/containers/logs/push`.
type ContainerLogPushPayload struct {
	SessionID     string `json:"session_id"`
	NodeID        string `json:"node_id"`
	Env           string `json:"env,omitempty"`
	Service       string `json:"service,omitempty"`
	ContainerID   string `json:"container_id,omitempty"`
	ContainerName string `json:"container_name,omitempty"`
	Seq           int    `json:"seq"`
	Chunk         string `json:"chunk,omitempty"`
	EOF           bool   `json:"eof,omitzero"`
	Error         string `json:"error,omitempty"`
}

func normalizeLogEnv(envName string) string {
	e := strings.ToLower(strings.TrimSpace(envName))
	switch e {
	case "production":
		return "prod"
	case "infrastructure":
		return "infra"
	default:
		return e
	}
}

// ResolveServiceContainer resolves a logical service (e.g. `postgres`, `benthos-cdc`, `radius`, `checkout-api`)
// or an explicit container name/ID to the best matching container on this host, preferring running active slots.
func (o *Orchestrator) ResolveServiceContainer(ctx context.Context, envName, target string) (string, string, error) {
	if o == nil || o.runner == nil {
		return "", "", fmt.Errorf("docker runner unavailable")
	}
	cleanTarget := strings.TrimPrefix(strings.TrimSpace(target), "/")
	cleanEnv := normalizeLogEnv(envName)
	if cleanTarget == "" {
		return "", "", fmt.Errorf("service or container name is required")
	}

	containers, err := o.runner.ListAllContainers(ctx)
	if err != nil {
		return "", "", fmt.Errorf("failed to list containers: %w", err)
	}

	lowerTarget := strings.ToLower(cleanTarget)

	// 1. Exact container name or container ID prefix match
	for _, c := range containers {
		if strings.HasPrefix(strings.ToLower(c.ID), lowerTarget) && len(lowerTarget) >= 6 {
			return c.ID, cmp.Or(firstNonEmpty(c.Names), c.ID[:12]), nil
		}
		for _, n := range c.Names {
			cleanName := strings.TrimPrefix(n, "/")
			if strings.EqualFold(cleanName, cleanTarget) {
				return c.ID, cleanName, nil
			}
		}
	}

	o.mu.RLock()
	activeSlot := o.activeSlots[cleanTarget]
	o.mu.RUnlock()

	type scoredMatch struct {
		id    string
		name  string
		score int
	}
	var best scoredMatch

	for _, c := range containers {
		primaryName := strings.TrimPrefix(firstNonEmpty(c.Names), "/")
		lowerName := strings.ToLower(primaryName)
		lblSvc := strings.ToLower(strings.TrimSpace(c.Labels["flarelens.service"]))
		lblEnv := normalizeLogEnv(c.Labels["flarelens.env"])
		lblSlot := strings.ToLower(strings.TrimSpace(c.Labels["flarelens.slot"]))
		isRunning := strings.EqualFold(c.State, "running")

		matchedSvc := false
		if lblSvc == lowerTarget {
			matchedSvc = true
		} else if lowerName == lowerTarget ||
			lowerName == lowerTarget+"-blue" ||
			lowerName == lowerTarget+"-green" ||
			lowerName == lowerTarget+"-"+cleanEnv ||
			lowerName == cleanEnv+"-"+lowerTarget ||
			strings.HasSuffix(lowerName, "-"+cleanEnv+"-"+lowerTarget) ||
			(cleanEnv == "infra" && strings.HasSuffix(lowerName, "-infrastructure-"+lowerTarget)) ||
			(cleanEnv == "" && (strings.HasSuffix(lowerName, "-"+lowerTarget) || strings.HasPrefix(lowerName, lowerTarget+"-"))) {
			matchedSvc = true
		} else {
			for _, aliases := range c.Networks {
				for _, al := range aliases {
					if strings.EqualFold(al, cleanTarget) {
						matchedSvc = true
						break
					}
				}
				if matchedSvc {
					break
				}
			}
		}
		if !matchedSvc {
			continue
		}

		// Filter out wrong environment when envName is explicitly requested
		if cleanEnv != "" {
			if lblEnv != "" && lblEnv != cleanEnv {
				continue
			}
			if lblEnv == "" {
				otherEnvs := []string{"uat", "prod", "staging", "dev", "infra", "infrastructure"}
				wrongEnv := false
				for _, oe := range otherEnvs {
					normOE := normalizeLogEnv(oe)
					if normOE == cleanEnv {
						continue
					}
					if strings.Contains(lowerName, "-"+oe+"-") ||
						strings.HasSuffix(lowerName, "-"+oe) ||
						strings.HasPrefix(lowerName, oe+"-") {
						wrongEnv = true
						break
					}
				}
				if wrongEnv {
					continue
				}
			}
		}

		score := 10
		if isRunning {
			score += 100
		}
		if cleanEnv != "" && (lblEnv == cleanEnv || strings.Contains(lowerName, cleanEnv) || (cleanEnv == "infra" && strings.Contains(lowerName, "infrastructure"))) {
			score += 30
		}
		if activeSlot != "" && (lblSlot == string(activeSlot) || strings.HasSuffix(lowerName, "-"+string(activeSlot))) {
			score += 25
		}
		for _, aliases := range c.Networks {
			if slices.Contains(aliases, lowerTarget) {
				score += 15
				break
			}
		}
		if score > best.score {
			best = scoredMatch{id: c.ID, name: cmp.Or(primaryName, c.ID), score: score}
		}
	}

	if best.id != "" {
		return best.id, best.name, nil
	}

	// Fallback direct Docker inspect if container was omitted from summary filter
	if id, findErr := o.runner.FindContainerIDByName(ctx, cleanTarget); findErr == nil && id != "" {
		return id, cleanTarget, nil
	}

	if cleanEnv != "" {
		return "", "", fmt.Errorf("no container found for %s/%s on node %s", cleanEnv, cleanTarget, o.nodeID)
	}
	return "", "", fmt.Errorf("no container found matching %q on node %s", cleanTarget, o.nodeID)
}

// StopContainerLogSession cancels an active follow log stream by session ID.
func (o *Orchestrator) StopContainerLogSession(sessionID string) {
	if o == nil || sessionID == "" {
		return
	}
	o.mu.Lock()
	cancel, ok := o.logStreams[sessionID]
	delete(o.logStreams, sessionID)
	o.mu.Unlock()
	if ok && cancel != nil {
		cancel()
	}
}

// CloseAllLogSessions cancels all active container log streams (called on agent shutdown).
func (o *Orchestrator) CloseAllLogSessions() {
	if o == nil {
		return
	}
	o.mu.Lock()
	cancels := make([]context.CancelFunc, 0, len(o.logStreams))
	for id, c := range o.logStreams {
		if c != nil {
			cancels = append(cancels, c)
		}
		delete(o.logStreams, id)
	}
	o.mu.Unlock()
	for _, c := range cancels {
		c()
	}
}

// StreamContainerLogSession resolves the target container and streams batched stdout/stderr chunks via pushFn.
func (o *Orchestrator) StreamContainerLogSession(
	parentCtx context.Context,
	req ContainerLogStreamRequest,
	pushFn func(payload ContainerLogPushPayload) (stop bool, err error),
) {
	if o == nil || pushFn == nil || strings.TrimSpace(req.SessionID) == "" {
		return
	}
	maxDur := time.Duration(cmp.Or(req.DurationSeconds, 120)) * time.Second
	if maxDur > 5*time.Minute {
		maxDur = 5 * time.Minute
	}
	ctx, cancel := context.WithTimeout(parentCtx, maxDur)

	o.mu.Lock()
	if prev, ok := o.logStreams[req.SessionID]; ok && prev != nil {
		prev()
	}
	o.logStreams[req.SessionID] = cancel
	o.mu.Unlock()

	defer func() {
		cancel()
		o.mu.Lock()
		delete(o.logStreams, req.SessionID)
		o.mu.Unlock()
	}()

	target := cmp.Or(strings.TrimSpace(req.ContainerName), strings.TrimSpace(req.Service))
	containerID, containerName, err := o.ResolveServiceContainer(ctx, req.Env, target)
	if err != nil {
		_, _ = pushFn(ContainerLogPushPayload{
			SessionID: req.SessionID,
			NodeID:    o.nodeID,
			Env:       req.Env,
			Service:   req.Service,
			Seq:       1,
			EOF:       true,
			Error:     err.Error(),
		})
		return
	}

	tailLines := req.TailLines
	if tailLines == 0 {
		tailLines = 200
	}

	var bufMu sync.Mutex
	var pending strings.Builder
	seq := 0

	flushLocked := func(eof bool, errMsg string) (bool, error) {
		if pending.Len() == 0 && !eof && errMsg == "" {
			return false, nil
		}
		seq++
		chunk := pending.String()
		pending.Reset()
		payload := ContainerLogPushPayload{
			SessionID:     req.SessionID,
			NodeID:        o.nodeID,
			Env:           req.Env,
			Service:       req.Service,
			ContainerID:   containerID,
			ContainerName: containerName,
			Seq:           seq,
			Chunk:         chunk,
			EOF:           eof,
			Error:         errMsg,
		}
		bufMu.Unlock()
		stop, pErr := pushFn(payload)
		bufMu.Lock()
		return stop, pErr
	}

	doneTicker := make(chan struct{})
	var tickerWG sync.WaitGroup
	if req.Follow {
		tickerWG.Go(func() {
			ticker := time.NewTicker(250 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-doneTicker:
					return
				case <-ctx.Done():
					return
				case <-ticker.C:
					bufMu.Lock()
					stop, _ := flushLocked(false, "")
					bufMu.Unlock()
					if stop {
						cancel()
						return
					}
				}
			}
		})
	}

	errStop := fmt.Errorf("log session stopped by viewer")
	streamErr := o.runner.StreamContainerLogs(ctx, containerID, tailLines, req.Follow, req.Timestamps, func(text string) error {
		bufMu.Lock()
		pending.WriteString(text)
		var stop bool
		if pending.Len() >= 8192 {
			stop, _ = flushLocked(false, "")
		}
		bufMu.Unlock()
		if stop {
			cancel()
			return errStop
		}
		return nil
	})

	close(doneTicker)
	tickerWG.Wait()

	var errText string
	if streamErr != nil && streamErr != errStop && ctx.Err() == nil {
		errText = streamErr.Error()
	}

	bufMu.Lock()
	_, _ = flushLocked(true, errText)
	bufMu.Unlock()
}
