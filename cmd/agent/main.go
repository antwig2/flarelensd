package main

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/antwig2/flarelens/internal/backup"
	"github.com/antwig2/flarelens/internal/config"
	"github.com/antwig2/flarelens/internal/deploy"
	"github.com/antwig2/flarelens/internal/docker"
	"github.com/antwig2/flarelens/internal/flags"
	"github.com/antwig2/flarelens/internal/heartbeat"
	"github.com/antwig2/flarelens/internal/mesh"
	"github.com/antwig2/flarelens/internal/system"
	"github.com/antwig2/flarelens/internal/transport"
	"github.com/antwig2/flarelens/internal/updater"
	"github.com/nats-io/nats.go"
)

var activeBackupOps atomic.Int32

var (
	Version = "0.2.3"
	Commit  = "none"
	Date    = "unknown"
	BuiltBy = "unknown"
)

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "--version" || os.Args[1] == "-version" || os.Args[1] == "-v") {
		fmt.Printf("FlareLens Host Agent v%s (commit: %s, built at: %s, built by: %s)\n", Version, Commit, Date, BuiltBy)
		os.Exit(0)
	}

	// Subcommand: self-update (Over-The-Air atomic binary upgrade with SHA-256 verification)
	if len(os.Args) > 1 && (os.Args[1] == "self-update" || os.Args[1] == "update") {
		updateFlags := flag.NewFlagSet("self-update", flag.ExitOnError)
		controlURL := updateFlags.String("control", os.Getenv("FLARELENS_ENDPOINT"), "FlareLens Control Plane URL")
		token := updateFlags.String("token", os.Getenv("FLARELENS_ENROLL_TOKEN"), "Control plane auth token")
		targetVer := updateFlags.String("version", "", "Target release version (default: latest registered release)")
		expectedSHA := updateFlags.String("sha256", "", "Expected SHA-256 hex digest (fetched from control plane if omitted)")
		downloadURL := updateFlags.String("url", "", "Optional explicit binary download URL")
		force := updateFlags.Bool("force", false, "Reinstall even if already on target version")
		configPath := updateFlags.String("config", "", "Optional path to agent config file")
		_ = updateFlags.Parse(os.Args[2:])

		if *controlURL == "" || *token == "" {
			var cfgArgs []string
			if *configPath != "" {
				cfgArgs = []string{"--config", *configPath}
			}
			if loadedCfg, err := config.Load(cfgArgs); err == nil {
				if *controlURL == "" {
					*controlURL = loadedCfg.ControlPlane.Endpoint
				}
				if *token == "" {
					*token = loadedCfg.ControlPlane.EnrollToken
				}
			}
		}

		logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()

		ver := strings.TrimSpace(*targetVer)
		sum := strings.TrimSpace(*expectedSHA)
		dl := strings.TrimSpace(*downloadURL)

		if sum == "" && *controlURL != "" {
			relVer, relSum, relURL, err := fetchLatestReleaseMetadata(ctx, *controlURL, *token, ver)
			if err != nil {
				fmt.Fprintf(os.Stderr, "❌ Failed to query release metadata from control plane: %v\n", err)
				os.Exit(1)
			}
			ver = cmp.Or(ver, relVer)
			sum = cmp.Or(sum, relSum)
			dl = cmp.Or(dl, relURL)
		}

		upd := updater.New(updater.Config{
			CurrentVersion: Version,
			ControlURL:     *controlURL,
			AuthToken:      *token,
			Logger:         logger,
			OnRestart:      func(string) error { return nil },
		})

		res, err := upd.Apply(ctx, updater.UpdateRequest{
			Version:     ver,
			SHA256:      sum,
			DownloadURL: dl,
			Force:       *force,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Self-update failed: %v\n", err)
			os.Exit(1)
		}
		if res.Status == "up_to_date" {
			fmt.Printf("✅ FlareLens Host Agent is already up to date (v%s)\n", res.PreviousVersion)
			os.Exit(0)
		}
		fmt.Printf("✅ Updated FlareLens Host Agent: v%s -> %s\n• Binary: %s\n• SHA-256: %s\n",
			res.PreviousVersion, res.TargetVersion, res.ExecutablePath, res.SHA256)
		os.Exit(0)
	}

	// Subcommand: backup (Runs on-demand streaming database backup directly to Cloudflare R2)
	if len(os.Args) > 1 && os.Args[1] == "backup" {
		cfg, err := config.Load(os.Args[2:])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Configuration error: %v\n", err)
			os.Exit(1)
		}
		logger := initLogger(cfg.Telemetry.LogLevel)
		dumper := backup.NewPostgresDumper(
			cfg.Database.Mode,
			cfg.Database.ServiceName,
			cfg.Database.Host,
			cfg.Database.Port,
			cmp.Or(cfg.Database.User, os.Getenv("PGUSER")),
			cmp.Or(cfg.Database.Database, os.Getenv("PGDATABASE")),
		)
		r2Client := backup.NewR2Client(
			cfg.Database.Backup.R2Endpoint,
			cfg.Database.Backup.R2AccessKeyID,
			cfg.Database.Backup.R2SecretAccessKey,
		)
		backupMgr := backup.NewManager(dumper, r2Client, nil, cfg, logger)
		fmt.Printf("Starting zero-disk streaming backup of %s (%s) to Cloudflare R2 (%s)...\n",
			cfg.Database.Database, cfg.Database.ServiceName, cfg.Database.Backup.R2Bucket)
		meta, err := backupMgr.CreateBackup(context.Background(), "manual_cli")
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Backup failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✅ Backup successfully streamed to Cloudflare R2!\n• Key: %s\n• Bucket: %s\n• Timestamp: %s\n",
			meta.Key, meta.Bucket, meta.Timestamp.Format(time.RFC3339))
		os.Exit(0)
	}

	// Subcommand: status (Displays real-time FlareLens Sovereign Mesh status, peers, and transfer stats)
	if len(os.Args) > 1 && os.Args[1] == "status" {
		logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
		if err := mesh.RunStatus(context.Background(), logger); err != nil {
			fmt.Fprintf(os.Stderr, "❌ Status error: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	// Subcommand: proxy / --socks5 (Zero-Root unprivileged SOCKS5 & HTTP CONNECT proxy)
	if len(os.Args) > 1 && (os.Args[1] == "proxy" || strings.HasPrefix(os.Args[1], "--socks5") || strings.HasPrefix(os.Args[1], "-socks5")) {
		proxyFlags := flag.NewFlagSet("proxy", flag.ExitOnError)
		listenAddr := proxyFlags.String("socks5", "127.0.0.1:1055", "SOCKS5 and HTTP CONNECT proxy listen address")
		user := proxyFlags.String("user", "", "Optional proxy authentication username")
		pass := proxyFlags.String("pass", "", "Optional proxy authentication password")
		allowLAN := proxyFlags.Bool("allow-lan", false, "Allow binding to non-loopback addresses (Security Warning)")

		subArgs := os.Args[1:]
		if os.Args[1] == "proxy" {
			subArgs = os.Args[2:]
		}
		_ = proxyFlags.Parse(subArgs)

		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()

		logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

		// Load cached mesh state to attach MagicDNS if available
		var dnsResolver *mesh.MagicDNSServer
		if state, err := mesh.LoadState(); err == nil && len(state.Peers) > 0 {
			dnsResolver = mesh.NewMagicDNSServer(mesh.MagicDNSConfig{DomainSuffix: ".mesh"}, logger)
			dnsResolver.UpdatePeers(state.Peers, state.OverlayIP, state.DeviceName)
		}

		proxyServer, err := mesh.NewProxyServer(mesh.ProxyConfig{
			ListenAddr:  *listenAddr,
			Username:    *user,
			Password:    *pass,
			AllowLAN:    *allowLAN,
			DNSResolver: dnsResolver,
		}, logger)
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Proxy configuration error: %v\n", err)
			os.Exit(1)
		}

		if err := proxyServer.Start(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "❌ Failed to start proxy: %v\n", err)
			os.Exit(1)
		}
		defer proxyServer.Stop()

		fmt.Println("================================================================")
		fmt.Printf("  🛡️  FlareLens Zero-Root SOCKS5 & HTTP Proxy\n")
		fmt.Println("================================================================")
		fmt.Printf("  • Listening On : %s\n", proxyServer.Addr().String())
		fmt.Printf("  • Protocol     : SOCKS5 (RFC 1928) & HTTP CONNECT (RFC 7231)\n")
		fmt.Printf("  • Privileges   : 0 (Zero Root / Unprivileged)\n")
		if dnsResolver != nil {
			fmt.Printf("  • MagicDNS     : Active (*.mesh resolution enabled)\n")
		}
		fmt.Println("----------------------------------------------------------------")
		fmt.Printf("  Usage in terminal / scripts:\n")
		fmt.Printf("    export ALL_PROXY=socks5h://%s\n", proxyServer.Addr().String())
		fmt.Printf("    curl -x socks5h://%s http://node-1.mesh\n", proxyServer.Addr().String())
		fmt.Println("================================================================")
		fmt.Println("Proxy is running. Press Ctrl+C to terminate.")

		<-ctx.Done()
		fmt.Println("\nShutting down proxy...")
		os.Exit(0)
	}

	// Subcommand: ssh-auth (OpenSSH AuthorizedKeysCommand dynamic query hook)
	// Usage: flarelens-agent ssh-auth %u %k %t
	if len(os.Args) > 1 && os.Args[1] == "ssh-auth" {
		user := ""
		key := ""
		keyType := ""
		if len(os.Args) > 2 {
			user = os.Args[2]
		}
		if len(os.Args) > 3 {
			key = os.Args[3]
		}
		if len(os.Args) > 4 {
			keyType = os.Args[4]
		}
		logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
		if err := mesh.RunSSHAuth(user, key, keyType, "", os.Stdout, logger); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}

	// Subcommand: ssh (Sovereign zero-trust SSH client using mesh identity)
	// Usage: flarelens-agent ssh [user@]target.mesh [extra-ssh-args...]
	if len(os.Args) > 1 && os.Args[1] == "ssh" {
		if len(os.Args) < 3 {
			fmt.Fprintf(os.Stderr, "Usage: flarelensd ssh [user@]target.mesh [extra-ssh-flags...]\n")
			fmt.Fprintf(os.Stderr, "Example: flarelensd ssh root@node-1.mesh\n")
			os.Exit(1)
		}
		target := os.Args[2]
		extraArgs := os.Args[3:]
		logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
		if err := mesh.RunSSH(context.Background(), target, extraArgs, logger); err != nil {
			fmt.Fprintf(os.Stderr, "❌ SSH failed: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	// Subcommand: ssh-setup (Configure local OpenSSH daemon with FlareLens AuthorizedKeysCommand)
	if len(os.Args) > 1 && os.Args[1] == "ssh-setup" {
		sshSetupFlags := flag.NewFlagSet("ssh-setup", flag.ExitOnError)
		enable := sshSetupFlags.Bool("enable", true, "Enable or disable FlareLens OpenSSH integration")
		_ = sshSetupFlags.Parse(os.Args[2:])
		if err := mesh.ConfigureOpenSSHServer(*enable); err != nil {
			fmt.Fprintf(os.Stderr, "❌ OpenSSH setup error: %v\n", err)
			os.Exit(1)
		}
		if *enable {
			fmt.Println("================================================================")
			fmt.Println("  🛡️  FlareLens OpenSSH Dynamic Keyless Integration")
			fmt.Println("================================================================")
			fmt.Printf("  • Config File : %s\n", mesh.OpenSSHConfigPath)
			fmt.Println("  • Mode        : OpenSSH AuthorizedKeysCommand (Dynamic Peer Query)")
			fmt.Println("  • Status      : Active & sshd reloaded")
			fmt.Println("  • Security    : Zero permanent keys, instant offboarding on KV revoke")
			fmt.Println("================================================================")
		} else {
			fmt.Println("✅ FlareLens OpenSSH configuration removed.")
		}
		os.Exit(0)
	}

	// Subcommand: login (Interactive browser SSO device login via Cloudflare Access - Tailscale style)
	if len(os.Args) > 1 && os.Args[1] == "login" {
		loginFlags := flag.NewFlagSet("login", flag.ExitOnError)
		controlURL := loginFlags.String("control", "https://control.flarelens.dev", "FlareLens Control Plane URL")
		nodeName := loginFlags.String("name", "", "Device node name (default: local hostname)")
		keyPath := loginFlags.String("key", "", "Path to WireGuard private key file")
		if len(os.Args) > 2 {
			_ = loginFlags.Parse(os.Args[2:])
		}

		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()

		logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
		if err := mesh.RunLogin(ctx, *controlURL, *nodeName, *keyPath, logger); err != nil {
			fmt.Fprintf(os.Stderr, "❌ Login failed: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	// Subcommand: connect / mesh (Connects workstation or laptop to FlareLens Sovereign Mesh)
	if len(os.Args) > 1 && (os.Args[1] == "connect" || os.Args[1] == "mesh") {
		connectFlags := flag.NewFlagSet("connect", flag.ExitOnError)
		controlURL := connectFlags.String("control", "https://control.flarelens.dev", "FlareLens Control Plane URL")
		enrollToken := connectFlags.String("token", os.Getenv("FLARELENS_ENROLL_TOKEN"), "Enrollment token or auth key")
		nodeName := connectFlags.String("name", "", "Device node name (default: local hostname)")
		keyPath := connectFlags.String("key", "", "Path to WireGuard private key file")
		ifaceName := connectFlags.String("interface", "flarelens0", "WireGuard interface name")
		exportOnly := connectFlags.Bool("export-conf", false, "Export WireGuard .conf file and exit")
		outputPath := connectFlags.String("output", "", "Output path for .conf file")

		subArgs := os.Args[2:]
		if len(os.Args) > 2 && (os.Args[2] == "connect" || os.Args[2] == "up" || os.Args[2] == "client") {
			subArgs = os.Args[3:]
		}
		_ = connectFlags.Parse(subArgs)

		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()

		logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
		opts := mesh.ConnectOptions{
			ControlURL:    *controlURL,
			EnrollToken:   *enrollToken,
			NodeName:      *nodeName,
			KeyPath:       *keyPath,
			InterfaceName: *ifaceName,
			ExportOnly:    *exportOnly,
			OutputPath:    *outputPath,
		}

		if err := mesh.RunConnect(ctx, opts, logger); err != nil {
			fmt.Fprintf(os.Stderr, "❌ Connection failed: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	// 1. Load configuration (Precedence: CLI Flags > ENV > Config File > Defaults)
	cfg, err := config.Load(os.Args[1:])
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		fmt.Fprintf(os.Stderr, "Configuration error: %v\n", err)
		os.Exit(1)
	}

	// 2. Setup structured logging
	logger := initLogger(cfg.Telemetry.LogLevel)
	slog.SetDefault(logger)

	logger.Info("Starting FlareLens Host Agent",
		"version", Version,
		"node_id", cfg.Identity.NodeID,
		"hostname", cfg.Identity.Hostname,
		"provider", cfg.Identity.Provider,
		"region", cfg.Identity.Region,
		"tags", cfg.Identity.Tags,
		"dev_mode", cfg.DevMode,
	)

	if cfg.ConfigFile != "" {
		logger.Info("Loaded configuration file", "path", cfg.ConfigFile)
	}

	// Protect agent daemon from Linux kernel OOM killer (Section 17.1)
	system.ProtectFromOOM(logger)

	// 3. Initialize host metrics sampler and Docker inspector
	sampler := system.NewSampler()
	inspector := docker.NewInspector(cfg.Docker.Socket)

	// Check initial Docker availability
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := inspector.Ping(ctx); err != nil {
		logger.Warn("Docker daemon not reachable via socket", "socket", cfg.Docker.Socket, "error", err)
	} else {
		logger.Info("Connected to Docker Engine", "socket", cfg.Docker.Socket)
	}

	// 4. Initialize Blue/Green deployment engine
	dockerRunner := deploy.NewDockerRunner(cfg.Docker.Socket)
	healthProber := deploy.NewHealthProber()
	discoveredTraefikDir := dockerRunner.DiscoverTraefikRoutesDir(ctx)
	if discoveredTraefikDir != "" {
		logger.Info("Discovered Traefik dynamic routes directory from running container mounts", "dir", discoveredTraefikDir)
	}
	traefikFlipper := deploy.NewTraefikRouteFlipper(discoveredTraefikDir)

	// 5. Connect to NATS Event Fabric (Embedded or Client mode)
	natsClient := transport.NewNATSClient(cfg.NATS.URL, cfg.NATS.AuthToken, logger)
	deployOrchestrator := deploy.NewOrchestrator(dockerRunner, healthProber, traefikFlipper, natsClient, cfg.Identity.NodeID, logger)

	// 6. Initialize Database Backup Engine (Zero-Disk Cloudflare R2 streaming)
	dumper := backup.NewPostgresDumper(
		cfg.Database.Mode,
		cfg.Database.ServiceName,
		cfg.Database.Host,
		cfg.Database.Port,
		cmp.Or(cfg.Database.User, os.Getenv("PGUSER")),
		cmp.Or(cfg.Database.Database, os.Getenv("PGDATABASE")),
	)
	r2Client := backup.NewR2Client(
		cfg.Database.Backup.R2Endpoint,
		cfg.Database.Backup.R2AccessKeyID,
		cfg.Database.Backup.R2SecretAccessKey,
	)
	backupMgr := backup.NewManager(dumper, r2Client, natsClient, cfg, logger)

	// Helper to resolve target DB from deploy context hint or host config
	resolveTargetDB := func(hookCtx context.Context) string {
		return cmp.Or(
			deploy.TargetDBFromContext(hookCtx),
			cfg.Database.Database,
			os.Getenv("PGDATABASE"),
			"postgres",
		)
	}

	// Hook pre-deploy database snapshot guardrail into deploy orchestrator
	deployOrchestrator.SetPreDeployHook(func(hookCtx context.Context, service, tag string) error {
		targetDB := resolveTargetDB(hookCtx)
		logger.Info("Executing pre-deploy database snapshot guardrail", "service", service, "database", targetDB, "tag", tag)
		activeBackupOps.Add(1)
		defer activeBackupOps.Add(-1)
		_, hookErr := backupMgr.CreateBackupForDB(hookCtx, tag, targetDB)
		return hookErr
	})

	// Hook automated snapshot rollback in case of migration failure
	deployOrchestrator.SetRollbackHook(func(hookCtx context.Context, service, tag string) error {
		targetDB := resolveTargetDB(hookCtx)
		logger.Warn("Executing automated snapshot rollback following migration failure", "service", service, "database", targetDB, "tag", tag)
		activeBackupOps.Add(1)
		defer activeBackupOps.Add(-1)
		return backupMgr.RestoreLatestMatchingTag(hookCtx, tag, targetDB)
	})

	// Start automated cron scheduler for backups
	backupMgr.StartCron(ctx)

	// 7. Initialize in-memory Feature Flags Store
	flagStore := flags.NewStore(logger)

	// 8. Initialize WireGuard Mesh Engine (Embedded Overlay Network)
	var meshMgr *mesh.Manager
	if cfg.Mesh.Enabled {
		meshPrivKey, meshPubKey, err := mesh.LoadOrGenerateKeypair(cfg.Mesh.KeyPath)
		if err != nil {
			logger.Warn("Failed to load or generate WireGuard keypair", "error", err)
		} else {
			meshCfg := mesh.Config{
				Enabled:        true,
				InterfaceName:  cfg.Mesh.Interface,
				ListenPort:     cfg.Mesh.Port,
				KeyPath:        cfg.Mesh.KeyPath,
				PublicEndpoint: cfg.Mesh.Endpoint,
				Subnet:         "10.42.0.0/16",
			}
			meshMgr = mesh.NewManager(meshCfg, meshPrivKey, meshPubKey, nil, logger)

			// Async registration with Cloudflare Worker Mesh Control Plane
			go func() {
				if cfg.ControlPlane.Endpoint == "" {
					return
				}
				regURL := fmt.Sprintf("%s/api/v1/control/mesh/register", strings.TrimRight(cfg.ControlPlane.Endpoint, "/"))
				payload := map[string]any{
					"node_id":     cfg.Identity.NodeID,
					"name":        cfg.Identity.Hostname,
					"public_key":  meshPubKey,
					"endpoint":    cfg.Mesh.Endpoint,
					"listen_port": cfg.Mesh.Port,
				}
				bodyBytes, _ := json.Marshal(payload)
				req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, regURL, bytes.NewReader(bodyBytes))
				if err != nil {
					return
				}
				req.Header.Set("Content-Type", "application/json")
				if cfg.ControlPlane.EnrollToken != "" {
					req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", cfg.ControlPlane.EnrollToken))
				}
				client := &http.Client{Timeout: 10 * time.Second}
				resp, err := client.Do(req)
				if err != nil {
					logger.Warn("WireGuard mesh control plane registration skipped or failed", "error", err)
					return
				}
				defer resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					var regResp mesh.MeshRegisterResponse
					if err := json.NewDecoder(resp.Body).Decode(&regResp); err == nil {
						logger.Info("Mesh node registered with control plane",
							"overlay_ip", regResp.Peer.OverlayIP,
							"subnet", regResp.Subnet,
							"peers_count", len(regResp.Peers),
						)
						meshCfg.OverlayIP = regResp.Peer.OverlayIP
						meshMgr = mesh.NewManager(meshCfg, meshPrivKey, meshPubKey, nil, logger)
						if err := meshMgr.InitInterface(context.Background()); err != nil {
							logger.Warn("WireGuard interface init warning (requires kernel module & CAP_NET_ADMIN)", "error", err)
						} else {
							_ = meshMgr.SyncPeers(context.Background(), regResp.Peers)
						}
					}
				}
			}()
		}
	}

	agentUpdater := updater.New(updater.Config{
		CurrentVersion: Version,
		ControlURL:     cfg.ControlPlane.Endpoint,
		AuthToken:      cfg.ControlPlane.EnrollToken,
		Logger:         logger,
		IsIdle: func() bool {
			return deployOrchestrator.ActiveOps() == 0 && activeBackupOps.Load() == 0
		},
		OnRestart: func(execPath string) error {
			logger.Warn("OTA binary swap complete; exiting cleanly for service supervisor handover", "executable", execPath)
			go func() {
				time.Sleep(250 * time.Millisecond)
				os.Exit(0)
			}()
			return nil
		},
	})

	if cfg.NATS.Mode == "embedded" || cfg.DevMode {
		embedOpts := transport.EmbeddedOptions{
			DontListen: cfg.DevMode, // In dev mode, run 100% in-process with zero open ports!
			Port:       cfg.NATS.EmbeddedTCPPort,
			WSPort:     cfg.NATS.EmbeddedPort,
			AuthToken:  cfg.NATS.AuthToken,
		}
		if err := natsClient.StartEmbedded(ctx, embedOpts); err != nil {
			logger.Error("Failed to start embedded NATS server", "error", err)
		} else {
			registerCommandListeners(natsClient, deployOrchestrator, backupMgr, flagStore, meshMgr, agentUpdater, cfg, logger)
		}
	} else if cfg.NATS.Mode != "disabled" && cfg.NATS.Mode != "none" && cfg.NATS.Mode != "off" {
		if err := natsClient.Connect(ctx); err != nil {
			logger.Warn("Initial NATS connection failed; will retry in background",
				"url", cfg.NATS.URL,
				"error", err,
			)
		} else {
			registerCommandListeners(natsClient, deployOrchestrator, backupMgr, flagStore, meshMgr, agentUpdater, cfg, logger)
		}
	} else {
		logger.Info("NATS transport disabled; operating in HTTPS / Cloudflare Edge Control Plane mode")
	}
	defer natsClient.Close()

	// 5. Initialize telemetry reporter & enroll node
	reporter := heartbeat.NewReporter(cfg, sampler, inspector, natsClient, Version, logger)
	if err := reporter.Enroll(ctx); err != nil {
		logger.Warn("Node enrollment warning", "error", err)
	}

	// 6. Configure piggybacked command & feature-flag synchronization on the 15s heartbeat loop
	configureControlPlaneSync(ctx, reporter, flagStore, backupMgr, deployOrchestrator, agentUpdater, cfg, logger)

	// 6a. Launch background telemetry + piggybacked control-plane sync loop (every 15s)
	go reporter.StartHeartbeatLoop(ctx)

	// 6b. Reconcile stable Docker DNS aliases for already-running containers on host startup
	go deployOrchestrator.ReconcileActiveAliases(ctx)

	// 6c. Launch local zero-latency Feature Flags edge daemon (HTTP on 0.0.0.0:8999 for containers)
	go startLocalFlagsServer(ctx, flagStore, logger)

	// 7. Handle OS Signals (Graceful shutdown & SIGHUP hot reload on Unix)
	waitForShutdown(cancel, logger, func() {
		if reloaded, err := config.Load(os.Args[1:]); err == nil {
			cfg = reloaded
			logger.Info("Configuration reloaded successfully", "log_level", cfg.Telemetry.LogLevel)
		} else {
			logger.Error("Failed to reload configuration", "error", err)
		}
	})
}

func initLogger(levelStr string) *slog.Logger {
	var level slog.Level
	switch strings.ToLower(levelStr) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
	})
	return slog.New(handler)
}

func registerCommandListeners(
	nc *transport.NATSClient,
	orchestrator *deploy.Orchestrator,
	backupMgr *backup.Manager,
	flagStore *flags.Store,
	meshMgr *mesh.Manager,
	agentUpdater *updater.Updater,
	cfg *config.Config,
	logger *slog.Logger,
) {
	nodeID := cfg.Identity.NodeID

	// 1. Target node reboot command
	rebootSubj := fmt.Sprintf("flarelens.node.%s.reboot", nodeID)
	_, _ = nc.Subscribe(rebootSubj, func(msg *nats.Msg) {
		logger.Warn("Received remote reboot command via NATS", "subject", msg.Subject)
		go func() {
			logger.Warn("Initiating coordinated host reboot sequence (15s connection drain window)...")
			time.Sleep(15 * time.Second)
			logger.Warn("Executing system reboot now")
			executeSystemReboot(logger)
		}()
	})

	// 2. Target node dynamic config update (OTA Hot Reload)
	configSubj := fmt.Sprintf("flarelens.node.%s.config.update", nodeID)
	_, _ = nc.Subscribe(configSubj, func(msg *nats.Msg) {
		logger.Info("Received OTA dynamic configuration update via NATS", "subject", msg.Subject)
	})

	// 3. Fleet-wide feature flag updates (Sub-50ms instant broadcast)
	flagSubj := "flarelens.fleet.all.flags"
	_, _ = nc.Subscribe(flagSubj, func(msg *nats.Msg) {
		logger.Debug("Received fleet feature flag broadcast", "subject", msg.Subject)
		_ = flagStore.UpdateFromJSON(msg.Data)
	})

	// 4. GitOps & Zero-Downtime Blue/Green Deploy Trigger (Single Node & Fleet Multi-Node Rollout)
	handleDeploy := func(msg *nats.Msg) {
		var req deploy.DeployRequest
		if err := json.Unmarshal(msg.Data, &req); err != nil {
			logger.Error("Malformed deploy request payload", "error", err)
			return
		}

		// Filter if targeted
		if req.NodeID != "" && req.NodeID != "all" && req.NodeID != "all-prod" && req.NodeID != nodeID {
			return
		}

		logger.Info("Received deploy command via NATS",
			"service", req.Service,
			"image", req.Image,
			"deployment_id", req.DeploymentID,
			"subject", msg.Subject,
		)

		// Execute Blue/Green rollout asynchronously
		go func(r deploy.DeployRequest, replySubject string) {
			resp := orchestrator.Deploy(context.Background(), r)

			statusSubj := fmt.Sprintf("flarelens.node.%s.deploy.status", nodeID)
			_ = nc.PublishJSON(statusSubj, resp)

			if replySubject != "" {
				_ = nc.PublishJSON(replySubject, resp)
			}

			// Report deployment outcome to Cloudflare Worker Control Plane
			if cfg.ControlPlane.Endpoint != "" {
				reportHTTPStatus(
					fmt.Sprintf("%s/api/v1/control/deploy/status", cfg.ControlPlane.Endpoint),
					cfg.ControlPlane.EnrollToken,
					map[string]any{
						"deployment_id": resp.DeploymentID,
						"service":       resp.Service,
						"status":        resp.Status,
						"active_slot":   resp.ActiveSlot,
						"active_port":   resp.ActivePort,
						"message":       resp.Message,
						"duration_ms":   resp.DurationMS,
					},
					logger,
				)
			}
		}(req, msg.Reply)
	}

	deploySubj := fmt.Sprintf("flarelens.node.%s.deploy", nodeID)
	_, _ = nc.Subscribe(deploySubj, handleDeploy)
	_, _ = nc.Subscribe("flarelens.fleet.all.deploy", handleDeploy)
	_, _ = nc.Subscribe("flarelens.fleet.prod.deploy", handleDeploy)

	// 5. On-Demand Database Backup Trigger
	backupSubj := fmt.Sprintf("flarelens.node.%s.backup", nodeID)
	_, _ = nc.Subscribe(backupSubj, func(msg *nats.Msg) {
		var req backup.BackupTriggerRequest
		_ = json.Unmarshal(msg.Data, &req)

		logger.Info("Received on-demand database backup request via NATS", "tag", req.Tag)

		go func(tag string, replySubject string) {
			meta, err := backupMgr.CreateBackup(context.Background(), tag)
			statusSubj := fmt.Sprintf("flarelens.node.%s.backup.status", nodeID)
			if err != nil {
				_ = nc.PublishJSON(statusSubj, map[string]any{"status": "failed", "error": err.Error(), "tag": tag})
				if replySubject != "" {
					_ = nc.PublishJSON(replySubject, map[string]any{"status": "failed", "error": err.Error()})
				}
				return
			}
			_ = nc.PublishJSON(statusSubj, map[string]any{"status": "success", "metadata": meta})
			if replySubject != "" {
				_ = nc.PublishJSON(replySubject, map[string]any{"status": "success", "metadata": meta})
			}
		}(req.Tag, msg.Reply)
	})

	// 6. Database Restore Trigger
	restoreSubj := fmt.Sprintf("flarelens.node.%s.backup.restore", nodeID)
	_, _ = nc.Subscribe(restoreSubj, func(msg *nats.Msg) {
		var req backup.RestoreTriggerRequest
		if err := json.Unmarshal(msg.Data, &req); err != nil {
			logger.Error("Malformed restore request payload", "error", err)
			return
		}

		logger.Info("Received database restore request via NATS", "key", req.Key, "target_db", req.TargetDB)

		go func(r backup.RestoreTriggerRequest, replySubject string) {
			err := backupMgr.RestoreBackup(context.Background(), r.Key, r.TargetDB)
			statusSubj := fmt.Sprintf("flarelens.node.%s.backup.restore.status", nodeID)
			restoreStatus := "completed"
			errMsg := ""
			if err != nil {
				restoreStatus = "failed"
				errMsg = err.Error()
				_ = nc.PublishJSON(statusSubj, map[string]any{"status": "failed", "error": err.Error(), "key": r.Key})
				if replySubject != "" {
					_ = nc.PublishJSON(replySubject, map[string]any{"status": "failed", "error": err.Error()})
				}
			} else {
				_ = nc.PublishJSON(statusSubj, map[string]any{"status": "success", "key": r.Key, "target_db": r.TargetDB})
				if replySubject != "" {
					_ = nc.PublishJSON(replySubject, map[string]any{"status": "success", "key": r.Key})
				}
			}

			// Report restore status to Cloudflare Worker Control Plane
			if cfg.ControlPlane.Endpoint != "" {
				reportHTTPStatus(
					fmt.Sprintf("%s/api/v1/control/backup/status", cfg.ControlPlane.Endpoint),
					cfg.ControlPlane.EnrollToken,
					map[string]any{
						"node_id": nodeID,
						"key":     r.Key,
						"status":  restoreStatus,
						"error":   errMsg,
					},
					logger,
				)
			}
		}(req, msg.Reply)
	})

	// 7. Backup Listing Query
	listSubj := fmt.Sprintf("flarelens.node.%s.backup.list", nodeID)
	_, _ = nc.Subscribe(listSubj, func(msg *nats.Msg) {
		if msg.Reply == "" {
			return
		}
		go func(replySubject string) {
			objs, err := backupMgr.ListBackups(context.Background())
			if err != nil {
				_ = nc.PublishJSON(replySubject, map[string]any{"error": err.Error()})
				return
			}
			_ = nc.PublishJSON(replySubject, map[string]any{"backups": objs, "count": len(objs)})
		}(msg.Reply)
	})

	// 8. Ephemeral PR Preview Teardown Trigger
	handleTeardown := func(msg *nats.Msg) {
		var req deploy.TeardownRequest
		if err := json.Unmarshal(msg.Data, &req); err != nil {
			logger.Error("Malformed teardown request payload", "error", err)
			return
		}

		if req.NodeID != "" && req.NodeID != "all" && req.NodeID != nodeID {
			return
		}

		logger.Info("Received PR preview teardown command via NATS",
			"service", req.Service,
			"pr_number", req.PRNumber,
			"subject", msg.Subject,
		)

		go func(r deploy.TeardownRequest, replySubject string) {
			err := orchestrator.TeardownPreview(context.Background(), r)
			statusSubj := fmt.Sprintf("flarelens.node.%s.preview.teardown.status", nodeID)
			statusPayload := map[string]any{
				"service":   r.Service,
				"pr_number": r.PRNumber,
				"status":    "destroyed",
			}
			if err != nil {
				statusPayload["status"] = "failed"
				statusPayload["error"] = err.Error()
			}
			_ = nc.PublishJSON(statusSubj, statusPayload)
			if replySubject != "" {
				_ = nc.PublishJSON(replySubject, statusPayload)
			}
		}(req, msg.Reply)
	}

	teardownSubj := fmt.Sprintf("flarelens.node.%s.preview.teardown", nodeID)
	_, _ = nc.Subscribe(teardownSubj, handleTeardown)
	_, _ = nc.Subscribe("flarelens.fleet.all.preview.teardown", handleTeardown)

	// 9. Dynamic WireGuard Mesh Peer Sync
	if meshMgr != nil {
		syncHandler := func(msg *nats.Msg) {
			var peers []mesh.Peer
			if err := json.Unmarshal(msg.Data, &peers); err == nil && len(peers) > 0 {
				logger.Info("Received dynamic mesh peer broadcast via NATS", "peers_count", len(peers))
				if err := meshMgr.SyncPeers(context.Background(), peers); err != nil {
					logger.Warn("Failed to sync WireGuard mesh peers", "error", err)
				}
			}
		}
		_, _ = nc.Subscribe("flarelens.fleet.all.mesh.peers", syncHandler)
		nodeMeshSubj := fmt.Sprintf("flarelens.node.%s.mesh.sync", nodeID)
		_, _ = nc.Subscribe(nodeMeshSubj, syncHandler)
	}

	// 10. Singleton / Stateful Manifest Reconciler
	singletonSubj := fmt.Sprintf("flarelens.node.%s.singleton", nodeID)
	_, _ = nc.Subscribe(singletonSubj, func(msg *nats.Msg) {
		var spec deploy.SingletonSpec
		if err := json.Unmarshal(msg.Data, &spec); err != nil {
			logger.Error("Malformed singleton reconcile payload", "error", err)
			return
		}
		if spec.NodeID != "" && spec.NodeID != "all" && spec.NodeID != nodeID {
			return
		}
		go func(s deploy.SingletonSpec, replySubject string) {
			resp := orchestrator.ReconcileSingleton(context.Background(), s)
			if replySubject != "" {
				_ = nc.PublishJSON(replySubject, resp)
			}
			if cfg.ControlPlane.Endpoint != "" {
				reportHTTPStatus(
					fmt.Sprintf("%s/api/v1/control/deploy/status", strings.TrimRight(cfg.ControlPlane.Endpoint, "/")),
					cfg.ControlPlane.EnrollToken,
					map[string]any{
						"deployment_id": resp.DeploymentID,
						"service":       resp.Service,
						"status":        resp.Status,
						"active_slot":   resp.ActiveSlot,
						"message":       resp.Message,
						"duration_ms":   resp.DurationMS,
					},
					logger,
				)
			}
		}(spec, msg.Reply)
	})

	// 11. Over-The-Air (OTA) Agent Self-Update Trigger
	updateSubj := fmt.Sprintf("flarelens.node.%s.update", nodeID)
	if agentUpdater != nil {
		handleUpdate := func(msg *nats.Msg) {
			var uReq updater.UpdateRequest
			if err := json.Unmarshal(msg.Data, &uReq); err != nil {
				logger.Error("Malformed self-update payload", "error", err)
				return
			}
			go executeSelfUpdate(agentUpdater, uReq, "", nodeID, cfg, logger)
		}
		_, _ = nc.Subscribe(updateSubj, handleUpdate)
		_, _ = nc.Subscribe("flarelens.fleet.all.update", handleUpdate)
	}

	logger.Info("NATS command listeners registered",
		"reboot_subject", rebootSubj,
		"config_subject", configSubj,
		"flag_subject", flagSubj,
		"deploy_subject", deploySubj,
		"singleton_subject", singletonSubj,
		"update_subject", updateSubj,
		"backup_subject", backupSubj,
		"restore_subject", restoreSubj,
		"list_subject", listSubj,
		"teardown_subject", teardownSubj,
	)
}

func reportHTTPStatus(url string, token string, payload any, logger *slog.Logger) {
	if url == "" {
		return
	}
	go reportHTTPStatusSync(url, token, payload, logger)
}

func reportHTTPStatusSync(url string, token string, payload any, logger *slog.Logger) {
	if url == "" {
		return
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return
	}
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	}
	resp, err := client.Do(req)
	if err != nil {
		logger.Warn("Failed to report HTTP status to control plane", "url", url, "error", err)
		return
	}
	_ = resp.Body.Close()
}

func fetchLatestReleaseMetadata(ctx context.Context, controlURL, token, wantVersion string) (string, string, string, error) {
	targetArch := fmt.Sprintf("%s-%s", runtime.GOOS, runtime.GOARCH)
	endpoint := fmt.Sprintf("%s/api/v1/control/agent/releases?target=%s",
		strings.TrimRight(controlURL, "/"),
		url.QueryEscape(targetArch),
	)
	if wantVersion != "" {
		endpoint += "&version=" + url.QueryEscape(wantVersion)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", "", "", err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", "", "", fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var payload struct {
		Release *struct {
			Version     string `json:"version"`
			SHA256      string `json:"sha256"`
			DownloadURL string `json:"download_url"`
		} `json:"release"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", "", "", err
	}
	if payload.Release == nil || payload.Release.SHA256 == "" {
		return "", "", "", fmt.Errorf("no published release metadata found for %s", targetArch)
	}
	return payload.Release.Version, payload.Release.SHA256, payload.Release.DownloadURL, nil
}

func executeSelfUpdate(
	agentUpdater *updater.Updater,
	uReq updater.UpdateRequest,
	commandID string,
	nodeID string,
	cfg *config.Config,
	logger *slog.Logger,
) {
	statusURL := ""
	if cfg.ControlPlane.Endpoint != "" {
		statusURL = fmt.Sprintf("%s/api/v1/control/agent/update/status", strings.TrimRight(cfg.ControlPlane.Endpoint, "/"))
	}
	reportHTTPStatusSync(statusURL, cfg.ControlPlane.EnrollToken, map[string]any{
		"command_id":       commandID,
		"node_id":          nodeID,
		"previous_version": Version,
		"target_version":   uReq.Version,
		"status":           "updating",
	}, logger)

	res, err := agentUpdater.Apply(context.Background(), uReq)
	if err != nil {
		logger.Error("OTA self-update failed", "target_version", uReq.Version, "error", err)
		reportHTTPStatusSync(statusURL, cfg.ControlPlane.EnrollToken, map[string]any{
			"command_id":       commandID,
			"node_id":          nodeID,
			"previous_version": Version,
			"target_version":   uReq.Version,
			"status":           "failed",
			"error":            err.Error(),
		}, logger)
		return
	}

	reportHTTPStatusSync(statusURL, cfg.ControlPlane.EnrollToken, map[string]any{
		"command_id":       commandID,
		"node_id":          nodeID,
		"previous_version": res.PreviousVersion,
		"target_version":   res.TargetVersion,
		"sha256":           res.SHA256,
		"status":           res.Status,
	}, logger)
}

type NodeCommand struct {
	ID                    string                  `json:"id"`
	Type                  string                  `json:"type"`
	NodeID                string                  `json:"node_id"`
	Tag                   string                  `json:"tag"`
	Key                   string                  `json:"key"`
	TargetDB              string                  `json:"target_db"`
	DeploymentID          string                  `json:"deployment_id"`
	Service               string                  `json:"service"`
	Image                 string                  `json:"image"`
	Env                   string                  `json:"env"`
	ContainerName         string                  `json:"container_name"`
	Restart               string                  `json:"restart"`
	Ports                 []string                `json:"ports"`
	Healthcheck           *deploy.HealthcheckSpec `json:"healthcheck"`
	ForceRecreateStateful bool                    `json:"force_recreate_stateful"`
	ContainerPort         int                     `json:"container_port"`
	HostPortBlue          int                     `json:"host_port_blue"`
	HostPortGreen         int                     `json:"host_port_green"`
	Domain                string                  `json:"domain"`
	HealthPath            string                  `json:"health_path"`
	Secrets               map[string]string       `json:"secrets"`
	Network               string                  `json:"network"`
	CanaryWeight          int                     `json:"canary_weight"`
	CanaryDuration        int                     `json:"canary_duration"`
	PreDeploySnapshot     bool                    `json:"pre_deploy_snapshot"`
	RunMigrations         bool                    `json:"run_migrations"`
	MigrationCmd          string                  `json:"migration_cmd"`
	Command               []string                `json:"command"`
	Entrypoint            []string                `json:"entrypoint"`
	Networks              []string                `json:"networks"`
	Aliases               []string                `json:"aliases"`
	Volumes               []string                `json:"volumes"`
	Workers               []deploy.WorkerSpec     `json:"workers"`
	IsPreview             bool                    `json:"is_preview"`
	PRNumber              int                     `json:"pr_number"`
	Version               string                  `json:"version"`
	SHA256                string                  `json:"sha256"`
	DownloadURL           string                  `json:"download_url"`
	Force                 bool                    `json:"force"`
}

type CommandsResponse struct {
	Commands []NodeCommand `json:"commands"`
}

func configureControlPlaneSync(
	ctx context.Context,
	reporter *heartbeat.Reporter,
	flagStore *flags.Store,
	backupMgr *backup.Manager,
	orchestrator *deploy.Orchestrator,
	agentUpdater *updater.Updater,
	cfg *config.Config,
	logger *slog.Logger,
) {
	if cfg.ControlPlane.Endpoint == "" {
		return
	}

	client := &http.Client{Timeout: 15 * time.Second}
	nodeID := cfg.Identity.NodeID

	var syncMu sync.Mutex
	initialFlagsSynced := syncFlagsOnce(ctx, client, flagStore, cfg, logger)
	lastFlagsVersion := ""
	var lastLegacyPoll time.Time

	logger.Info("Configured consolidated 15s heartbeat control-plane sync",
		"endpoint", cfg.ControlPlane.Endpoint,
		"node_id", nodeID,
		"initial_flags_synced", initialFlagsSynced,
	)

	reporter.SetSyncHandler(func(hbCtx context.Context, rawCommands []json.RawMessage, flagsVersion string, piggybacked bool) {
		if len(rawCommands) > 0 {
			cmds := make([]NodeCommand, 0, len(rawCommands))
			for _, raw := range rawCommands {
				var c NodeCommand
				if err := json.Unmarshal(raw, &c); err == nil && c.ID != "" {
					cmds = append(cmds, c)
				}
			}
			if len(cmds) > 0 {
				dispatchNodeCommands(cmds, client, backupMgr, orchestrator, agentUpdater, cfg, nodeID, logger)
			}
		}

		syncMu.Lock()
		defer syncMu.Unlock()

		if piggybacked {
			if flagsVersion == "" {
				return
			}
			if !initialFlagsSynced {
				if syncFlagsOnce(hbCtx, client, flagStore, cfg, logger) {
					initialFlagsSynced = true
					lastFlagsVersion = flagsVersion
				}
				return
			}
			if lastFlagsVersion == "" {
				lastFlagsVersion = flagsVersion
				return
			}
			if flagsVersion != lastFlagsVersion {
				logger.Info("Feature flags version changed on control plane; syncing flags",
					"prev_version", lastFlagsVersion,
					"new_version", flagsVersion,
				)
				if syncFlagsOnce(hbCtx, client, flagStore, cfg, logger) {
					lastFlagsVersion = flagsVersion
				}
			}
			return
		}

		// Legacy fallback: only used when connected to an older control plane that omits flags_version
		if time.Since(lastLegacyPoll) >= 30*time.Second {
			lastLegacyPoll = time.Now()
			pollAndExecuteCommands(hbCtx, client, backupMgr, orchestrator, agentUpdater, cfg, nodeID, logger)
			if syncFlagsOnce(hbCtx, client, flagStore, cfg, logger) {
				initialFlagsSynced = true
			}
		}
	})
}

var inFlightCommands sync.Map

func pollAndExecuteCommands(ctx context.Context, client *http.Client, backupMgr *backup.Manager, orchestrator *deploy.Orchestrator, agentUpdater *updater.Updater, cfg *config.Config, nodeID string, logger *slog.Logger) {
	reqURL := fmt.Sprintf("%s/api/v1/control/commands?node_id=%s", strings.TrimRight(cfg.ControlPlane.Endpoint, "/"), url.QueryEscape(nodeID))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return
	}
	if cfg.ControlPlane.EnrollToken != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", cfg.ControlPlane.EnrollToken))
	}

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return
	}

	var cmdResp CommandsResponse
	if err := json.NewDecoder(resp.Body).Decode(&cmdResp); err != nil {
		return
	}

	dispatchNodeCommands(cmdResp.Commands, client, backupMgr, orchestrator, agentUpdater, cfg, nodeID, logger)
}

func dispatchNodeCommands(cmds []NodeCommand, client *http.Client, backupMgr *backup.Manager, orchestrator *deploy.Orchestrator, agentUpdater *updater.Updater, cfg *config.Config, nodeID string, logger *slog.Logger) {
	for _, cmd := range cmds {
		if _, loaded := inFlightCommands.LoadOrStore(cmd.ID, true); loaded {
			continue // Already in-flight
		}

		// Acknowledge immediately so worker removes it from R2 / memory queue
		ackCommand(cfg, client, cmd.ID, nodeID, logger)

		logger.Info("Received queued command from FlareLens Control Plane", "id", cmd.ID, "type", cmd.Type, "tag", cmd.Tag)
		switch cmd.Type {
		case "deploy":
			go func(c NodeCommand) {
				defer inFlightCommands.Delete(c.ID)
				startTime := time.Now()
				logger.Info("Executing queued deploy command...", "service", c.Service, "image", c.Image, "id", c.ID)

				deployScript := fmt.Sprintf("/usr/local/bin/deploy-%s.sh", c.Service)
				envName := c.Env
				if envName == "" {
					envName = "uat"
				}

				versionTag := c.Image
				if idx := strings.LastIndex(versionTag, ":"); idx != -1 {
					versionTag = versionTag[idx+1:]
				}

				var deployStatus = "success"
				var deployMsg = fmt.Sprintf("Deployed %s image %s", c.Service, c.Image)

				// Prefer native Kamal-style container orchestrator (multi-network, companion workers, migrations, Traefik zero-downtime)
				if orchestrator != nil && os.Getenv("FLARELENS_USE_HOST_SCRIPTS") != "true" {
					logger.Info("Executing native container orchestration (zero-downtime)", "service", c.Service, "image", c.Image)
					dReq := deploy.DeployRequest{
						DeploymentID:      cmp.Or(c.DeploymentID, c.ID),
						Service:           c.Service,
						Image:             c.Image,
						Env:               c.Env,
						Domain:            c.Domain,
						ContainerPort:     c.ContainerPort,
						HostPortBlue:      c.HostPortBlue,
						HostPortGreen:     c.HostPortGreen,
						HealthPath:        c.HealthPath,
						Command:           c.Command,
						Entrypoint:        c.Entrypoint,
						Networks:          c.Networks,
						Aliases:           c.Aliases,
						Volumes:           c.Volumes,
						Workers:           c.Workers,
						Secrets:           c.Secrets,
						Network:           c.Network,
						TargetDB:          c.TargetDB,
						CanaryWeight:      c.CanaryWeight,
						CanaryDuration:    c.CanaryDuration,
						PreDeploySnapshot: c.PreDeploySnapshot,
						RunMigrations:     c.RunMigrations,
						MigrationCmd:      c.MigrationCmd,
						IsPreview:         c.IsPreview,
						PRNumber:          c.PRNumber,
					}
					resp := orchestrator.Deploy(context.Background(), dReq)
					deployStatus = resp.Status
					deployMsg = resp.Message
				} else if _, err := os.Stat(deployScript); err == nil {
					logger.Info("Executing host deploy script", "script", deployScript, "env", envName, "version", versionTag)
					cmdExec := exec.CommandContext(context.Background(), deployScript, envName, versionTag)
					out, err := cmdExec.CombinedOutput()
					if err != nil {
						logger.Error("Host deploy script failed", "error", err, "output", string(out))
						deployStatus = "failed"
						deployMsg = fmt.Sprintf("Deploy script error: %v (output: %s)", err, string(out))
					} else {
						logger.Info("Host deploy script completed successfully", "output", string(out))
						deployMsg = fmt.Sprintf("Successfully deployed %s (%s) via %s", c.Service, versionTag, deployScript)
					}
				} else {
					deployStatus = "failed"
					deployMsg = fmt.Sprintf("Neither native container orchestrator nor host deploy script %s available", deployScript)
				}

				// Report deployment outcome to Cloudflare Worker Control Plane
				if cfg.ControlPlane.Endpoint != "" {
					reportHTTPStatus(
						fmt.Sprintf("%s/api/v1/control/deploy/status", strings.TrimRight(cfg.ControlPlane.Endpoint, "/")),
						cfg.ControlPlane.EnrollToken,
						map[string]any{
							"deployment_id": cmp.Or(c.DeploymentID, c.ID),
							"service":       c.Service,
							"status":        deployStatus,
							"message":       deployMsg,
							"duration_ms":   time.Since(startTime).Milliseconds(),
						},
						logger,
					)
				}
				ackCommand(cfg, client, c.ID, nodeID, logger)
			}(cmd)

		case "reconcile_singleton":
			go func(c NodeCommand) {
				defer inFlightCommands.Delete(c.ID)
				if orchestrator == nil {
					return
				}
				logger.Info("Executing singleton manifest reconciliation...", "service", c.Service, "container", c.ContainerName, "id", c.ID)
				resp := orchestrator.ReconcileSingleton(context.Background(), deploy.SingletonSpec{
					DeploymentID:          cmp.Or(c.DeploymentID, c.ID),
					NodeID:                c.NodeID,
					Service:               c.Service,
					Env:                   c.Env,
					Image:                 c.Image,
					ContainerName:         c.ContainerName,
					Restart:               c.Restart,
					Networks:              c.Networks,
					Aliases:               c.Aliases,
					Volumes:               c.Volumes,
					Ports:                 c.Ports,
					Command:               c.Command,
					Entrypoint:            c.Entrypoint,
					Healthcheck:           c.Healthcheck,
					Secrets:               c.Secrets,
					ForceRecreateStateful: c.ForceRecreateStateful,
				})
				if cfg.ControlPlane.Endpoint != "" {
					reportHTTPStatus(
						fmt.Sprintf("%s/api/v1/control/deploy/status", strings.TrimRight(cfg.ControlPlane.Endpoint, "/")),
						cfg.ControlPlane.EnrollToken,
						map[string]any{
							"deployment_id": resp.DeploymentID,
							"service":       resp.Service,
							"status":        resp.Status,
							"active_slot":   resp.ActiveSlot,
							"message":       resp.Message,
							"duration_ms":   resp.DurationMS,
						},
						logger,
					)
				}
				ackCommand(cfg, client, c.ID, nodeID, logger)
			}(cmd)

		case "self_update":
			go func(c NodeCommand) {
				defer inFlightCommands.Delete(c.ID)
				if agentUpdater == nil {
					return
				}
				logger.Info("Executing queued OTA self-update command...", "target_version", c.Version, "id", c.ID)
				executeSelfUpdate(agentUpdater, updater.UpdateRequest{
					Version:     c.Version,
					SHA256:      c.SHA256,
					DownloadURL: c.DownloadURL,
					Force:       c.Force,
				}, c.ID, nodeID, cfg, logger)
			}(cmd)

		case "preview_teardown":
			go func(c NodeCommand) {
				defer inFlightCommands.Delete(c.ID)
				logger.Info("Executing queued preview teardown...", "service", c.Service, "pr_number", c.PRNumber, "command_id", c.ID)
				if orchestrator != nil {
					tdReq := deploy.TeardownRequest{
						Service:  c.Service,
						PRNumber: c.PRNumber,
					}
					_ = orchestrator.TeardownPreview(context.Background(), tdReq)
				}
				ackCommand(cfg, client, c.ID, nodeID, logger)
			}(cmd)
		case "backup":
			go func(c NodeCommand) {
				defer inFlightCommands.Delete(c.ID)
				activeBackupOps.Add(1)
				defer activeBackupOps.Add(-1)
				tag := c.Tag
				if tag == "" {
					tag = "manual_ui"
				}
				logger.Info("Executing queued database backup...", "tag", tag, "key", c.Key, "command_id", c.ID)
				meta, err := backupMgr.CreateBackup(context.Background(), tag, c.Key)
				statusPayload := map[string]any{
					"key":     c.Key,
					"node_id": nodeID,
					"tag":     tag,
				}
				if err != nil {
					logger.Error("Command backup execution failed", "id", c.ID, "error", err)
					statusPayload["status"] = "failed"
					statusPayload["error"] = err.Error()
				} else {
					logger.Info("Command backup execution succeeded", "id", c.ID, "key", meta.Key)
					statusPayload["key"] = meta.Key
					statusPayload["status"] = "completed"
				}

				// Report status back to control plane
				reportHTTPStatus(
					fmt.Sprintf("%s/api/v1/control/backup/status", strings.TrimRight(cfg.ControlPlane.Endpoint, "/")),
					cfg.ControlPlane.EnrollToken,
					statusPayload,
					logger,
				)

				// Acknowledge command so it gets removed from the queue
				ackCommand(cfg, client, c.ID, nodeID, logger)
			}(cmd)

		case "restore":
			go func(c NodeCommand) {
				defer inFlightCommands.Delete(c.ID)
				activeBackupOps.Add(1)
				defer activeBackupOps.Add(-1)
				logger.Info("Executing queued database restore...", "key", c.Key, "target_db", c.TargetDB, "command_id", c.ID)
				err := backupMgr.RestoreBackup(context.Background(), c.Key, c.TargetDB)
				statusPayload := map[string]any{
					"key":       c.Key,
					"node_id":   nodeID,
					"target_db": c.TargetDB,
					"status":    "completed",
				}
				if err != nil {
					logger.Error("Command restore execution failed", "id", c.ID, "error", err)
					statusPayload["status"] = "failed"
					statusPayload["error"] = err.Error()
				} else {
					logger.Info("Command restore execution succeeded", "id", c.ID, "key", c.Key)
				}
				reportHTTPStatus(
					fmt.Sprintf("%s/api/v1/control/backup/status", strings.TrimRight(cfg.ControlPlane.Endpoint, "/")),
					cfg.ControlPlane.EnrollToken,
					statusPayload,
					logger,
				)
				ackCommand(cfg, client, c.ID, nodeID, logger)
			}(cmd)
		default:
			inFlightCommands.Delete(cmd.ID)
		}
	}
}

func ackCommand(cfg *config.Config, client *http.Client, cmdID string, nodeID string, logger *slog.Logger) {
	ackURL := fmt.Sprintf("%s/api/v1/control/commands/ack?id=%s&node_id=%s",
		strings.TrimRight(cfg.ControlPlane.Endpoint, "/"),
		url.QueryEscape(cmdID),
		url.QueryEscape(nodeID),
	)
	req, err := http.NewRequest("POST", ackURL, nil)
	if err != nil {
		return
	}
	if cfg.ControlPlane.EnrollToken != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", cfg.ControlPlane.EnrollToken))
	}
	if resp, err := client.Do(req); err == nil {
		_ = resp.Body.Close()
	}
}

func syncFlagsOnce(ctx context.Context, client *http.Client, store *flags.Store, cfg *config.Config, logger *slog.Logger) bool {
	if cfg.ControlPlane.Endpoint == "" {
		return false
	}
	flagsURL := fmt.Sprintf("%s/api/v1/control/flags", strings.TrimRight(cfg.ControlPlane.Endpoint, "/"))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, flagsURL, nil)
	if err != nil {
		return false
	}
	if cfg.ControlPlane.EnrollToken != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", cfg.ControlPlane.EnrollToken))
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false
	}
	if err := store.UpdateFromJSON(body); err != nil {
		return false
	}
	if syncErr := store.SyncToFile("/etc/flarelens/flags"); syncErr != nil {
		logger.Debug("Sync flags to /etc/flarelens/flags notice", "error", syncErr)
	}
	return true
}

func startLocalFlagsServer(ctx context.Context, store *flags.Store, logger *slog.Logger) {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	mux.HandleFunc("/api/v1/flags", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		data, _ := store.DumpJSON()
		_, _ = w.Write(data)
	})
	mux.HandleFunc("/flags", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		data, _ := store.DumpJSON()
		_, _ = w.Write(data)
	})
	mux.HandleFunc("/api/v1/flags/", func(w http.ResponseWriter, r *http.Request) {
		key := strings.TrimPrefix(r.URL.Path, "/api/v1/flags/")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		if strings.HasSuffix(key, "/enabled") {
			flagKey := strings.TrimSuffix(key, "/enabled")
			if store.IsEnabled(flagKey) {
				_, _ = w.Write([]byte("true\n"))
			} else {
				_, _ = w.Write([]byte("false\n"))
			}
			return
		}
		flag, exists := store.Get(key)
		if !exists {
			http.Error(w, `{"error":"Flag not found"}`, http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		data, _ := json.Marshal(flag)
		_, _ = w.Write(data)
	})
	mux.HandleFunc("/flags/", func(w http.ResponseWriter, r *http.Request) {
		key := strings.TrimPrefix(r.URL.Path, "/flags/")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		if strings.HasSuffix(key, "/enabled") {
			flagKey := strings.TrimSuffix(key, "/enabled")
			if store.IsEnabled(flagKey) {
				_, _ = w.Write([]byte("true\n"))
			} else {
				_, _ = w.Write([]byte("false\n"))
			}
			return
		}
		flag, exists := store.Get(key)
		if !exists {
			http.Error(w, `{"error":"Flag not found"}`, http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		data, _ := json.Marshal(flag)
		_, _ = w.Write(data)
	})

	srv := &http.Server{
		Addr:    "0.0.0.0:8999",
		Handler: mux,
	}
	go func() {
		logger.Info("Local Feature Flags edge daemon listening", "addr", "0.0.0.0:8999")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Warn("Local feature flags daemon server stopped", "error", err)
		}
	}()
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
}
