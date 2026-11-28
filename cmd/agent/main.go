package main

import (
	"bufio"
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
	"path/filepath"
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
	Version = "0.2.13"
	Commit  = "none"
	Date    = "unknown"
	BuiltBy = "unknown"
)

func printCLIUsage() {
	fmt.Printf("FlareLens Host Agent & WireGuard Mesh CLI (v%s)\n\n", Version)
	fmt.Println("Usage:")
	fmt.Println("  flarelensd [flags]                  Run host daemon (reconciler, mesh & 15s heartbeat)")
	fmt.Println("  flarelensd login [flags]            Authenticate workstation via browser SSO & join mesh")
	fmt.Println("  flarelensd connect [flags]          Join WireGuard mesh using enrollment token")
	fmt.Println("  flarelensd down [flags]             Disconnect WireGuard interface & revert MagicDNS")
	fmt.Println("  flarelensd logout [flags]           Revoke mesh session, tear down interface & clear state")
	fmt.Println("  flarelensd status                   Show WireGuard mesh peers, handshakes & transfer stats")
	fmt.Println("  flarelensd ssh [user@]host.mesh     Open zero-trust SSH session over private mesh")
	fmt.Println("  flarelensd logs <service> [flags]   Stream live container stdout/stderr without SSH")
	fmt.Println("  flarelensd http <port> [flags]      Expose localhost port on a public HTTPS URL (ngrok-style Funnel)")
	fmt.Println("  flarelensd proxy [flags]            Start unprivileged local SOCKS5 / HTTP CONNECT proxy")
	fmt.Println("  flarelensd backup [flags]           Stream on-demand PostgreSQL backup directly to R2")
	fmt.Println("  flarelensd self-update [flags]      Atomically upgrade flarelensd with SHA-256 verification")
	fmt.Println("  flarelensd leave [flags]            Unenroll host & stop service (keeps binary & Docker apps)")
	fmt.Println("  flarelensd uninstall [flags]        Unenroll host, remove service & binary (keeps Docker apps)")
	fmt.Println("  flarelensd --version                Print version information")
	fmt.Println()
}

func isInteractiveTerminal() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "--version" || os.Args[1] == "-version" || os.Args[1] == "-v") {
		fmt.Printf("FlareLens Host Agent v%s (commit: %s, built at: %s, built by: %s)\n", Version, Commit, Date, BuiltBy)
		os.Exit(0)
	}

	if len(os.Args) > 1 && (os.Args[1] == "help" || os.Args[1] == "--help" || os.Args[1] == "-h") {
		printCLIUsage()
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

	// Subcommand: logs (Stream live container stdout/stderr locally or remotely via Control Plane without SSH)
	if len(os.Args) > 1 && (os.Args[1] == "logs" || os.Args[1] == "log") {
		logFlags := flag.NewFlagSet("logs", flag.ExitOnError)
		follow := logFlags.Bool("f", false, "Follow live log output (docker logs -f)")
		followLong := logFlags.Bool("follow", false, "Follow live log output (docker logs -f)")
		tail := logFlags.Int("n", 200, "Number of recent lines to show from the end of the logs")
		tailLong := logFlags.Int("tail", 200, "Number of recent lines to show from the end of the logs")
		envName := logFlags.String("env", "", "Environment filter (e.g. uat, prod, infra)")
		nodeIDFlag := logFlags.String("node", "", "Target server node_id")
		timestamps := logFlags.Bool("timestamps", false, "Show Docker log timestamps")
		timestampsShort := logFlags.Bool("t", false, "Show Docker log timestamps")
		localOnly := logFlags.Bool("local", false, "Read directly from local Docker socket (/var/run/docker.sock)")
		dockerSock := logFlags.String("docker-socket", "/var/run/docker.sock", "Local Docker socket path")
		controlURL := logFlags.String("control", os.Getenv("FLARELENS_ENDPOINT"), "Control Plane URL")
		token := logFlags.String("token", os.Getenv("FLARELENS_ENROLL_TOKEN"), "Control Plane Bearer token")

		boolFlags := map[string]bool{
			"f": true, "follow": true, "t": true, "timestamps": true, "local": true, "h": true, "help": true,
		}
		rawArgs := os.Args[2:]
		var flagArgs, posArgs []string
		for i := 0; i < len(rawArgs); i++ {
			arg := rawArgs[i]
			if strings.HasPrefix(arg, "-") {
				flagArgs = append(flagArgs, arg)
				cleanFlag := strings.TrimLeft(arg, "-")
				if !strings.Contains(arg, "=") && !boolFlags[cleanFlag] && i+1 < len(rawArgs) {
					flagArgs = append(flagArgs, rawArgs[i+1])
					i++
				}
			} else {
				posArgs = append(posArgs, arg)
			}
		}
		_ = logFlags.Parse(append(flagArgs, posArgs...))

		if logFlags.NArg() < 1 {
			fmt.Fprintln(os.Stderr, "Usage: flarelensd logs <service|container> [-f|--follow] [-n|--tail 200] [--env uat] [--node id] [--timestamps]")
			os.Exit(1)
		}
		target := logFlags.Arg(0)
		wantFollow := *follow || *followLong
		wantTS := *timestamps || *timestampsShort
		tailLines := *tail
		if *tailLong != 200 {
			tailLines = *tailLong
		}

		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()

		// Hydrate control/token from /etc/flarelens/agent.toml if present on a server host
		if *controlURL == "" || *token == "" {
			if loadedCfg, err := config.Load(nil); err == nil {
				*controlURL = cmp.Or(*controlURL, loadedCfg.ControlPlane.Endpoint)
				*token = cmp.Or(*token, loadedCfg.ControlPlane.EnrollToken)
			}
		}

		// Try local Docker Engine directly when --local is set OR when --node is omitted and local socket has the container
		if *localOnly || *nodeIDFlag == "" {
			if _, statErr := os.Stat(*dockerSock); statErr == nil {
				runner := deploy.NewDockerRunner(*dockerSock)
				orch := deploy.NewOrchestrator(runner, nil, nil, nil, "local", nil)
				cid, _, resErr := orch.ResolveServiceContainer(ctx, *envName, target)
				if resErr == nil && cid != "" {
					if err := runner.StreamContainerLogs(ctx, cid, tailLines, wantFollow, wantTS, func(chunk string) error {
						_, wErr := io.WriteString(os.Stdout, chunk)
						return wErr
					}); err != nil {
						fmt.Fprintf(os.Stderr, "❌ Local log stream error: %v\n", err)
						os.Exit(1)
					}
					os.Exit(0)
				}
				if *localOnly {
					fmt.Fprintf(os.Stderr, "❌ %v\n", resErr)
					os.Exit(1)
				}
			} else if *localOnly {
				fmt.Fprintf(os.Stderr, "❌ Docker socket %s not reachable: %v\n", *dockerSock, statErr)
				os.Exit(1)
			}
		}

		if err := mesh.RunRemoteLogsCLI(ctx, mesh.RemoteLogsOptions{
			Target:     target,
			Env:        *envName,
			NodeID:     *nodeIDFlag,
			TailLines:  tailLines,
			Follow:     wantFollow,
			Timestamps: wantTS,
			ControlURL: *controlURL,
			AuthToken:  *token,
		}); err != nil {
			fmt.Fprintf(os.Stderr, "❌ Logs error: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	// Subcommand: http / tunnel / funnel (Expose localhost port on a public HTTPS URL via WireGuard + Traefik)
	if len(os.Args) > 1 && (os.Args[1] == "http" || os.Args[1] == "tunnel" || os.Args[1] == "funnel") {
		httpFlags := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
		subdomain := httpFlags.String("subdomain", "", "Requested public subdomain slug (e.g. billing-webhook)")
		domain := httpFlags.String("domain", "", "Explicit full public domain (e.g. webhook-dev.example.com)")
		basicAuth := httpFlags.String("auth", "", "Optional HTTP Basic Auth guard in username:password format")
		hostHeader := httpFlags.String("host-header", "rewrite", "Host header mode: 'rewrite' (localhost:<port>), 'preserve', or custom host")
		gatewayNode := httpFlags.String("node", "", "Optional gateway node_id override")
		controlURL := httpFlags.String("control", os.Getenv("FLARELENS_ENDPOINT"), "Optional Control Plane URL override")
		token := httpFlags.String("token", os.Getenv("FLARELENS_ENROLL_TOKEN"), "Optional Control Plane Bearer token")
		overlayIP := httpFlags.String("overlay-ip", "", "Optional local WireGuard overlay IP override")
		meshPort := httpFlags.Int("mesh-port", 0, "Optional explicit WireGuard listener port (default: ephemeral)")
		quiet := httpFlags.Bool("quiet", false, "Suppress per-request access log lines")

		// Reorder positional port argument (e.g. `flarelensd http 3000 --subdomain dev`) so flag.Parse sees all flags
		rawArgs := os.Args[2:]
		var flagArgs, posArgs []string
		for i := 0; i < len(rawArgs); i++ {
			arg := rawArgs[i]
			if strings.HasPrefix(arg, "-") {
				flagArgs = append(flagArgs, arg)
				cleanFlag := strings.TrimLeft(arg, "-")
				if !strings.Contains(arg, "=") && cleanFlag != "quiet" && cleanFlag != "h" && cleanFlag != "help" && i+1 < len(rawArgs) {
					flagArgs = append(flagArgs, rawArgs[i+1])
					i++
				}
			} else {
				posArgs = append(posArgs, arg)
			}
		}
		_ = httpFlags.Parse(append(flagArgs, posArgs...))

		if httpFlags.NArg() < 1 {
			fmt.Fprintln(os.Stderr, "Usage: flarelensd http <port|host:port> [--subdomain name] [--domain fqdn] [--auth user:pass]")
			os.Exit(1)
		}
		localHost, localPort, err := mesh.ParseFunnelTarget(httpFlags.Arg(0))
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ %v\n", err)
			os.Exit(1)
		}

		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()

		if err := mesh.RunFunnel(ctx, mesh.FunnelOptions{
			LocalHost:   localHost,
			LocalPort:   localPort,
			ListenIP:    *overlayIP,
			ListenPort:  *meshPort,
			Subdomain:   *subdomain,
			Domain:      *domain,
			BasicAuth:   *basicAuth,
			HostHeader:  *hostHeader,
			GatewayNode: *gatewayNode,
			ControlURL:  *controlURL,
			AuthToken:   *token,
			Quiet:       *quiet,
		}); err != nil {
			fmt.Fprintf(os.Stderr, "❌ Funnel error: %v\n", err)
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

	// Subcommand: down / disconnect / logout (Disconnects WireGuard mesh interface and optionally revokes session)
	if len(os.Args) > 1 && (os.Args[1] == "down" || os.Args[1] == "disconnect" || os.Args[1] == "logout" ||
		(os.Args[1] == "mesh" && len(os.Args) > 2 && (os.Args[2] == "down" || os.Args[2] == "disconnect" || os.Args[2] == "logout"))) {
		subCmd := os.Args[1]
		subArgs := os.Args[2:]
		if os.Args[1] == "mesh" {
			subCmd = os.Args[2]
			subArgs = os.Args[3:]
		}
		isLogout := subCmd == "logout"

		downFlags := flag.NewFlagSet(subCmd, flag.ExitOnError)
		ifaceName := downFlags.String("interface", "", "WireGuard interface name (default: flarelens0)")
		controlURL := downFlags.String("control", os.Getenv("FLARELENS_CONTROL_URL"), "FlareLens Control Plane URL")
		token := downFlags.String("token", os.Getenv("FLARELENS_ENROLL_TOKEN"), "Optional control plane auth token")
		keyPath := downFlags.String("key", "", "Optional path to WireGuard private key file")
		revoke := downFlags.Bool("revoke", isLogout, "Deregister this peer on the FlareLens Control Plane")
		purgeState := downFlags.Bool("purge", isLogout, "Remove cached mesh-state.json and WireGuard .conf")
		purgeKeys := downFlags.Bool("purge-keys", false, "Also delete local WireGuard and SSH keypairs")
		_ = downFlags.Parse(subArgs)

		if *controlURL == "" || *token == "" {
			if loadedCfg, err := config.Load(nil); err == nil {
				*controlURL = cmp.Or(*controlURL, loadedCfg.ControlPlane.Endpoint)
				*token = cmp.Or(*token, loadedCfg.ControlPlane.EnrollToken)
				if *ifaceName == "" {
					*ifaceName = loadedCfg.Mesh.Interface
				}
				if *keyPath == "" {
					*keyPath = loadedCfg.Mesh.KeyPath
				}
			}
		}

		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()

		logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
		res, err := mesh.RunDisconnect(ctx, mesh.DisconnectOptions{
			InterfaceName: *ifaceName,
			ControlURL:    *controlURL,
			AuthToken:     *token,
			KeyPath:       *keyPath,
			RevokeRemote:  *revoke,
			PurgeState:    *purgeState,
			PurgeKeys:     *purgeKeys,
		}, logger)
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Mesh disconnect error: %v\n", err)
			if os.Geteuid() != 0 && runtime.GOOS != "windows" {
				fmt.Fprintln(os.Stderr, "💡 Tip: tearing down the kernel WireGuard interface requires root privileges (run with sudo).")
			}
			os.Exit(1)
		}

		if isLogout {
			fmt.Printf("✅ Logged out of FlareLens Mesh (interface %s down).\n", res.Interface)
		} else {
			fmt.Printf("✅ Disconnected FlareLens Mesh interface (%s).\n", res.Interface)
		}
		if res.RemoteRevoked {
			fmt.Println("  • Control Plane : Peer deregistered")
		}
		if res.HostsCleaned {
			fmt.Println("  • MagicDNS      : /etc/hosts entries cleaned")
		}
		if len(res.RemovedFiles) > 0 {
			fmt.Printf("  • Cleaned State : %d file(s) removed\n", len(res.RemovedFiles))
		}
		for _, w := range res.Warnings {
			fmt.Fprintf(os.Stderr, "  ⚠️  %s\n", w)
		}
		os.Exit(0)
	}

	// Subcommand: leave / uninstall (Cleanly unenroll server/workstation, stop daemon & remove installation; Docker workloads stay running)
	if len(os.Args) > 1 && (os.Args[1] == "uninstall" || os.Args[1] == "leave") {
		subCmd := os.Args[1]
		defaultKeepBin := subCmd == "leave"

		uninstFlags := flag.NewFlagSet(subCmd, flag.ExitOnError)
		configPath := uninstFlags.String("config", "", "Optional path to agent.yaml")
		controlURL := uninstFlags.String("control", os.Getenv("FLARELENS_CONTROL_URL"), "FlareLens Control Plane URL")
		token := uninstFlags.String("token", os.Getenv("FLARELENS_ENROLL_TOKEN"), "Control plane auth token")
		nodeID := uninstFlags.String("node-id", os.Getenv("FLARELENS_NODE_ID"), "Node ID to unenroll")
		ifaceName := uninstFlags.String("interface", "", "WireGuard interface name (default: flarelens0)")
		keepConfig := uninstFlags.Bool("keep-config", false, "Preserve /etc/flarelens configuration directory")
		keepBinary := uninstFlags.Bool("keep-binary", defaultKeepBin, "Keep flarelensd binary in /usr/local/bin")
		assumeYes := uninstFlags.Bool("yes", false, "Skip interactive confirmation prompt")
		assumeY := uninstFlags.Bool("y", false, "Skip interactive confirmation prompt (shorthand)")
		_ = uninstFlags.Parse(os.Args[2:])

		if os.Geteuid() != 0 && runtime.GOOS != "windows" {
			fmt.Fprintf(os.Stderr, "❌ Root privileges are required to stop systemd services and remove host files. Run: sudo flarelensd %s\n", subCmd)
			os.Exit(1)
		}

		var cfgArgs []string
		if *configPath != "" {
			cfgArgs = []string{"--config", *configPath}
		}
		var meshKeyPath string
		if loadedCfg, err := config.Load(cfgArgs); err == nil {
			*controlURL = cmp.Or(*controlURL, loadedCfg.ControlPlane.Endpoint)
			*token = cmp.Or(*token, loadedCfg.ControlPlane.EnrollToken)
			*nodeID = cmp.Or(*nodeID, loadedCfg.Identity.NodeID)
			*ifaceName = cmp.Or(*ifaceName, loadedCfg.Mesh.Interface)
			meshKeyPath = loadedCfg.Mesh.KeyPath
		}
		if meshState, err := mesh.LoadState(); err == nil && meshState != nil {
			*controlURL = cmp.Or(*controlURL, meshState.ControlURL)
			*ifaceName = cmp.Or(*ifaceName, meshState.Interface)
			meshKeyPath = cmp.Or(meshKeyPath, meshState.PrivateKeyPath)
		}

		if !*assumeYes && !*assumeY && isInteractiveTerminal() {
			fmt.Println("================================================================")
			fmt.Printf("  FlareLens Host Agent — %s\n", strings.ToUpper(subCmd))
			fmt.Println("================================================================")
			if *nodeID != "" {
				fmt.Printf("  • Node ID           : %s\n", *nodeID)
			}
			if *controlURL != "" {
				fmt.Printf("  • Control Plane     : %s\n", *controlURL)
			}
			fmt.Println("  • Docker Workloads  : KEPT RUNNING (containers & volumes untouched)")
			if *keepBinary {
				fmt.Println("  • Agent Binary      : KEPT on disk (--keep-binary)")
			} else {
				fmt.Println("  • Agent Binary      : WILL BE REMOVED")
			}
			fmt.Print("\nProceed? [y/N]: ")
			reader := bufio.NewReader(os.Stdin)
			line, _ := reader.ReadString('\n')
			ans := strings.ToLower(strings.TrimSpace(line))
			if ans != "y" && ans != "yes" {
				fmt.Println("Aborted.")
				os.Exit(0)
			}
		}

		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()

		exePath, _ := os.Executable()
		if resolvedExe, err := filepath.EvalSymlinks(exePath); err == nil && resolvedExe != "" {
			exePath = resolvedExe
		}

		logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
		res, err := system.RunUninstall(ctx, system.UninstallOptions{
			NodeID:         *nodeID,
			ControlURL:     *controlURL,
			AuthToken:      *token,
			MeshInterface:  *ifaceName,
			MeshKeyPath:    meshKeyPath,
			KeepConfig:     *keepConfig,
			KeepBinary:     *keepBinary,
			ExecutablePath: exePath,
			Logger:         logger,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ %s failed: %v\n", subCmd, err)
			os.Exit(1)
		}

		fmt.Println("================================================================")
		if *keepBinary {
			fmt.Println("  ✅ Host cleanly unenrolled from FlareLens (flarelensd leave)")
		} else {
			fmt.Println("  ✅ FlareLens Host Agent cleanly uninstalled")
		}
		fmt.Println("================================================================")
		if res.NodeUnenrolled {
			fmt.Printf("  • Control Plane     : Node %s unenrolled\n", *nodeID)
		}
		if res.MeshRevoked {
			fmt.Println("  • WireGuard Mesh    : Peer deregistered")
		}
		if res.ServiceRemoved {
			fmt.Println("  • Background Daemon : Stopped, disabled & unit removed")
		}
		if res.InterfaceRemoved {
			fmt.Printf("  • Network Overlay   : Interface %s removed\n", cmp.Or(*ifaceName, "flarelens0"))
		}
		if res.HostsCleaned {
			fmt.Println("  • MagicDNS          : /etc/hosts entries cleaned")
		}
		fmt.Println("  • Docker Workloads  : Running containers & volumes untouched")
		for _, w := range res.Warnings {
			fmt.Fprintf(os.Stderr, "  ⚠️  %s\n", w)
		}
		fmt.Println("================================================================")
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
	defer deployOrchestrator.CloseAllFunnelTunnels()
	defer deployOrchestrator.CloseAllLogSessions()

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
		envCtx := backup.WithDeployEnv(hookCtx, deploy.DeployEnvFromContext(hookCtx))
		logger.Info("Executing pre-deploy database snapshot guardrail", "service", service, "database", targetDB, "tag", tag)
		activeBackupOps.Add(1)
		defer activeBackupOps.Add(-1)
		_, hookErr := backupMgr.CreateBackupForDB(envCtx, tag, targetDB)
		return hookErr
	})

	// Hook automated snapshot rollback in case of migration failure
	deployOrchestrator.SetRollbackHook(func(hookCtx context.Context, service, tag string) error {
		targetDB := resolveTargetDB(hookCtx)
		envCtx := backup.WithDeployEnv(hookCtx, deploy.DeployEnvFromContext(hookCtx))
		logger.Warn("Executing automated snapshot rollback following migration failure", "service", service, "database", targetDB, "tag", tag)
		activeBackupOps.Add(1)
		defer activeBackupOps.Add(-1)
		return backupMgr.RestoreLatestMatchingTag(envCtx, tag, targetDB)
	})

	// Start automated cron scheduler for backups
	backupMgr.StartCron(ctx)

	// 7. Initialize in-memory Feature Flags Store
	flagStore := flags.NewStore(logger)

	// 8. Initialize WireGuard Mesh Engine & Multi-Node Service Router
	serviceRouter := mesh.NewServiceRouter(
		cfg.Identity.NodeID,
		func(rCtx context.Context, ep mesh.ClusterEndpoint) (string, error) {
			return deployOrchestrator.ResolveLocalEndpointTarget(
				rCtx,
				ep.Env,
				ep.Service,
				ep.Mode,
				ep.ContainerName,
				ep.ContainerPort,
				ep.ActivePort,
			)
		},
		logger,
	)
	defer serviceRouter.Close()
	deployOrchestrator.SetMeshRoutingHooks(serviceRouter.ExtraHostsForEnv, serviceRouter.RemoteUpstreamURLs)

	var magicDNS *mesh.MagicDNSServer
	if cfg.Mesh.Enabled {
		magicDNS = mesh.NewMagicDNSServer(mesh.MagicDNSConfig{
			DomainSuffix:  ".mesh",
			InterfaceName: cfg.Mesh.Interface,
		}, logger)
		defer magicDNS.Stop()
		deployOrchestrator.SetMeshDNSHook(magicDNS.DNSHookForEnv, magicDNS.SeedFromExtraHosts)
	}

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
				Subnet:         "100.64.0.0/10",
			}
			meshMgr = mesh.NewManager(meshCfg, meshPrivKey, meshPubKey, nil, logger)

			// Async registration with Cloudflare Worker Mesh Control Plane
			go func(mgr *mesh.Manager, dnsSrv *mesh.MagicDNSServer) {
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
						mgr.SetOverlayIP(regResp.Peer.OverlayIP)
						serviceRouter.SetOverlayIP(regResp.Peer.OverlayIP)
						if dnsSrv != nil {
							dnsSrv.UpdatePeers(regResp.Peers, regResp.Peer.OverlayIP, cfg.Identity.Hostname)
						}
						if err := mgr.InitInterface(context.Background()); err != nil {
							logger.Warn("WireGuard interface init warning (requires kernel module & CAP_NET_ADMIN)", "error", err)
						} else {
							_ = mgr.SyncPeers(context.Background(), regResp.Peers)
							if dnsSrv != nil && regResp.Peer.OverlayIP != "" {
								if dnsErr := dnsSrv.RebindOverlayIP(ctx, regResp.Peer.OverlayIP); dnsErr != nil {
									logger.Warn("MagicDNS overlay port-53 bind warning (retaining ExtraHosts fallback)",
										"overlay_ip", regResp.Peer.OverlayIP,
										"error", dnsErr,
									)
								}
							}
						}
					}
				}
			}(meshMgr, magicDNS)
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
			registerCommandListeners(natsClient, deployOrchestrator, backupMgr, flagStore, meshMgr, magicDNS, agentUpdater, cfg, logger)
		}
	} else if cfg.NATS.Mode != "disabled" && cfg.NATS.Mode != "none" && cfg.NATS.Mode != "off" {
		if err := natsClient.Connect(ctx); err != nil {
			logger.Warn("Initial NATS connection failed; will retry in background",
				"url", cfg.NATS.URL,
				"error", err,
			)
		} else {
			registerCommandListeners(natsClient, deployOrchestrator, backupMgr, flagStore, meshMgr, magicDNS, agentUpdater, cfg, logger)
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

	// 6. Configure piggybacked command, mesh peer, placement & feature-flag synchronization on the 15s heartbeat loop
	configureControlPlaneSync(ctx, reporter, flagStore, backupMgr, deployOrchestrator, agentUpdater, meshMgr, serviceRouter, magicDNS, cfg, logger)

	// 6a. Launch background telemetry + piggybacked control-plane sync loop (every 15s)
	go reporter.StartHeartbeatLoop(ctx)

	// 6b. Reconcile stable Docker DNS aliases for already-running containers on host startup
	go deployOrchestrator.ReconcileActiveAliases(ctx)

	// 6c. Launch local zero-latency Feature Flags edge daemon (HTTP on 0.0.0.0:8999 for containers)
	go startLocalFlagsServer(ctx, flagStore, logger)

	// 6d. Periodic Docker image garbage collection for retired Blue/Green tags (every 12h when idle)
	go startAutoImagePruneLoop(ctx, deployOrchestrator, logger)

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
	magicDNS *mesh.MagicDNSServer,
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
				if magicDNS != nil {
					magicDNS.UpdatePeers(peers, meshMgr.OverlayIP(), cfg.Identity.Hostname)
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

	// 12. One-Off & Scheduled Container Job Runner
	jobSubj := fmt.Sprintf("flarelens.node.%s.job.run", nodeID)
	_, _ = nc.Subscribe(jobSubj, func(msg *nats.Msg) {
		var jReq deploy.JobRunRequest
		if err := json.Unmarshal(msg.Data, &jReq); err != nil {
			logger.Error("Malformed job run payload", "error", err)
			return
		}
		if jReq.NodeID != "" && jReq.NodeID != "all" && jReq.NodeID != nodeID {
			return
		}
		go executeContainerJob(orchestrator, jReq, msg.Reply, nc, nodeID, cfg, logger)
	})

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

func executeContainerJob(
	orchestrator *deploy.Orchestrator,
	jReq deploy.JobRunRequest,
	replySubject string,
	nc *transport.NATSClient,
	nodeID string,
	cfg *config.Config,
	logger *slog.Logger,
) {
	statusURL := ""
	if cfg.ControlPlane.Endpoint != "" {
		statusURL = fmt.Sprintf("%s/api/v1/control/jobs/status", strings.TrimRight(cfg.ControlPlane.Endpoint, "/"))
	}
	jReq.NodeID = nodeID

	reportHTTPStatusSync(statusURL, cfg.ControlPlane.EnrollToken, map[string]any{
		"run_id":     jReq.RunID,
		"job_name":   jReq.JobName,
		"service":    jReq.Service,
		"env":        jReq.Env,
		"node_id":    nodeID,
		"status":     "running",
		"started_at": time.Now().UTC().Format(time.RFC3339),
	}, logger)

	if orchestrator == nil {
		reportHTTPStatusSync(statusURL, cfg.ControlPlane.EnrollToken, map[string]any{
			"run_id":    jReq.RunID,
			"job_name":  jReq.JobName,
			"service":   jReq.Service,
			"env":       jReq.Env,
			"node_id":   nodeID,
			"status":    "failed",
			"exit_code": 1,
			"error":     "container orchestrator not initialized on node",
		}, logger)
		return
	}

	res := orchestrator.RunJob(context.Background(), jReq)
	if nc != nil && replySubject != "" {
		_ = nc.PublishJSON(replySubject, res)
	}
	reportHTTPStatusSync(statusURL, cfg.ControlPlane.EnrollToken, map[string]any{
		"run_id":       res.RunID,
		"job_name":     res.JobName,
		"service":      res.Service,
		"env":          res.Env,
		"node_id":      nodeID,
		"container_id": res.ContainerID,
		"status":       res.Status,
		"exit_code":    res.ExitCode,
		"output":       res.Output,
		"error":        res.Error,
		"duration_ms":  res.DurationMS,
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
	AdoptOnly             bool                    `json:"adopt_only,omitzero"`
	Ports                 []string                `json:"ports"`
	Healthcheck           *deploy.HealthcheckSpec `json:"healthcheck"`
	ForceRecreateStateful bool                    `json:"force_recreate_stateful"`
	ContainerPort         int                     `json:"container_port"`
	HostPortBlue          int                     `json:"host_port_blue"`
	HostPortGreen         int                     `json:"host_port_green"`
	Domain                string                  `json:"domain"`
	Domains               []string                `json:"domains,omitempty"`
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
	Units                 []string                `json:"units,omitempty"`
	Reason                string                  `json:"reason,omitempty"`
	MeshPort              int                     `json:"mesh_port,omitzero"`
	MemoryMB              int                     `json:"memory_mb,omitzero"`
	CPUCores              float64                 `json:"cpu_cores,omitzero"`
	UntilHours            int                     `json:"until_hours,omitzero"`
	DrainSeconds          int                     `json:"drain_seconds,omitzero"`
	TimeoutSeconds        int                     `json:"timeout_seconds,omitzero"`
	RunID                 string                  `json:"run_id,omitempty"`
	JobName               string                  `json:"job_name,omitempty"`
	Trigger               string                  `json:"trigger,omitempty"`
	TunnelID              string                  `json:"tunnel_id,omitempty"`
	TargetIP              string                  `json:"target_ip,omitempty"`
	TargetPort            int                     `json:"target_port,omitzero"`
	SessionID             string                  `json:"session_id,omitempty"`
	TailLines             int                     `json:"tail_lines,omitzero"`
	Follow                bool                    `json:"follow,omitzero"`
	Timestamps            bool                    `json:"timestamps,omitzero"`
	Prefix                string                  `json:"prefix,omitempty"`
	RetainDays            int                     `json:"retain_days,omitzero"`
	ExtraHosts            []string                `json:"extra_hosts,omitempty"`
	RemoteUpstreams       []string                `json:"remote_upstreams,omitempty"`
	ForceRemoveStateful   bool                    `json:"force_remove_stateful,omitzero"`
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
	meshMgr *mesh.Manager,
	serviceRouter *mesh.ServiceRouter,
	magicDNS *mesh.MagicDNSServer,
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

	// Rehydrate any active public Funnel tunnels assigned to this gateway node across agent restarts / OTA updates
	if orchestrator != nil {
		go rehydrateActiveFunnelTunnels(ctx, client, orchestrator, cfg, nodeID, logger)
	}

	reporter.SetClusterSyncHandler(func(hbCtx context.Context, overlayIP string, rawPeers json.RawMessage, rawEndpoints json.RawMessage) {
		effectiveIP := overlayIP
		if effectiveIP == "" && meshMgr != nil {
			effectiveIP = meshMgr.OverlayIP()
		}
		if overlayIP != "" {
			if meshMgr != nil && meshMgr.OverlayIP() == "" {
				meshMgr.SetOverlayIP(overlayIP)
				_ = meshMgr.InitInterface(hbCtx)
			}
			if serviceRouter != nil {
				serviceRouter.SetOverlayIP(overlayIP)
			}
			if magicDNS != nil && magicDNS.ContainerDNSServer() == "" {
				if err := magicDNS.RebindOverlayIP(ctx, overlayIP); err != nil {
					logger.Debug("MagicDNS overlay port-53 bind skipped on heartbeat", "overlay_ip", overlayIP, "error", err)
				}
			}
		}
		if len(rawPeers) > 0 {
			var peers []mesh.Peer
			if err := json.Unmarshal(rawPeers, &peers); err == nil && len(peers) > 0 {
				if meshMgr != nil {
					if err := meshMgr.SyncPeers(hbCtx, peers); err != nil {
						logger.Debug("Piggybacked WireGuard peer sync skipped or warning", "error", err)
					}
				}
				if magicDNS != nil {
					magicDNS.UpdatePeers(peers, effectiveIP, cfg.Identity.Hostname)
				}
			}
		}
		if len(rawEndpoints) > 0 {
			var endpoints []mesh.ClusterEndpoint
			if err := json.Unmarshal(rawEndpoints, &endpoints); err == nil {
				if magicDNS != nil {
					magicDNS.UpdateServiceEndpoints(effectiveIP, endpoints)
				}
				if serviceRouter != nil {
					serviceRouter.UpdateEndpoints(effectiveIP, endpoints)
					if orchestrator != nil {
						for _, g := range serviceRouter.RouteGroups() {
							if !g.HasLocalNode && len(g.RemoteURLs) > 0 && len(g.Domains) > 0 {
								_ = orchestrator.SyncRemoteOnlyRoute(g.Env, g.Service, g.Domains, g.RemoteURLs, g.HealthPath)
							}
						}
					}
				}
			}
		}
	})

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

		// Acknowledge immediately for non-reboot commands; reboot_node strictly verifies ACK before invoking reboot
		if cmd.Type != "reboot_node" {
			ackCommand(cfg, client, cmd.ID, nodeID, logger)
		}

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
				var activeSlot string
				var activePort int

				// Prefer native Kamal-style container orchestrator (multi-network, companion workers, migrations, Traefik zero-downtime)
				if orchestrator != nil && os.Getenv("FLARELENS_USE_HOST_SCRIPTS") != "true" {
					logger.Info("Executing native container orchestration (zero-downtime)", "service", c.Service, "image", c.Image)
					dReq := deploy.DeployRequest{
						DeploymentID:      cmp.Or(c.DeploymentID, c.ID),
						Service:           c.Service,
						Image:             c.Image,
						Env:               c.Env,
						Domain:            c.Domain,
						Domains:           c.Domains,
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
						DrainSeconds:      c.DrainSeconds,
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
						MeshPort:          c.MeshPort,
						MemoryMB:          c.MemoryMB,
						CPUCores:          c.CPUCores,
						ExtraHosts:        c.ExtraHosts,
						RemoteUpstreams:   c.RemoteUpstreams,
					}
					resp := orchestrator.Deploy(context.Background(), dReq)
					deployStatus = resp.Status
					deployMsg = resp.Message
					activeSlot = resp.ActiveSlot
					activePort = resp.ActivePort
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
							"node_id":       nodeID,
							"service":       c.Service,
							"env":           c.Env,
							"status":        deployStatus,
							"active_slot":   activeSlot,
							"active_port":   activePort,
							"message":       deployMsg,
							"duration_ms":   time.Since(startTime).Milliseconds(),
						},
						logger,
					)
				}
				ackCommand(cfg, client, c.ID, nodeID, logger)
			}(cmd)

		case "decommission_service":
			go func(c NodeCommand) {
				defer inFlightCommands.Delete(c.ID)
				if orchestrator == nil {
					ackCommand(cfg, client, c.ID, nodeID, logger)
					return
				}
				logger.Info("Executing service decommission on node...", "service", c.Service, "env", c.Env, "id", c.ID)
				resp := orchestrator.DecommissionService(context.Background(), deploy.DecommissionRequest{
					DeploymentID:        cmp.Or(c.DeploymentID, c.ID),
					Service:             c.Service,
					Env:                 c.Env,
					ContainerName:       c.ContainerName,
					Domains:             c.Domains,
					HealthPath:          c.HealthPath,
					RemoteUpstreams:     c.RemoteUpstreams,
					DrainSeconds:        c.DrainSeconds,
					ForceRemoveStateful: c.ForceRemoveStateful,
				})
				if cfg.ControlPlane.Endpoint != "" {
					reportHTTPStatus(
						fmt.Sprintf("%s/api/v1/control/deploy/status", strings.TrimRight(cfg.ControlPlane.Endpoint, "/")),
						cfg.ControlPlane.EnrollToken,
						map[string]any{
							"deployment_id": resp.DeploymentID,
							"node_id":       nodeID,
							"service":       resp.Service,
							"env":           c.Env,
							"status":        resp.Status,
							"message":       resp.Message,
							"duration_ms":   resp.DurationMS,
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
					AdoptOnly:             c.AdoptOnly,
					Networks:              c.Networks,
					Aliases:               c.Aliases,
					Volumes:               c.Volumes,
					Ports:                 c.Ports,
					Command:               c.Command,
					Entrypoint:            c.Entrypoint,
					Healthcheck:           c.Healthcheck,
					Secrets:               c.Secrets,
					ExtraHosts:            c.ExtraHosts,
					MemoryMB:              c.MemoryMB,
					CPUCores:              c.CPUCores,
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
		case "prune_images":
			go func(c NodeCommand) {
				defer inFlightCommands.Delete(c.ID)
				if orchestrator != nil {
					retention := time.Duration(cmp.Or(c.UntilHours, 72)) * time.Hour
					pruneCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
					rep, err := orchestrator.PruneUnusedImages(pruneCtx, retention)
					cancel()
					if err != nil {
						logger.Warn("On-demand Docker image prune failed", "id", c.ID, "error", err)
					} else {
						logger.Info("On-demand Docker image prune completed",
							"id", c.ID,
							"images_deleted", rep.ImagesDeleted,
							"space_reclaimed_bytes", rep.SpaceReclaimed,
						)
					}
				}
				ackCommand(cfg, client, c.ID, nodeID, logger)
			}(cmd)
		case "run_job":
			go func(c NodeCommand) {
				defer inFlightCommands.Delete(c.ID)
				jReq := deploy.JobRunRequest{
					RunID:          cmp.Or(c.RunID, c.ID),
					JobName:        c.JobName,
					Service:        c.Service,
					Env:            c.Env,
					Image:          c.Image,
					Command:        c.Command,
					Entrypoint:     c.Entrypoint,
					Volumes:        c.Volumes,
					Networks:       c.Networks,
					Network:        c.Network,
					Secrets:        c.Secrets,
					ExtraHosts:     c.ExtraHosts,
					TimeoutSeconds: c.TimeoutSeconds,
					MemoryMB:       c.MemoryMB,
					CPUCores:       c.CPUCores,
					Trigger:        c.Trigger,
					NodeID:         nodeID,
				}
				executeContainerJob(orchestrator, jReq, "", nil, nodeID, cfg, logger)
				ackCommand(cfg, client, c.ID, nodeID, logger)
			}(cmd)
		case "sync_tunnel":
			go func(c NodeCommand) {
				defer inFlightCommands.Delete(c.ID)
				if orchestrator != nil {
					_, err := orchestrator.SyncFunnelTunnel(context.Background(), deploy.FunnelTunnelSpec{
						TunnelID:   c.TunnelID,
						Domain:     c.Domain,
						TargetIP:   c.TargetIP,
						TargetPort: c.TargetPort,
					})
					if err != nil {
						logger.Warn("Failed to sync Funnel tunnel route", "tunnel_id", c.TunnelID, "domain", c.Domain, "error", err)
					}
				}
				ackCommand(cfg, client, c.ID, nodeID, logger)
			}(cmd)
		case "remove_tunnel":
			go func(c NodeCommand) {
				defer inFlightCommands.Delete(c.ID)
				if orchestrator != nil {
					orchestrator.RemoveFunnelTunnel(c.TunnelID)
				}
				ackCommand(cfg, client, c.ID, nodeID, logger)
			}(cmd)
		case "stream_container_logs":
			go func(c NodeCommand) {
				defer inFlightCommands.Delete(c.ID)
				ackCommand(cfg, client, c.ID, nodeID, logger)
				if orchestrator == nil || cfg.ControlPlane.Endpoint == "" {
					return
				}
				pushURL := fmt.Sprintf("%s/api/v1/control/containers/logs/push", strings.TrimRight(cfg.ControlPlane.Endpoint, "/"))
				orchestrator.StreamContainerLogSession(context.Background(), deploy.ContainerLogStreamRequest{
					SessionID:       cmp.Or(c.SessionID, c.ID),
					Env:             c.Env,
					Service:         c.Service,
					ContainerName:   c.ContainerName,
					TailLines:       c.TailLines,
					Follow:          c.Follow,
					Timestamps:      c.Timestamps,
					DurationSeconds: c.TimeoutSeconds,
				}, func(payload deploy.ContainerLogPushPayload) (bool, error) {
					raw, _ := json.Marshal(payload)
					req, err := http.NewRequest(http.MethodPost, pushURL, bytes.NewReader(raw))
					if err != nil {
						return false, err
					}
					req.Header.Set("Content-Type", "application/json")
					if cfg.ControlPlane.EnrollToken != "" {
						req.Header.Set("Authorization", "Bearer "+cfg.ControlPlane.EnrollToken)
					}
					resp, err := client.Do(req)
					if err != nil {
						return false, err
					}
					var resBody struct {
						Stop bool `json:"stop"`
					}
					_ = json.NewDecoder(resp.Body).Decode(&resBody)
					_ = resp.Body.Close()
					return resBody.Stop, nil
				})
			}(cmd)
		case "stop_container_logs":
			go func(c NodeCommand) {
				defer inFlightCommands.Delete(c.ID)
				if orchestrator != nil {
					orchestrator.StopContainerLogSession(c.SessionID)
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
				logger.Info("Executing queued database backup...", "tag", tag, "key", c.Key, "target_db", c.TargetDB, "command_id", c.ID)
				bkCtx := backup.WithDeployEnv(context.Background(), c.Env)
				bkCtx = backup.WithContainerName(bkCtx, c.ContainerName)
				meta, err := backupMgr.CreateBackupForDB(bkCtx, tag, c.TargetDB, c.Key)
				var prunedKeys []string
				if err == nil && c.RetainDays > 0 {
					prunedKeys, _ = backupMgr.PruneExpiredBackups(bkCtx, c.Prefix, c.RetainDays)
				}
				statusPayload := map[string]any{
					"key":       c.Key,
					"node_id":   nodeID,
					"tag":       tag,
					"service":   c.Service,
					"env":       c.Env,
					"target_db": c.TargetDB,
				}
				if len(prunedKeys) > 0 {
					statusPayload["pruned_keys"] = prunedKeys
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

		case "retire_systemd_units":
			go func(c NodeCommand) {
				defer inFlightCommands.Delete(c.ID)
				startTime := time.Now()
				logger.Info("Executing zero-SSH systemd unit retirement...", "units", c.Units, "id", c.ID)

				results, err := system.RetireSystemdUnits(context.Background(), c.Units, nil)
				retiredCount := 0
				missingCount := 0
				retiredNames := make([]string, 0, len(results))
				for _, r := range results {
					switch r.Status {
					case "retired":
						retiredCount++
						retiredNames = append(retiredNames, r.Unit)
					case "not_present":
						missingCount++
					}
				}

				status := "success"
				msg := fmt.Sprintf("Systemd maintenance complete: %d retired (%s), %d not present", retiredCount, strings.Join(retiredNames, ", "), missingCount)
				if err != nil {
					status = "failed"
					msg = fmt.Sprintf("Systemd maintenance error: %v (retired=%d, not_present=%d)", err, retiredCount, missingCount)
					logger.Error("Systemd unit retirement failed", "error", err, "id", c.ID)
				} else {
					logger.Info("Systemd unit retirement succeeded", "retired", retiredCount, "not_present", missingCount, "id", c.ID)
				}

				if cfg.ControlPlane.Endpoint != "" {
					reportHTTPStatusSync(
						fmt.Sprintf("%s/api/v1/control/deploy/status", strings.TrimRight(cfg.ControlPlane.Endpoint, "/")),
						cfg.ControlPlane.EnrollToken,
						map[string]any{
							"deployment_id": cmp.Or(c.DeploymentID, c.ID),
							"service":       cmp.Or(c.Service, "host-maintenance"),
							"status":        status,
							"message":       msg,
							"duration_ms":   time.Since(startTime).Milliseconds(),
						},
						logger,
					)
				}
				ackCommand(cfg, client, c.ID, nodeID, logger)
			}(cmd)

		case "reboot_node":
			go func(c NodeCommand) {
				defer inFlightCommands.Delete(c.ID)
				startTime := time.Now()
				logger.Warn("Received drain-locked graceful OS reboot command", "id", c.ID, "reason", c.Reason)

				isIdle := func() bool {
					return (orchestrator == nil || orchestrator.ActiveOps() == 0) && activeBackupOps.Load() == 0
				}
				if err := system.WaitForDrainLock(context.Background(), isIdle, 5*time.Minute, 500*time.Millisecond); err != nil {
					logger.Error("Aborting OS reboot: active operations did not drain within timeout", "error", err, "id", c.ID)
					if cfg.ControlPlane.Endpoint != "" {
						reportHTTPStatusSync(
							fmt.Sprintf("%s/api/v1/control/deploy/status", strings.TrimRight(cfg.ControlPlane.Endpoint, "/")),
							cfg.ControlPlane.EnrollToken,
							map[string]any{
								"deployment_id": cmp.Or(c.DeploymentID, c.ID),
								"service":       cmp.Or(c.Service, "host-reboot"),
								"status":        "failed",
								"message":       fmt.Sprintf("Aborted reboot: %v", err),
								"duration_ms":   time.Since(startTime).Milliseconds(),
							},
							logger,
						)
					}
					ackCommand(cfg, client, c.ID, nodeID, logger)
					return
				}

				// CRITICAL: Confirm command ACK on the control plane BEFORE calling reboot so the node can never reboot-loop
				if err := ackCommandStrict(context.Background(), cfg, client, c.ID, nodeID, logger); err != nil {
					logger.Error("Aborting OS reboot: failed to confirm command ACK with control plane", "error", err, "id", c.ID)
					if cfg.ControlPlane.Endpoint != "" {
						reportHTTPStatusSync(
							fmt.Sprintf("%s/api/v1/control/deploy/status", strings.TrimRight(cfg.ControlPlane.Endpoint, "/")),
							cfg.ControlPlane.EnrollToken,
							map[string]any{
								"deployment_id": cmp.Or(c.DeploymentID, c.ID),
								"service":       cmp.Or(c.Service, "host-reboot"),
								"status":        "failed",
								"message":       fmt.Sprintf("Aborted reboot to prevent loop: command ACK failed (%v)", err),
								"duration_ms":   time.Since(startTime).Milliseconds(),
							},
							logger,
						)
					}
					return
				}

				if cfg.ControlPlane.Endpoint != "" {
					reportHTTPStatusSync(
						fmt.Sprintf("%s/api/v1/control/deploy/status", strings.TrimRight(cfg.ControlPlane.Endpoint, "/")),
						cfg.ControlPlane.EnrollToken,
						map[string]any{
							"deployment_id": cmp.Or(c.DeploymentID, c.ID),
							"service":       cmp.Or(c.Service, "host-reboot"),
							"status":        "success",
							"message":       fmt.Sprintf("Graceful OS reboot initiated on %s after drain lock and verified command ACK", nodeID),
							"duration_ms":   time.Since(startTime).Milliseconds(),
						},
						logger,
					)
				}

				logger.Warn("Drain lock clear and command ACK verified; executing system reboot in 2s...", "node_id", nodeID, "id", c.ID)
				time.Sleep(2 * time.Second)
				executeSystemReboot(logger)
			}(cmd)

		default:
			inFlightCommands.Delete(cmd.ID)
		}
	}
}

func ackCommandStrict(ctx context.Context, cfg *config.Config, client *http.Client, cmdID string, nodeID string, logger *slog.Logger) error {
	if cfg.ControlPlane.Endpoint == "" {
		return errors.New("control plane endpoint is empty")
	}
	ackURL := fmt.Sprintf("%s/api/v1/control/commands/ack?id=%s&node_id=%s",
		strings.TrimRight(cfg.ControlPlane.Endpoint, "/"),
		url.QueryEscape(cmdID),
		url.QueryEscape(nodeID),
	)
	var lastErr error
	for attempt := range 3 {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, ackURL, nil)
		if err != nil {
			return err
		}
		if cfg.ControlPlane.EnrollToken != "" {
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", cfg.ControlPlane.EnrollToken))
		}
		resp, err := client.Do(req)
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				return nil
			}
			lastErr = fmt.Errorf("unexpected ACK status %d", resp.StatusCode)
		} else {
			lastErr = err
		}
		logger.Warn("Retrying strict command ACK...", "attempt", attempt+1, "id", cmdID, "error", lastErr)
		time.Sleep(time.Duration(attempt+1) * time.Second)
	}
	return lastErr
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

func startAutoImagePruneLoop(ctx context.Context, orchestrator *deploy.Orchestrator, logger *slog.Logger) {
	if orchestrator == nil {
		return
	}
	ticker := time.NewTicker(12 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			orchestrator.MaybeAutoPruneImages(ctx)
		}
	}
}

func rehydrateActiveFunnelTunnels(
	ctx context.Context,
	client *http.Client,
	orchestrator *deploy.Orchestrator,
	cfg *config.Config,
	nodeID string,
	logger *slog.Logger,
) {
	if orchestrator == nil || cfg == nil || cfg.ControlPlane.Endpoint == "" {
		return
	}
	reqURL := fmt.Sprintf("%s/api/v1/control/tunnels", strings.TrimRight(cfg.ControlPlane.Endpoint, "/"))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return
	}
	if cfg.ControlPlane.EnrollToken != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.ControlPlane.EnrollToken)
	}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return
	}

	var payload struct {
		Tunnels []struct {
			TunnelID   string `json:"tunnel_id"`
			NodeID     string `json:"node_id"`
			Domain     string `json:"domain"`
			TargetIP   string `json:"target_ip"`
			TargetPort int    `json:"target_port"`
		} `json:"tunnels"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return
	}
	for _, t := range payload.Tunnels {
		if t.TunnelID == "" || t.Domain == "" || t.TargetIP == "" || t.TargetPort < 1 {
			continue
		}
		if t.NodeID != "" && t.NodeID != nodeID {
			continue
		}
		if _, syncErr := orchestrator.SyncFunnelTunnel(ctx, deploy.FunnelTunnelSpec{
			TunnelID:   t.TunnelID,
			Domain:     t.Domain,
			TargetIP:   t.TargetIP,
			TargetPort: t.TargetPort,
		}); syncErr != nil {
			logger.Warn("Startup Funnel tunnel rehydration warning", "tunnel_id", t.TunnelID, "domain", t.Domain, "error", syncErr)
		}
	}
}
