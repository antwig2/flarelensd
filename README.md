# flarelensd

> **The lightweight in-kernel host execution daemon for the FlareLens sovereign infrastructure control plane — in-kernel WireGuard mesh, atomic blue/green deployments, zero-plaintext secrets, and streaming telemetry in a single <25MB Go binary.**

[![CI](https://github.com/antwig2/flarelensd/actions/workflows/ci.yml/badge.svg)](https://github.com/antwig2/flarelensd/actions/workflows/ci.yml)
[![Release](https://github.com/antwig2/flarelensd/actions/workflows/release.yml/badge.svg)](https://github.com/antwig2/flarelensd/actions/workflows/release.yml)
[![Go Version](https://img.shields.io/badge/Go-1.24-00ADD8?style=flat&logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Platforms](https://img.shields.io/badge/Platforms-Linux_|_Windows_|_macOS-informational)](https://github.com/antwig2/flarelensd/releases)
[![Control Plane](https://img.shields.io/badge/Control_Plane-Cloudflare_Workers-F38020?style=flat&logo=cloudflare)](https://github.com/antwig2/flarelens)

---

> [!NOTE]
> This repository contains **`flarelensd`**, the native host daemon.  
> For the serverless edge control plane and dashboard UI, see **[`flarelens`](https://github.com/antwig2/flarelens)** (deployable to Cloudflare Workers with 1 click).

---

## ⚡ Overview

**FlareLens** is the unified operational control plane for your infrastructure.

It unifies 4 major systems that previously required 4 separate tools:

```
┌────────────────────────────────────────────────────────────────────────┐
│                               FLARELENS                                │
│                                                                        │
│   1. OBSERVABILITY      ───  Live Logs, Metrics, Global Uptime Checks  │
│   2. ZERO-TRUST MESH    ───  P2P WireGuard Overlay (No Bastion/SSH)    │
│   3. GITOPS DEPLOYMENTS ───  Atomic Blue/Green Container Swaps (<1ms)  │
│   4. SECRETS & FLAGS    ───  Edge AES-256 Vault & Real-Time Flags      │
└────────────────────────────────────────────────────────────────────────┘
```

### The 4 Pillars of FlareLens:

#### 1. Observability (Replaces Grafana / Datadog / BetterStack)
- **Real-Time Live Tail**: Stream container and host logs in real time over SSE/WebSocket.
- **Serverless Edge Lakehouse**: Saves cold logs as compressed columnar Parquet files directly in Cloudflare R2 ($0 bandwidth egress fees).
- **Global Uptime Monitoring**: Cloudflare Worker pings your services every 60 seconds from 300+ cities worldwide and sends alerts to Telegram, Slack, WhatsApp, or Email.

#### 2. Zero-Trust Networking (Replaces Bastion Hosts / Tailscale / OpenVPN)
- **Serverless Edge Coordinator**: Coordinated serverlessly across 330+ Cloudflare edge PoPs (Workers + KV) with RFC 8628 Device Flow browser SSO (`@yourcompany.com`). **Zero coordinator VMs or SQLite databases to maintain.**
- **Pure P2P WireGuard Data Plane**: Encrypted point-to-point overlay (`100.64.0.0/10` CGNAT) running directly over UDP with **< 0.1ms kernel latency and $0 egress fees**.
- **Traefik Mesh Ingress**: Internal dashboards and container services bind directly to `100.64.0.1` (`flarelens0`), leaving zero public firewall ports open to port scanners.
- **Outbound-Only Signaling**: Eliminates open inbound SSH ports (port 22) to the public internet; port 22 is strictly bound to the private WireGuard mesh.

#### 3. GitOps & Zero-Downtime Deployments (Replaces Portainer / Jenkins / ArgoCD)
- **Atomic Blue/Green Rollouts**: Deploys the new container (Green), verifies its health on localhost, and performs an atomic inotify swap on Traefik routing in **< 1 millisecond** (zero dropped TCP connections).
- **Isolated Migration Runner**: Executes database schema migrations in an ephemeral container with auto-rollback before live traffic hits the new app version.

#### 4. Secrets Vault & Feature Flags (Replaces HashiCorp Vault / LaunchDarkly)
- **Encrypted Secrets Vault (AES-256-GCM)**: All your production secrets live encrypted at the Cloudflare edge.
- **RAM-Only Injection**: Secrets and cryptographic PEM keys are injected directly into container memory (`-e KEY=VAL`), leaving zero plaintext `.env` files on host hard drives.
- **Edge Feature Flags**: Evaluate toggle flags locally in **< 1 microsecond** with instant propagation from the dashboard.

> **In One Sentence:**  
> **FlareLens is Observability + Zero-Trust Networking + Continuous Deployment + Secrets Management, managed from a single serverless Cloudflare dashboard.**

---

### Fleet Overview

```
┌────────────────────────────────────────────────────────────────────────┐
│                   CLOUDFLARE EDGE CONTROL PLANE                        │
│               https://<your-worker-subdomain>.workers.dev              │
│                                                                        │
│   Single Dashboard for Logs, Metrics, Health, Alerts, Secrets & Flags │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │ Metadata & Signaling Only (TLS / WS)
       ┌───────────────────────────┼───────────────────────────┐
       ▼                           ▼                           ▼
┌───────────────────────┐ ┌───────────────────────┐ ┌───────────────────────┐
│   BARE-METAL / VM     │ │    CONTAINER HOST     │ │ DEVELOPER WORKSTATION │
│   (Zero Containers)   │ │   (Docker / Podman)   │ │  (Windows / macOS)    │
├───────────────────────┤ ├───────────────────────┤ ├───────────────────────┤
│ • Native Systemd apps │ │ • Blue/Green rollouts │ │ • P2P WireGuard mesh  │
│ • Host PostgreSQL     │ │ • Traefik atomic swap │ │ • Secure admin access │
│ • Kernel OOM (-1000)  │ │ • Container telemetry │ │ • Secrets injection   │
│ • OS reboot detection │ │ • In-memory secrets   │ │ • Zero open ports     │
└───────────────────────┘ └───────────────────────┘ └───────────────────────┘
```

### Fleet Mesh Architecture

```mermaid
flowchart TD
    subgraph External ["External Access"]
        Users["Public Web Users<br/>(Browsers / Mobile)"]
        Operator["Operator / Developer<br/>(Tailscale / WireGuard Client)"]
    end

    subgraph ControlPlane ["Cloudflare Serverless Control Plane"]
        CF_WAF["Cloudflare Edge & WAF<br/>(Public Ingress & DDoS)"]
        CF_Worker["FlareLens Control Plane<br/>(Edge API & Telemetry Sink)"]
        CF_KV[("Cloudflare KV<br/>(Secrets & Flags)")]
        CF_R2[("Cloudflare R2<br/>(Logs & DB Backups)")]
        CF_Queue["Cloudflare Queues<br/>(Task & Deploy Queue)"]

        CF_Worker --- CF_KV
        CF_Worker --- CF_R2
        CF_Worker --- CF_Queue
    end

    Users ==>|HTTPS Port 443| CF_WAF

    subgraph Node1 ["VPS Node 1 (Primary Droplet)"]
        Agent1["flarelens-agent<br/>• Host Daemon<br/>• OOM -1000"]
        Traefik1["Traefik Ingress<br/>(Bound to 100.64.0.1)"]
        WG1["WireGuard Interface<br/>flarelens0 (100.64.0.1)"]
    end

    subgraph Node2 ["VPS Node 2 (Worker Host)"]
        Agent2["flarelens-agent<br/>(Host Daemon)"]
        WG2["WireGuard Interface<br/>flarelens0 (100.64.0.2)"]
    end

    subgraph Node3 ["VPS Node 3 (Analytics / Standby)"]
        Agent3["flarelens-agent<br/>(Host Daemon)"]
        WG3["WireGuard Interface<br/>flarelens0 (100.64.0.3)"]
    end

    CF_WAF ==>|Outbound Tunnel Protocol| CFD1

    CF_Queue -.->|Outbound HTTPS Long-Poll| Agent1
    CF_Queue -.->|Outbound HTTPS Long-Poll| Agent2
    CF_Queue -.->|Outbound HTTPS Long-Poll| Agent3

    Agent1 -->|Parquet Log Streams| CF_R2
    Agent2 -->|Parquet Log Streams| CF_R2
    Agent3 -->|Parquet Log Streams| CF_R2

    Operator -.->|Signaling & Auth| Agent1
    Operator <==>|"Direct P2P Encrypted WireGuard"| WG1
    Operator <==>|"Direct P2P Encrypted WireGuard"| WG2
    Operator <==>|"Direct P2P Encrypted WireGuard"| WG3

    WG1 <==>|"P2P Mesh Tunnel (UDP 51820)"| WG2
    WG2 <==>|"P2P Mesh Tunnel (UDP 51820)"| WG3
    WG1 <==>|"P2P Mesh Tunnel (UDP 51820)"| WG3
```

---

### GitOps Blue/Green Zero-Downtime Pipeline

```mermaid
flowchart TD
    subgraph CI ["CI/CD Pipeline"]
        GHA["GitHub Actions<br/>(Workload Identity OIDC)"]
    end

    subgraph Edge ["Cloudflare Control Plane"]
        Worker["flarelens-worker<br/>(Validates GitHub OIDC JWT)"]
        Queue["Cloudflare Queue<br/>(flarelens-deploy-queue)"]
        KV[("Cloudflare KV<br/>(AES-256 Encrypted Secrets)")]

        Worker -->|Enqueue Deploy Task| Queue
        Worker --- KV
    end

    GHA -->|POST /api/v1/deploy| Worker

    subgraph Host ["Host Deployment Execution"]
        Agent["flarelens-agent<br/>• Polls Queue<br/>• Decrypts Secrets in RAM"]
        
        subgraph Docker ["Docker Engine Runtime"]
            Migrate["Ephemeral Migration Container<br/>(docker run --rm)"]
            Blue["Active Container (Blue)<br/>(Serving Current Traffic)"]
            Green["Candidate Container (Green)<br/>(RAM Injected Secrets)"]
        end

        Traefik["Traefik Dynamic Router<br/>(/etc/traefik/dynamic/app.yaml)"]
    end

    Queue -.->|Fetch Deploy Event| Agent
    KV -.->|Fetch Encrypted Secrets| Agent

    Agent -->|1. Run Pre-flight Migrations| Migrate
    Migrate -->|Success / Abort Rollback| Agent
    Agent -->|2. Start Candidate Container| Green
    Agent -.->|3. Local Health Probes| Green
    Agent -->|"4. Atomic inotify YAML Swap (<1ms)"| Traefik
    
    Traefik -.->|Old Route| Blue
    Traefik ==>|Active Cutover| Green
    
    Agent -->|5. Graceful Stop & Remove| Blue
```

---

## 🔒 Architecture: Control Plane vs. Data Plane

A foundational design principle of FlareLens is the strict physical separation between the **Control Plane** and the **Data Plane**:

```
┌────────────────────────────────────────────────────────────────────────┐
│                   CONTROL PLANE (Cloudflare Edge)                      │
│                  "The Orchestrator, Not the Router"                    │
│                                                                        │
│   • Coordinates WireGuard peer discovery (Public Keys & Endpoints in KV│
│   • Enforces Zero-Trust Admin Identity (Cloudflare Access SSO / OTP)  │
│   • Stores Cold Parquet Logs & DB Backups (Cloudflare R2 - $0 Egress)  │
│   • Runs Serverless across 300+ cities (Zero master servers to patch)  │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │ Metadata & Signaling Only (KB/sec)
                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│                      DATA PLANE (WireGuard Mesh)                       │
│                        "Direct, Private, P2P"                          │
│                                                                        │
│    [ Node 1 (AWS) ] ◄═════════ Direct Encrypted ════════► [ Node 2 ]   │
│                       UDP P2P (10.42.0.0/16)                           │
│                                                                        │
│    ❌ NEVER touches Cloudflare data centers.                            │
│    ❌ Zero packet inspection or throttling by third parties.            │
│    ✅ Full LAN line-speed (10Gbps+ direct).                             │
│    ✅ End-to-end encrypted with local Curve25519 keys (RFC 7748).      │
└────────────────────────────────────────────────────────────────────────┘
```

### Why Cloudflare for the Control Plane?
Traditional platforms require provisioning and maintaining expensive central master servers (Kubernetes Control Plane nodes, HashiCorp Consul clusters, or Jenkins controllers) with open public IP ports. 

FlareLens eliminates the master server by leveraging Cloudflare's free-tier serverless edge primitives:
- **Cloudflare Workers**: High-performance, sub-10ms global edge API.
- **Cloudflare D1 (`$0` Free Tier)**: Relational control-plane state (`nodes`, `node_commands`, `deployments`, `feature_flags`) piggybacked onto a single **15-second heartbeat** (`POST /api/v1/ingest`) — **zero R2 `list()` Class A polling calls**.
- **Cloudflare Access**: Optional Enterprise Zero-Trust identity (Google, GitHub, Microsoft 365, or Email One-Time PIN) protecting the dashboard.
- **Cloudflare KV**: AES-256-GCM encrypted Secrets Vault, declarative `fleet/*.yml` manifest registry, and WireGuard peer coordination.
- **Cloudflare R2**: Columnar Parquet log lakehouse and streaming database backup storage with **zero bandwidth egress fees**.

### Public Ingress: Standalone Traefik/Caddy vs. Optional `cloudflared`
**Standalone FlareLens users do NOT need `cloudflared`.**
- **Direct Edge Ingress (Default)**: Point DNS `A`/`AAAA` records directly at your VM (`80/tcp`, `443/tcp`) and let Traefik or Caddy terminate Let's Encrypt TLS natively while `flarelensd` flips dynamic upstream routes in `< 1ms`.
- **Optional Zero-Inbound-Port Tunnel (`cloudflared`)**: If you want zero open inbound TCP ports (`22`, `80`, `443` all closed at your cloud firewall) plus Cloudflare WAF/DDoS protection, you can optionally declare `cloudflared` as a singleton container in `fleet/infra/cloudflared.yml` (`networks: ["host"]`, `adopt_only: true`) forwarding to `http://127.0.0.1:80` (Traefik).

### Why WireGuard for the Data Plane?
Private inter-server communications, database replication, internal microservice calls, and operator SSH sessions **never touch Cloudflare**. They travel **directly peer-to-peer (P2P)** between your machines over an encrypted WireGuard UDP overlay (`10.42.0.0/16`), delivering full line-speed and absolute privacy.

---

## ✨ Core Superpowers

### 🌐 1. Serverless Edge-Native WireGuard Mesh (P2P)
- **Serverless Cloudflare Edge Coordinator**: Replaces centralized Headscale VMs with a global serverless coordinator on Cloudflare Workers + KV (`control.yourcompany.com`). Zero coordinator VMs and zero SQLite servers to manage.
- **Browser SSO Device Flow (RFC 8628)**: Users run `sudo flarelens-agent login` and authenticate via Cloudflare Access Zero Trust (`@yourcompany.com`) in their web browser.
- **Pure P2P Kernel Data Plane**: Traffic between servers and laptops flows directly peer-to-peer at line-rate Linux kernel speed (`flarelens0` via ChaCha20-Poly1305) with zero proxy hops.
- **Traefik Mesh Integration**: Workloads and admin dashboards can listen exclusively on private/loopback interfaces, keeping public firewall ports closed to attackers.
- **Pure Go Cryptography**: Keypairs generated in-memory using `golang.org/x/crypto/curve25519` with RFC 7748 key clamping (`priv[0] &= 248`, `priv[31] = (priv[31] & 127) | 64`).
- **Zero Inbound WAN SSH**: Traverses NATs and corporate firewalls without opening host SSH ports (port 22) to the public internet; administrative SSH is locked strictly to the private mesh.

### 🔄 2. Declarative `fleet/*.yml` & Blue/Green Zero-Downtime GitOps
- **ArgoCD-Style `fleet/<env>/*.yml` Reconciliation**: Syncs both stateless Blue/Green web services (with Kamal-style companion `workers`, `aliases`, `domains`, and `env_vars`) and stateful/infrastructure singletons (`postgres`, `dragonfly`, `traefik`, `vector`, optional `cloudflared`) with `adopt_only: true`, `networks: ["host"]`, and `enabled: false` (`Suspended` staging).
- **Atomic Inotify Route Swapping**: Auto-discovers Traefik's live dynamic routes mount (including nested `routes/` subdirectories), updates existing alias route files in place or generates multi-host `Host(...) || Host(...)` rules via atomic file renames (`os.Rename(tmp, final)`), cutting over traffic in **< 1 millisecond with zero dropped TCP packets**.
- **Brownfield Slot & Port Adoption**: Automatically detects pre-existing legacy slot containers, avoids bound host-port collisions, promotes stable Docker DNS aliases (`PromoteNetworkAliases`) after readiness probes pass, and cleanly retires replaced web/worker containers after drain.
- **Isolated Migration Runner & Automated Rollback**: Executes database migrations inside an ephemeral container (`docker run --rm`) with RAM-mounted secret files before cutover, rolling back automatically on failure.

### 🔁 3. Zero-SSH Over-The-Air (OTA) Upgrades & Host Maintenance
- **Cryptographic `self_update`**: Verified with SHA-256 digests, drain-locked (`ActiveOps() == 0`), symlink-safe under `ProtectSystem=full`, smoke-tested before atomic swap, and self-healing if restart fails.
- **Allowlisted Systemd Unit Retirement (`retire_systemd_units`)**: Safely stops and disables deprecated host polling `.timer`/`.service` units over D-Bus without SSH or shell invocation while blocking protected OS/agent units.
- **Drain-Locked Graceful OS Reboot (`reboot_node`)**: Waits for active deployments and R2 backups to drain, strictly confirms command `ACK` with the D1 control plane first (making reboot loops impossible), and triggers a clean `systemctl reboot` when `/var/run/reboot-required` is raised.

### 🚩 4. Edge-Synchronized Feature Flags
- **Zero-Latency In-Memory Evaluation**: The Go agent maintains a local, thread-safe cache (`Store` with `sync.RWMutex`). Application flag lookups complete in **< 1 microsecond with 0 network hops**.
- **Piggybacked Edge Sync**: Flag version hashes travel inside the 15-second heartbeat response, triggering instant delta syncs only when flags actually change.
- **Percentage Rollouts**: Supports deterministic rollout percentages (`rollout_pct: 0-100`) and environment scoping (`production`, `staging`, `infra`).

### 📊 5. Parquet Log Lakehouse & Live Stream
- **Dual-Tier Ingestion**: Ingests logs from systemd journald, Docker socket, syslog, Vector, or application SDKs via `POST /api/v1/ingest`.
- **Sub-Second Live Tail**: Real-time in-memory ring buffer streams live events to the web UI via Server-Sent Events (`/api/v1/live/sse`).
- **Columnar R2 Storage**: Automatically compacts log streams into compressed Apache Parquet files in Cloudflare R2, enabling DuckDB-WASM SQL queries in the browser with **zero egress costs**.
- **Resilient WAL**: Local Write-Ahead Log buffers data to disk during network blips, guaranteeing zero log loss.

### 🔐 6. Zero-Trust Secrets Vault & RAM Secret Files
- **AES-GCM-256 Authenticated Encryption**: Secrets are stored encrypted in Cloudflare KV and merged with manifest `env_vars` at deploy time.
- **In-Memory Env & `tmpfs` File Injection**: Secrets are injected directly into container environment variables (`-e KEY=VAL`) and ephemeral `/dev/shm` (`0700`/`0600`) RAM-backed files (`__FLARELENS_FILE__`) for PEM/SAML certificates — **never written to persistent host disks**.

### 💾 7. Zero-Disk Streaming Database Backups
- **Memory-Piped `pg_dump`**: Streams compressed database backups directly into Cloudflare R2 via Go's `io.Pipe` and multipart S3 uploads.
- **Prevents Node Crashes**: Eliminates temporary 20GB `.sql` files on `/tmp`, preventing disk-full failures during deployments.
- **Host-Native & Container Support**: Works with both containerized PostgreSQL and host-native PostgreSQL installs.

### 🛡️ 8. Host Kernel OOM Governance & System Health
- **Self-Preservation**: Automatically sets `/proc/self/oom_score_adj = -1000` at startup on Linux so the host kernel never kills the FlareLens daemon under heavy load.
- **Workload Score Ladder**: Proactively prioritizes container survival (`-900` for databases, `-800` for caches, `+500` for background workers).
- **OS Kernel Patching & Reboot Detection**: Tracks `/var/run/reboot-required` on Linux and `RebootPending` registry keys on Windows, surfacing 1-click drain-locked reboots in the dashboard.

---

## 🚀 Getting Started

Deploying FlareLens consists of two straightforward steps:
1. **Deploy your Control Plane**: Run the serverless Worker on **your own Cloudflare account** (`$0/month` free tier).
2. **Install the Agent on your Nodes**: Download `flarelensd` directly from **GitHub Releases** and point it to **your deployed Worker URL**.

---

### Step 1: Deploy Your Control Plane (Cloudflare Worker + D1 + KV + R2)

FlareLens uses Cloudflare Workers, D1, KV, and R2 as a 100% serverless, zero-maintenance control plane. You deploy this into **your own Cloudflare account** for complete data ownership and zero SaaS markup.

```bash
# 1. Clone the Control Plane repository
git clone https://github.com/antwig2/flarelens.git
cd flarelens

# 2. Install dependencies
npm install

# 3. Create Cloudflare D1 database, KV namespace, and R2 bucket
npx wrangler d1 create flarelens-control
npx wrangler kv namespace create FLEET_KV
npx wrangler r2 bucket create flarelens-logs-cold

# Copy the returned database_id and KV id into wrangler.toml, then apply the D1 schema:
npx wrangler d1 migrations apply flarelens-control --remote

# 4. Set your dashboard password, ingest token, and Vault master key
npx wrangler secret put DASHBOARD_PASSWORD
npx wrangler secret put INGEST_SECRET
npx wrangler secret put VAULT_MASTER_KEY

# 5. Deploy to your Cloudflare account
npx wrangler deploy
```

Once deployed, Cloudflare will output your unique live endpoint:
```text
https://flarelens.<your-subdomain>.workers.dev
```
*(You can also attach a custom domain in the Cloudflare dashboard, e.g. `https://control.yourdomain.com`)*.

> ⚠️ **Important:** This deployed URL is **your control plane endpoint**. You will provide this URL when configuring and running your FlareLens agents. Never use someone else's control plane URL.

---

### Step 2: Install FlareLens Agent on Your Nodes

Once your control plane is running, install `flarelens-agent` on your servers, VMs, or developer workstations.

#### Option A: Download Pre-Built Binaries from GitHub Releases (Recommended)

Standalone, statically compiled release binaries are hosted directly on **[GitHub Releases](https://github.com/antwig2/flarelensd/releases)**:

| OS | Architecture | Binary Asset | Format |
| :--- | :--- | :--- | :--- |
| **Linux** | x86_64 (`amd64`) | `flarelens-agent-linux-amd64` | `.tar.gz` |
| **Linux** | ARM64 (`arm64`) | `flarelens-agent-linux-arm64` | `.tar.gz` |
| **Windows** | x86_64 (`amd64`) | `flarelens-agent-windows-amd64.exe` | `.zip` |
| **macOS** | Apple Silicon (`arm64`) | `flarelens-agent-darwin-arm64` | `.tar.gz` |
| **macOS** | Intel (`amd64`) | `flarelens-agent-darwin-amd64` | `.tar.gz` |

```bash
# Example: Download latest Linux amd64 archive directly from GitHub
curl -fsSL https://github.com/antwig2/flarelensd/releases/latest/download/flarelens-agent_linux_amd64.tar.gz \
  | sudo tar -xz -C /usr/local/bin flarelens-agent
sudo chmod +x /usr/local/bin/flarelens-agent

# Run agent pointing to YOUR deployed Cloudflare Worker URL
flarelens-agent \
  --control-url "https://<your-worker-subdomain>.workers.dev" \
  --enroll-token "<YOUR_INGEST_SECRET>"
```

#### Option B: One-Line Installer (Served by Your Deployed Worker)

Your deployed worker serves ready-to-use bootstrap installers for your fleet:

**Linux:**
```bash
curl -fsSL https://<your-worker-subdomain>.workers.dev/install.sh | sudo bash -s -- \
  --control "https://<your-worker-subdomain>.workers.dev" \
  --token "<YOUR_INGEST_SECRET>"
```

**Windows (Run PowerShell as Administrator):**
```powershell
iwr -useb https://<your-worker-subdomain>.workers.dev/install.ps1 | iex
```

---

## ⚙️ Configuration Reference

Configuration is loaded dynamically with the following precedence:
1. **CLI Flags** (`--config`, `--node-id`, `--control-url`)
2. **Environment Variables** (`FLARELENS_NODE_ID`, `FLARELENS_CONTROL_URL`, `FLARELENS_ENROLL_TOKEN`)
3. **YAML Configuration** (`/etc/flarelens/agent.yaml` on Linux, `$ProgramData\FlareLens\agent.yaml` on Windows)

### Sample `/etc/flarelens/agent.yaml`

```yaml
identity:
  node_id: "node-fra-01"
  hostname: "app-prod-1"
  provider: "bare-metal"
  region: "fra1"
  tags: ["app", "prod"]

control_plane:
  # Point to YOUR Cloudflare Worker URL
  endpoint: "https://<your-worker-subdomain>.workers.dev"
  enroll_token: "${FLARELENS_ENROLL_TOKEN}"
  heartbeat_interval: 15s

mesh:
  enabled: true
  listen_port: 51820
  interface_name: "flarelens0"
  overlay_ip: "100.64.0.1"
  subnet: "100.64.0.0/10"

telemetry:
  log_level: "info"
  metrics_interval: 10s

database:
  mode: "host_native" # Or "container" for Docker PostgreSQL
  host: "127.0.0.1"
  port: 5432
  backup:
    enabled: true
    pre_deploy_snapshot: true
```

---

## 🛠️ CLI Usage

```bash
# Print agent version and build information
flarelens-agent --version

# Run daemon with explicit configuration file
flarelens-agent --config /etc/flarelens/agent.yaml

# Run in development mode with debug logging
flarelens-agent --dev --log-level debug

# Perform an Over-The-Air SHA-256 verified binary upgrade
sudo flarelens-agent self-update --control https://<your-worker-subdomain>.workers.dev

# Connect to YOUR deployed control plane and specify WireGuard mesh port
flarelens-agent --control-url https://<your-worker-subdomain>.workers.dev --mesh-port 51820
```

---

## 🏗️ Development & Building

### Prerequisites

- Go 1.23 or later
- Docker (optional, for Blue/Green container tests)

```bash
# Clone repository
git clone https://github.com/antwig2/flarelensd.git
cd flarelensd

# Run test suite
go test -v ./...

# Build binary locally
go build -ldflags="-s -w" -o bin/flarelens-agent ./cmd/agent

# Verify GoReleaser configuration
goreleaser check
```

---

## 📄 License

Licensed under the [Apache License, Version 2.0](LICENSE).  
Copyright &copy; 2026 FlareLens Authors.
