package mesh

import (
	"cmp"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const (
	DefaultMagicDNSSuffix        = ".mesh"
	DefaultMagicDNSPeerTTL       = uint32(60)
	DefaultMagicDNSServiceTTL    = uint32(5)
	MagicDNSHostsHeader          = "# --- FLARELENS MAGICDNS START ---"
	MagicDNSHostsFooter          = "# --- FLARELENS MAGICDNS END ---"
)

// MagicDNSConfig holds configuration for the in-memory MagicDNS responder
type MagicDNSConfig struct {
	ListenAddr    string        // e.g. "127.0.0.1:53" or "100.64.0.1:53" or "127.0.0.1:5353"
	UpstreamDNS   string        // default: "1.1.1.1:53"
	DomainSuffix  string        // default: ".mesh"
	InterfaceName string        // e.g. "flarelens0"
	QueryTimeout  time.Duration // default: 2s
	SyncHostsFile bool          // whether to write /etc/hosts entries for 0ms resolution
	PeerTTL       uint32        // default: 60s for node hostnames (<node>.mesh)
	ServiceTTL    uint32        // default: 5s for dynamic cross-server container services (<svc>.<env>.mesh)
}

// MagicDNSServer provides an in-memory, split-horizon UDP+TCP DNS server for mesh nodes and containers.
type MagicDNSServer struct {
	cfg            MagicDNSConfig
	logger         *slog.Logger
	mu             sync.RWMutex
	records        map[string]net.IP   // peer node domain (lowercase, no trailing dot) -> IP
	serviceRecords map[string][]net.IP // dynamic service domain (<svc>.<env>.mesh) -> healthy replica IPs
	hasEndpoints   bool
	conn           *net.UDPConn
	tcpLn          net.Listener
	upstream       string
	cancelFunc     context.CancelFunc
	rrCounter      atomic.Uint64
}

// NewMagicDNSServer initializes a new in-memory MagicDNS responder
func NewMagicDNSServer(cfg MagicDNSConfig, logger *slog.Logger) *MagicDNSServer {
	if logger == nil {
		logger = slog.Default()
	}
	cfg.UpstreamDNS = cmp.Or(cfg.UpstreamDNS, "1.1.1.1:53")
	cfg.DomainSuffix = cmp.Or(cfg.DomainSuffix, DefaultMagicDNSSuffix)
	if cfg.QueryTimeout <= 0 {
		cfg.QueryTimeout = 2 * time.Second
	}
	cfg.PeerTTL = cmp.Or(cfg.PeerTTL, DefaultMagicDNSPeerTTL)
	cfg.ServiceTTL = cmp.Or(cfg.ServiceTTL, DefaultMagicDNSServiceTTL)

	return &MagicDNSServer{
		cfg:            cfg,
		logger:         logger,
		records:        make(map[string]net.IP),
		serviceRecords: make(map[string][]net.IP),
		upstream:       cfg.UpstreamDNS,
	}
}

// UpdatePeers updates the in-memory DNS records from the current active mesh peer list
func (s *MagicDNSServer) UpdatePeers(peers []Peer, localIP string, localName string) {
	s.mu.Lock()
	newRecords := make(map[string]net.IP)

	// Add local node if provided
	if localIP != "" {
		if ip := net.ParseIP(localIP); ip != nil {
			if cleanLocal := cleanDNSName(localName); cleanLocal != "" {
				newRecords[cleanLocal+s.cfg.DomainSuffix] = ip
			}
		}
	}

	// Add all peers
	for _, p := range peers {
		overlay := cmp.Or(p.OverlayIP, p.TailscaleIP)
		if overlay == "" {
			continue
		}
		ip := net.ParseIP(overlay)
		if ip == nil {
			continue
		}

		name := cleanDNSName(p.Name)
		if name != "" {
			newRecords[name+s.cfg.DomainSuffix] = ip
		}

		idName := cleanDNSName(p.ID)
		if idName != "" && idName != name {
			newRecords[idName+s.cfg.DomainSuffix] = ip
		}
	}
	s.records = newRecords
	s.mu.Unlock()

	s.logger.Debug("Updated MagicDNS peer records", "count", len(newRecords))

	// Optionally sync /etc/hosts for zero-latency local resolution
	if s.cfg.SyncHostsFile && os.Geteuid() == 0 {
		s.syncHostsFile(newRecords)
	}
}

// UpdateServiceEndpoints refreshes dynamic cross-server container DNS records (TTL 5s)
// from control-plane cluster placement endpoints. Each healthy replica is exposed under
// <service>.<env>.mesh and <alias>.<env>.mesh (plus unambiguous <service>.mesh when only
// a single environment defines that name).
func (s *MagicDNSServer) UpdateServiceEndpoints(localOverlayIP string, endpoints []ClusterEndpoint) {
	suffix := s.cfg.DomainSuffix
	type envKey struct {
		env  string
		name string
	}

	grouped := make(map[envKey][]net.IP)
	nameEnvs := make(map[string]map[string]struct{})

	appendUniqueIP := func(key envKey, ip net.IP) {
		ipv4 := ip.To4()
		if ipv4 == nil {
			return
		}
		for _, existing := range grouped[key] {
			if existing.Equal(ipv4) {
				return
			}
		}
		grouped[key] = append(grouped[key], ipv4)
		if nameEnvs[key.name] == nil {
			nameEnvs[key.name] = make(map[string]struct{})
		}
		nameEnvs[key.name][key.env] = struct{}{}
	}

	_ = strings.TrimSpace(localOverlayIP) // reserved for future locality weighting

	for _, ep := range endpoints {
		if !ep.Healthy {
			continue
		}
		ip := net.ParseIP(strings.TrimSpace(ep.MeshIP))
		if ip == nil || ip.To4() == nil {
			continue
		}
		envName := cleanDNSName(normalizeMeshEnv(ep.Env))
		if envName == "" {
			envName = "uat"
		}

		names := expandServiceDNSNames(ep.Service, envName, ep.Aliases)
		for _, n := range names {
			appendUniqueIP(envKey{env: envName, name: n}, ip)
		}
	}

	s.mu.Lock()
	next := make(map[string][]net.IP, len(grouped)*2)
	for k, ips := range grouped {
		fqdn := fmt.Sprintf("%s.%s%s", k.name, k.env, suffix)
		next[fqdn] = ips

		// Expose <name>.mesh only when unambiguous across environments and not colliding with a peer node name.
		if len(nameEnvs[k.name]) == 1 {
			shortMesh := k.name + suffix
			if _, isPeer := s.records[shortMesh]; !isPeer {
				next[shortMesh] = ips
			}
		}
	}
	s.serviceRecords = next
	s.hasEndpoints = true
	s.mu.Unlock()

	s.logger.Debug("Updated MagicDNS dynamic service records", "records", len(next), "ttl_seconds", s.cfg.ServiceTTL)
}

// SeedFromExtraHosts populates initial <host>.<env>.mesh records from deploy-time host:ip pairs
// only if authoritative cluster_endpoints have not yet arrived for that FQDN.
func (s *MagicDNSServer) SeedFromExtraHosts(env string, extraHosts []string) {
	if len(extraHosts) == 0 {
		return
	}
	envName := cleanDNSName(normalizeMeshEnv(env))
	if envName == "" {
		envName = "uat"
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, entry := range extraHosts {
		hostRaw, ipRaw, ok := strings.Cut(strings.TrimSpace(entry), ":")
		if !ok {
			continue
		}
		ip := net.ParseIP(strings.TrimSpace(ipRaw))
		if ip == nil || ip.To4() == nil {
			continue
		}
		cleanHost := cleanDNSName(hostRaw)
		if cleanHost == "" {
			continue
		}
		fqdn := fmt.Sprintf("%s.%s%s", cleanHost, envName, s.cfg.DomainSuffix)
		if len(s.serviceRecords[fqdn]) == 0 {
			s.serviceRecords[fqdn] = []net.IP{ip.To4()}
		}
	}
}

// LookupAll queries the in-memory DNS tables and returns round-robin rotated IPv4 addresses plus record TTL.
func (s *MagicDNSServer) LookupAll(name string) ([]net.IP, uint32) {
	normalized := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))

	s.mu.RLock()
	svcIPs := s.serviceRecords[normalized]
	if len(svcIPs) > 0 {
		cloned := slices.Clone(svcIPs)
		ttl := s.cfg.ServiceTTL
		s.mu.RUnlock()

		if len(cloned) > 1 {
			offset := int((s.rrCounter.Add(1) - 1) % uint64(len(cloned)))
			if offset > 0 {
				rotated := make([]net.IP, len(cloned))
				for i := range len(cloned) {
					rotated[i] = cloned[(i+offset)%len(cloned)]
				}
				return rotated, ttl
			}
		}
		return cloned, ttl
	}

	peerIP := s.records[normalized]
	peerTTL := s.cfg.PeerTTL
	s.mu.RUnlock()

	if peerIP != nil {
		return []net.IP{peerIP}, peerTTL
	}
	return nil, 0
}

// Lookup queries the in-memory DNS table for a domain and returns the primary (or next round-robin) IP.
func (s *MagicDNSServer) Lookup(name string) net.IP {
	ips, _ := s.LookupAll(name)
	if len(ips) == 0 {
		return nil
	}
	return ips[0]
}

// ContainerDNSServer returns the bound non-loopback host IP when MagicDNS is actively listening
// on standard DNS port 53 (suitable for Docker HostConfig.Dns injection), or "" otherwise.
func (s *MagicDNSServer) ContainerDNSServer() string {
	s.mu.RLock()
	conn := s.conn
	s.mu.RUnlock()
	if conn == nil {
		return ""
	}
	host, port, err := net.SplitHostPort(conn.LocalAddr().String())
	if err != nil || port != "53" {
		return ""
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
		return ""
	}
	return ip.String()
}

// DNSHookForEnv returns Docker HostConfig.Dns and HostConfig.DnsSearch slices for containers in env
// when MagicDNS is actively bound on <overlay_ip>:53. Returns (nil, nil) when unavailable so callers
// automatically retain /etc/hosts ExtraHosts fallback.
func (s *MagicDNSServer) DNSHookForEnv(env string) ([]string, []string) {
	serverIP := s.ContainerDNSServer()
	if serverIP == "" {
		return nil, nil
	}
	envShort := cleanDNSName(normalizeMeshEnv(env))
	if envShort == "" {
		envShort = "uat"
	}
	baseDomain := strings.TrimPrefix(s.cfg.DomainSuffix, ".")
	if baseDomain == "" {
		baseDomain = "mesh"
	}
	// Include 1.1.1.1 as secondary fallback so external internet resolution stays uninterrupted
	// even during a ~250ms flarelensd OTA binary swap.
	servers := []string{serverIP, "1.1.1.1"}
	search := []string{fmt.Sprintf("%s.%s", envShort, baseDomain), baseDomain}
	return servers, search
}

// RebindOverlayIP binds (or rebinds) the UDP+TCP DNS listeners strictly onto <overlayIP>:53
// so local Docker containers and WireGuard peers can resolve *.mesh names without colliding with
// systemd-resolved (127.0.0.53:53) or exposing port 53 on public interfaces.
func (s *MagicDNSServer) RebindOverlayIP(ctx context.Context, overlayIP string) error {
	ip := net.ParseIP(strings.TrimSpace(overlayIP))
	if ip == nil {
		return fmt.Errorf("invalid overlay IP %q", overlayIP)
	}
	targetAddr := net.JoinHostPort(ip.String(), "53")

	s.mu.Lock()
	if s.conn != nil && s.conn.LocalAddr().String() == targetAddr {
		s.mu.Unlock()
		return nil
	}
	s.mu.Unlock()

	return s.bindAndServe(ctx, targetAddr, false)
}

// Start begins listening on the configured UDP (and matching TCP) socket
func (s *MagicDNSServer) Start(ctx context.Context) error {
	listenAddr := cmp.Or(s.cfg.ListenAddr, "127.0.0.1:53")
	return s.bindAndServe(ctx, listenAddr, true)
}

func (s *MagicDNSServer) bindAndServe(ctx context.Context, listenAddr string, allowHighPortFallback bool) error {
	udpAddr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return fmt.Errorf("failed to resolve magicdns listen address %s: %w", listenAddr, err)
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		if allowHighPortFallback && strings.HasSuffix(listenAddr, ":53") {
			fallbackAddr := "127.0.0.1:5353"
			s.logger.Warn("Port 53 busy, falling back MagicDNS listener", "from", listenAddr, "to", fallbackAddr)
			if fbUDP, fbErr := net.ResolveUDPAddr("udp", fallbackAddr); fbErr == nil {
				conn, err = net.ListenUDP("udp", fbUDP)
				if err == nil {
					listenAddr = fallbackAddr
				}
			}
		}
		if err != nil {
			return fmt.Errorf("failed to bind magicdns udp socket on %s: %w", listenAddr, err)
		}
	}

	boundAddr := conn.LocalAddr().String()
	tcpLn, tcpErr := net.Listen("tcp", boundAddr)
	if tcpErr != nil {
		s.logger.Debug("MagicDNS TCP listener optional bind skipped", "addr", boundAddr, "error", tcpErr)
	}

	s.mu.Lock()
	oldCancel := s.cancelFunc
	oldConn := s.conn
	oldTCP := s.tcpLn

	runCtx, cancel := context.WithCancel(ctx)
	s.cfg.ListenAddr = boundAddr
	s.conn = conn
	s.tcpLn = tcpLn
	s.cancelFunc = cancel
	s.mu.Unlock()

	if oldCancel != nil {
		oldCancel()
	}
	if oldConn != nil {
		_ = oldConn.Close()
	}
	if oldTCP != nil {
		_ = oldTCP.Close()
	}

	s.logger.Info("MagicDNS split-horizon responder started",
		"listen", boundAddr,
		"tcp", tcpLn != nil,
		"suffix", s.cfg.DomainSuffix,
		"service_ttl_s", s.cfg.ServiceTTL,
	)

	s.configureSystemdResolved(boundAddr)

	go s.serveUDPLoop(runCtx, conn)
	if tcpLn != nil {
		go s.serveTCPLoop(runCtx, tcpLn)
	}
	return nil
}

// LocalAddr returns the active UDP listener address, or "" if not started.
func (s *MagicDNSServer) LocalAddr() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.conn == nil {
		return ""
	}
	return s.conn.LocalAddr().String()
}

// Stop shuts down the DNS server and cleans up system integrations
func (s *MagicDNSServer) Stop() {
	s.mu.Lock()
	cancel := s.cancelFunc
	conn := s.conn
	tcpLn := s.tcpLn
	s.cancelFunc = nil
	s.conn = nil
	s.tcpLn = nil
	s.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if conn != nil {
		_ = conn.Close()
	}
	if tcpLn != nil {
		_ = tcpLn.Close()
	}
	if s.cfg.SyncHostsFile && os.Geteuid() == 0 {
		s.cleanHostsFile()
	}
	s.cleanSystemdResolved()
	s.logger.Info("MagicDNS responder stopped")
}

func (s *MagicDNSServer) serveUDPLoop(ctx context.Context, conn *net.UDPConn) {
	buf := make([]byte, 4096)
	for {
		n, remoteAddr, err := conn.ReadFrom(buf)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				continue
			}
		}

		reqBytes := slices.Clone(buf[:n])
		go s.handleUDPQuery(conn, reqBytes, remoteAddr)
	}
}

func (s *MagicDNSServer) serveTCPLoop(ctx context.Context, ln net.Listener) {
	for {
		clientConn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				continue
			}
		}
		go s.handleTCPConn(clientConn)
	}
}

func (s *MagicDNSServer) handleTCPConn(clientConn net.Conn) {
	defer clientConn.Close()
	_ = clientConn.SetDeadline(time.Now().Add(s.cfg.QueryTimeout * 2))

	for {
		var lenBuf [2]byte
		if _, err := io.ReadFull(clientConn, lenBuf[:]); err != nil {
			return
		}
		msgLen := int(binary.BigEndian.Uint16(lenBuf[:]))
		if msgLen == 0 || msgLen > 65535 {
			return
		}
		reqBytes := make([]byte, msgLen)
		if _, err := io.ReadFull(clientConn, reqBytes); err != nil {
			return
		}

		respBytes, forward := s.processDNSQuery(reqBytes)
		if forward {
			respBytes = s.exchangeUpstream(reqBytes, true)
		}
		if len(respBytes) == 0 {
			return
		}

		out := make([]byte, 2+len(respBytes))
		binary.BigEndian.PutUint16(out[:2], uint16(len(respBytes)))
		copy(out[2:], respBytes)
		if _, err := clientConn.Write(out); err != nil {
			return
		}
	}
}

func (s *MagicDNSServer) handleUDPQuery(conn *net.UDPConn, reqBytes []byte, remoteAddr net.Addr) {
	respBytes, forward := s.processDNSQuery(reqBytes)
	if forward {
		respBytes = s.exchangeUpstream(reqBytes, false)
	}
	if len(respBytes) > 0 {
		_, _ = conn.WriteTo(respBytes, remoteAddr)
	}
}

func (s *MagicDNSServer) processDNSQuery(reqBytes []byte) ([]byte, bool) {
	var msg dnsmessage.Message
	if err := msg.Unpack(reqBytes); err != nil {
		return nil, false
	}

	// Only process standard queries
	if msg.Header.Response || len(msg.Questions) == 0 {
		return nil, false
	}

	question := msg.Questions[0]
	qName := strings.ToLower(strings.TrimSuffix(question.Name.String(), "."))

	// Authoritatively handle:
	// 1. Any *.mesh query (prevents internal .mesh queries from ever leaking upstream).
	// 2. Bare single-label queries (!strings.Contains(qName, ".")): never exist in public root DNS;
	//    answering instant in-memory NXDOMAIN avoids a 30ms internet round-trip and lets container
	//    resolvers immediately query <name>.<env>.mesh from DnsSearch with strict env isolation.
	if strings.HasSuffix(qName, s.cfg.DomainSuffix) || !strings.Contains(qName, ".") || s.hasExactRecord(qName) {
		resp := s.buildMeshResponse(&msg, question, qName)
		packed, err := resp.Pack()
		if err != nil {
			return nil, false
		}
		return packed, false
	}

	return nil, true
}

func (s *MagicDNSServer) hasExactRecord(qName string) bool {
	s.mu.RLock()
	_, inSvc := s.serviceRecords[qName]
	_, inPeers := s.records[qName]
	s.mu.RUnlock()
	return inSvc || inPeers
}

func (s *MagicDNSServer) buildMeshResponse(req *dnsmessage.Message, q dnsmessage.Question, qName string) dnsmessage.Message {
	resp := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:                 req.ID,
			Response:           true,
			OpCode:             req.OpCode,
			Authoritative:      true,
			RecursionDesired:   req.RecursionDesired,
			RecursionAvailable: true,
			RCode:              dnsmessage.RCodeSuccess,
		},
		Questions: req.Questions,
	}

	ips, ttl := s.LookupAll(qName)
	if len(ips) == 0 {
		resp.Header.RCode = dnsmessage.RCodeNameError
		return resp
	}

	// Only answer TypeA (IPv4) queries or TypeALL; TypeAAAA returns RFC 4074 NODATA (RCodeSuccess, 0 answers)
	if q.Type == dnsmessage.TypeA || q.Type == dnsmessage.TypeALL {
		for _, ip := range ips {
			ipv4 := ip.To4()
			if ipv4 == nil {
				continue
			}
			var ipBytes [4]byte
			copy(ipBytes[:], ipv4)
			resp.Answers = append(resp.Answers, dnsmessage.Resource{
				Header: dnsmessage.ResourceHeader{
					Name:  q.Name,
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
					TTL:   ttl,
				},
				Body: &dnsmessage.AResource{A: ipBytes},
			})
		}
	}

	return resp
}

func (s *MagicDNSServer) exchangeUpstream(reqBytes []byte, preferTCP bool) []byte {
	if preferTCP {
		if resp := s.exchangeUpstreamTCP(reqBytes); len(resp) > 0 {
			return resp
		}
	}
	udpAddr, err := net.ResolveUDPAddr("udp", s.upstream)
	if err != nil {
		return nil
	}

	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return nil
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(s.cfg.QueryTimeout))
	if _, err := conn.Write(reqBytes); err != nil {
		return nil
	}

	respBuf := make([]byte, 4096)
	n, err := conn.Read(respBuf)
	if err != nil {
		return nil
	}
	return respBuf[:n]
}

func (s *MagicDNSServer) exchangeUpstreamTCP(reqBytes []byte) []byte {
	conn, err := net.DialTimeout("tcp", s.upstream, s.cfg.QueryTimeout)
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(s.cfg.QueryTimeout))

	out := make([]byte, 2+len(reqBytes))
	binary.BigEndian.PutUint16(out[:2], uint16(len(reqBytes)))
	copy(out[2:], reqBytes)
	if _, err := conn.Write(out); err != nil {
		return nil
	}

	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil
	}
	respLen := int(binary.BigEndian.Uint16(lenBuf[:]))
	if respLen == 0 || respLen > 65535 {
		return nil
	}
	respBuf := make([]byte, respLen)
	if _, err := io.ReadFull(conn, respBuf); err != nil {
		return nil
	}
	return respBuf
}

func expandServiceDNSNames(service, envName string, aliases []string) []string {
	var out []string
	add := func(raw string) {
		clean := cleanDNSName(raw)
		if clean != "" && !slices.Contains(out, clean) {
			out = append(out, clean)
		}
	}

	base := strings.ToLower(strings.TrimSpace(service))
	for _, suf := range []string{"-production", "-prod", "-uat", "-staging"} {
		if strings.HasSuffix(base, suf) && len(base) > len(suf) {
			base = strings.TrimSuffix(base, suf)
			break
		}
	}
	add(service)
	add(base)
	if base != "" && envName != "" {
		add(fmt.Sprintf("%s-%s", base, envName))
	}
	if base == "dragonfly" {
		add("redis")
		if envName != "" {
			add("redis-" + envName)
		}
	}
	for _, a := range aliases {
		add(a)
	}
	return out
}

// cleanDNSName normalizes hostnames for RFC 1035 labels
func cleanDNSName(raw string) string {
	lower := strings.ToLower(strings.TrimSpace(raw))
	var b strings.Builder
	for _, ch := range lower {
		if (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-' {
			b.WriteRune(ch)
		}
	}
	return strings.Trim(b.String(), "-")
}

// syncHostsFile dynamically updates /etc/hosts with current peer mappings for 0ms lookup
func (s *MagicDNSServer) syncHostsFile(records map[string]net.IP) {
	hostsPath := "/etc/hosts"
	content, err := os.ReadFile(hostsPath)
	if err != nil {
		return
	}

	original := string(content)
	cleanContent := original
	if startIdx := strings.Index(cleanContent, MagicDNSHostsHeader); startIdx != -1 {
		if endIdx := strings.Index(cleanContent, MagicDNSHostsFooter); endIdx != -1 {
			cleanContent = cleanContent[:startIdx] + strings.TrimSpace(cleanContent[endIdx+len(MagicDNSHostsFooter):])
		}
	}

	var b strings.Builder
	b.WriteString(strings.TrimRight(cleanContent, "\n") + "\n\n")
	b.WriteString(MagicDNSHostsHeader + "\n")
	b.WriteString("# Managed dynamically by FlareLens Sovereign Mesh (Do not edit manually)\n")

	ipToNames := make(map[string][]string)
	for name, ip := range records {
		ipStr := ip.String()
		ipToNames[ipStr] = append(ipToNames[ipStr], name)
	}

	for ipStr, names := range ipToNames {
		b.WriteString(fmt.Sprintf("%-16s %s\n", ipStr, strings.Join(names, " ")))
	}
	b.WriteString(MagicDNSHostsFooter + "\n")

	_ = os.WriteFile(hostsPath, []byte(b.String()), 0644)
}

// StripMagicDNSHostsBlock removes the managed FlareLens MagicDNS block from /etc/hosts content.
func StripMagicDNSHostsBlock(content string) (string, bool) {
	before, rest, hasStart := strings.Cut(content, MagicDNSHostsHeader)
	if !hasStart {
		return content, false
	}
	_, after, hasEnd := strings.Cut(rest, MagicDNSHostsFooter)
	if !hasEnd {
		return content, false
	}
	trimmedBefore := strings.TrimRight(before, " \t\r\n")
	trimmedAfter := strings.TrimSpace(after)
	if trimmedBefore == "" && trimmedAfter == "" {
		return "", true
	}
	if trimmedAfter == "" {
		return trimmedBefore + "\n", true
	}
	if trimmedBefore == "" {
		return trimmedAfter + "\n", true
	}
	return trimmedBefore + "\n\n" + trimmedAfter + "\n", true
}

// CleanHostDNS removes the managed FlareLens block from hostsPath and reverts systemd-resolved for ifaceName.
func CleanHostDNS(ctx context.Context, ifaceName string, hostsPath string, execFn func(ctx context.Context, cmd string, args ...string) ([]byte, error)) bool {
	hostsPath = cmp.Or(strings.TrimSpace(hostsPath), "/etc/hosts")
	modifiedHosts := false
	if content, err := os.ReadFile(hostsPath); err == nil {
		if cleaned, changed := StripMagicDNSHostsBlock(string(content)); changed {
			if writeErr := os.WriteFile(hostsPath, []byte(cleaned), 0644); writeErr == nil {
				modifiedHosts = true
			}
		}
	}

	if iface := strings.TrimSpace(ifaceName); iface != "" {
		if execFn != nil {
			_, _ = execFn(ctx, "resolvectl", "revert", iface)
		} else if _, err := exec.LookPath("resolvectl"); err == nil {
			_ = exec.CommandContext(ctx, "resolvectl", "revert", iface).Run()
		}
	}
	return modifiedHosts
}

// cleanHostsFile strips out the FlareLens block from /etc/hosts
func (s *MagicDNSServer) cleanHostsFile() {
	hostsPath := "/etc/hosts"
	content, err := os.ReadFile(hostsPath)
	if err != nil {
		return
	}
	if cleaned, changed := StripMagicDNSHostsBlock(string(content)); changed {
		_ = os.WriteFile(hostsPath, []byte(cleaned), 0644)
	}
}

func (s *MagicDNSServer) configureSystemdResolved(localAddr string) {
	if s.cfg.InterfaceName == "" {
		return
	}
	host, port, err := net.SplitHostPort(localAddr)
	if err != nil || port != "53" {
		return // resolvectl requires standard port 53 for per-link DNS
	}

	if _, err := exec.LookPath("resolvectl"); err != nil {
		return
	}

	_ = exec.Command("resolvectl", "dns", s.cfg.InterfaceName, host).Run()
	_ = exec.Command("resolvectl", "domain", s.cfg.InterfaceName, "~mesh").Run()
}

func (s *MagicDNSServer) cleanSystemdResolved() {
	if s.cfg.InterfaceName == "" {
		return
	}
	if _, err := exec.LookPath("resolvectl"); err != nil {
		return
	}
	_ = exec.Command("resolvectl", "revert", s.cfg.InterfaceName).Run()
}
