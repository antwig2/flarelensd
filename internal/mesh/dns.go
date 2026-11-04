package mesh

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const (
	DefaultMagicDNSSuffix = ".mesh"
	MagicDNSHostsHeader   = "# --- FLARELENS MAGICDNS START ---"
	MagicDNSHostsFooter   = "# --- FLARELENS MAGICDNS END ---"
)

// MagicDNSConfig holds configuration for the in-memory MagicDNS responder
type MagicDNSConfig struct {
	ListenAddr    string        // e.g. "127.0.0.1:53" or "100.64.0.1:53" or "127.0.0.1:5353"
	UpstreamDNS   string        // default: "1.1.1.1:53"
	DomainSuffix  string        // default: ".mesh"
	InterfaceName string        // e.g. "flarelens0"
	QueryTimeout  time.Duration // default: 2s
	SyncHostsFile bool          // whether to write /etc/hosts entries for 0ms resolution
}

// MagicDNSServer provides an in-memory, split-horizon DNS server for mesh nodes
type MagicDNSServer struct {
	cfg        MagicDNSConfig
	logger     *slog.Logger
	mu         sync.RWMutex
	records    map[string]net.IP // normalized domain (lowercase, no trailing dot) -> IP
	conn       *net.UDPConn
	upstream   string
	cancelFunc context.CancelFunc
}

// NewMagicDNSServer initializes a new in-memory MagicDNS responder
func NewMagicDNSServer(cfg MagicDNSConfig, logger *slog.Logger) *MagicDNSServer {
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.UpstreamDNS == "" {
		cfg.UpstreamDNS = "1.1.1.1:53"
	}
	if cfg.DomainSuffix == "" {
		cfg.DomainSuffix = DefaultMagicDNSSuffix
	}
	if cfg.QueryTimeout <= 0 {
		cfg.QueryTimeout = 2 * time.Second
	}

	return &MagicDNSServer{
		cfg:      cfg,
		logger:   logger,
		records:  make(map[string]net.IP),
		upstream: cfg.UpstreamDNS,
	}
}

// UpdatePeers updates the in-memory DNS records from the current active mesh peer list
func (s *MagicDNSServer) UpdatePeers(peers []Peer, localIP string, localName string) {
	s.mu.Lock()
	newRecords := make(map[string]net.IP)

	// Add local node if provided
	if localIP != "" {
		if ip := net.ParseIP(localIP); ip != nil {
			cleanLocal := cleanDNSName(localName)
			if cleanLocal != "" {
				newRecords[cleanLocal+s.cfg.DomainSuffix] = ip
			}
		}
	}

	// Add all peers
	for _, p := range peers {
		overlay := p.OverlayIP
		if overlay == "" {
			overlay = p.TailscaleIP
		}
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

	s.logger.Debug("Updated MagicDNS in-memory records", "count", len(newRecords))

	// Optionally sync /etc/hosts for zero-latency local resolution
	if s.cfg.SyncHostsFile && os.Geteuid() == 0 {
		s.syncHostsFile(newRecords)
	}
}

// Lookup queries the in-memory DNS table for a domain
func (s *MagicDNSServer) Lookup(name string) net.IP {
	s.mu.RLock()
	defer s.mu.RUnlock()

	normalized := strings.ToLower(strings.TrimSuffix(name, "."))
	return s.records[normalized]
}

// Start begins listening on the configured UDP socket
func (s *MagicDNSServer) Start(ctx context.Context) error {
	listenAddr := s.cfg.ListenAddr
	if listenAddr == "" {
		listenAddr = "127.0.0.1:53"
	}

	udpAddr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return fmt.Errorf("failed to resolve magicdns listen address %s: %w", listenAddr, err)
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		// Fallback to high port if port 53 is already taken
		if strings.HasSuffix(listenAddr, ":53") {
			fallbackAddr := "127.0.0.1:5353"
			s.logger.Warn("Port 53 busy, falling back MagicDNS listener", "from", listenAddr, "to", fallbackAddr)
			s.cfg.ListenAddr = fallbackAddr
			if fbUDP, fbErr := net.ResolveUDPAddr("udp", fallbackAddr); fbErr == nil {
				conn, err = net.ListenUDP("udp", fbUDP)
			}
		}
		if err != nil {
			return fmt.Errorf("failed to bind magicdns udp socket on %s: %w", s.cfg.ListenAddr, err)
		}
	}

	s.conn = conn
	ctx, cancel := context.WithCancel(ctx)
	s.cancelFunc = cancel

	s.logger.Info("MagicDNS split-horizon responder started", "listen", conn.LocalAddr().String(), "suffix", s.cfg.DomainSuffix)

	// Configure systemd-resolved split-domain if resolvectl is available
	s.configureSystemdResolved(conn.LocalAddr().String())

	go s.serveLoop(ctx)
	return nil
}

// Stop shuts down the DNS server and cleans up system integrations
func (s *MagicDNSServer) Stop() {
	if s.cancelFunc != nil {
		s.cancelFunc()
	}
	if s.conn != nil {
		_ = s.conn.Close()
	}
	if s.cfg.SyncHostsFile && os.Geteuid() == 0 {
		s.cleanHostsFile()
	}
	s.cleanSystemdResolved()
	s.logger.Info("MagicDNS responder stopped")
}

func (s *MagicDNSServer) serveLoop(ctx context.Context) {
	buf := make([]byte, 4096)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		n, remoteAddr, err := s.conn.ReadFrom(buf)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				continue
			}
		}

		reqBytes := make([]byte, n)
		copy(reqBytes, buf[:n])

		go s.handleQuery(reqBytes, remoteAddr)
	}
}

func (s *MagicDNSServer) handleQuery(reqBytes []byte, remoteAddr net.Addr) {
	var msg dnsmessage.Message
	if err := msg.Unpack(reqBytes); err != nil {
		return
	}

	// Only process standard queries
	if msg.Header.Response || len(msg.Questions) == 0 {
		return
	}

	question := msg.Questions[0]
	qName := strings.ToLower(strings.TrimSuffix(question.Name.String(), "."))

	// Check if this query belongs to our MagicDNS domain (e.g. ends with .mesh)
	if strings.HasSuffix(qName, s.cfg.DomainSuffix) {
		resp := s.buildMeshResponse(&msg, question, qName)
		packed, err := resp.Pack()
		if err == nil {
			_, _ = s.conn.WriteTo(packed, remoteAddr)
		}
		return
	}

	// Forward non-mesh queries upstream
	s.forwardUpstream(reqBytes, remoteAddr)
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

	ip := s.Lookup(qName)
	if ip == nil {
		// Domain not found in peer table -> NXDOMAIN
		resp.Header.RCode = dnsmessage.RCodeNameError
		return resp
	}

	// Only answer TypeA (IPv4) queries or TypeAll
	if q.Type == dnsmessage.TypeA || q.Type == dnsmessage.TypeALL {
		ipv4 := ip.To4()
		if ipv4 != nil {
			var ipBytes [4]byte
			copy(ipBytes[:], ipv4)
			resp.Answers = append(resp.Answers, dnsmessage.Resource{
				Header: dnsmessage.ResourceHeader{
					Name:  q.Name,
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
					TTL:   60,
				},
				Body: &dnsmessage.AResource{A: ipBytes},
			})
		}
	}

	return resp
}

func (s *MagicDNSServer) forwardUpstream(reqBytes []byte, remoteAddr net.Addr) {
	udpAddr, err := net.ResolveUDPAddr("udp", s.upstream)
	if err != nil {
		return
	}

	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(s.cfg.QueryTimeout))
	if _, err := conn.Write(reqBytes); err != nil {
		return
	}

	respBuf := make([]byte, 4096)
	n, err := conn.Read(respBuf)
	if err != nil {
		return
	}

	_, _ = s.conn.WriteTo(respBuf[:n], remoteAddr)
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

	// Map IP -> names
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

// cleanHostsFile strips out the FlareLens block from /etc/hosts
func (s *MagicDNSServer) cleanHostsFile() {
	hostsPath := "/etc/hosts"
	content, err := os.ReadFile(hostsPath)
	if err != nil {
		return
	}

	str := string(content)
	if startIdx := strings.Index(str, MagicDNSHostsHeader); startIdx != -1 {
		if endIdx := strings.Index(str, MagicDNSHostsFooter); endIdx != -1 {
			cleaned := str[:startIdx] + strings.TrimSpace(str[endIdx+len(MagicDNSHostsFooter):]) + "\n"
			_ = os.WriteFile(hostsPath, []byte(cleaned), 0644)
		}
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

	// Only apply if resolvectl binary exists
	if _, err := exec.LookPath("resolvectl"); err != nil {
		return
	}

	// Route ~mesh queries strictly to this interface
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
