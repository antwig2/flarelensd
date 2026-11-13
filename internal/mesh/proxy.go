package mesh

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	socks5Version          = 0x05
	socks5AuthNone         = 0x00
	socks5AuthUserPass     = 0x02
	socks5AuthNoAcceptable = 0xFF

	socks5CmdConnect = 0x01

	socks5AtypIPv4   = 0x01
	socks5AtypDomain = 0x03
	socks5AtypIPv6   = 0x04

	socks5RepSuccess        = 0x00
	socks5RepGeneralFailure = 0x01
	socks5RepHostUnreach    = 0x04
	socks5RepConnRefused    = 0x05
)

// ProxyConfig defines settings for the in-memory zero-root SOCKS5 & HTTP CONNECT proxy
type ProxyConfig struct {
	ListenAddr  string          // e.g. "127.0.0.1:1055"
	Username    string          // optional username for authentication
	Password    string          // optional password for authentication
	DialTimeout time.Duration   // default: 5s
	AllowLAN    bool            // if true, allows binding to non-loopback addresses
	DNSResolver *MagicDNSServer // optional resolver for .mesh domains
}

// ProxyServer runs an unprivileged SOCKS5 and HTTP CONNECT proxy server
type ProxyServer struct {
	cfg        ProxyConfig
	logger     *slog.Logger
	listener   net.Listener
	mu         sync.Mutex
	cancelFunc context.CancelFunc
}

// NewProxyServer creates a new instance of the zero-root proxy server
func NewProxyServer(cfg ProxyConfig, logger *slog.Logger) (*ProxyServer, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = "127.0.0.1:1055"
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = 5 * time.Second
	}

	// Security Assertion: Enforce loopback binding unless explicitly overridden
	if !cfg.AllowLAN {
		host, _, err := net.SplitHostPort(cfg.ListenAddr)
		if err == nil {
			if host == "0.0.0.0" || host == "" || host == "::" {
				return nil, fmt.Errorf("security violation: refusing to bind zero-root proxy to %q (LAN jumpbox vulnerability); must bind to 127.0.0.1 or localhost", cfg.ListenAddr)
			}
			ip := net.ParseIP(host)
			if ip != nil && !ip.IsLoopback() {
				return nil, fmt.Errorf("security violation: binding to non-loopback address %q requires explicit AllowLAN=true", host)
			}
		}
	}

	return &ProxyServer{
		cfg:    cfg,
		logger: logger,
	}, nil
}

// Start begins listening on the configured TCP port
func (s *ProxyServer) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	l, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to bind proxy listener on %s: %w", s.cfg.ListenAddr, err)
	}
	s.listener = l

	ctx, cancel := context.WithCancel(ctx)
	s.cancelFunc = cancel

	authMode := "anonymous"
	if s.cfg.Username != "" {
		authMode = "username/password"
	}
	s.logger.Info("Zero-root SOCKS5 & HTTP proxy started", "listen", l.Addr().String(), "auth", authMode)

	go s.acceptLoop(ctx)
	return nil
}

// Addr returns the real listening address
func (s *ProxyServer) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener != nil {
		return s.listener.Addr()
	}
	return nil
}

// Stop shuts down the proxy listener and terminates active connections
func (s *ProxyServer) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancelFunc != nil {
		s.cancelFunc()
	}
	if s.listener != nil {
		_ = s.listener.Close()
	}
	s.logger.Info("Zero-root proxy stopped")
}

func (s *ProxyServer) acceptLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				continue
			}
		}

		go s.handleConnection(conn)
	}
}

func (s *ProxyServer) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	reader := bufio.NewReader(clientConn)

	// Peek first byte to determine protocol: 0x05 = SOCKS5, 'C'/'G'/'P' = HTTP
	firstByte, err := reader.Peek(1)
	if err != nil {
		return
	}

	if firstByte[0] == socks5Version {
		s.handleSOCKS5(reader, clientConn)
	} else if firstByte[0] == 'C' || firstByte[0] == 'G' || firstByte[0] == 'P' || firstByte[0] == 'H' {
		s.handleHTTP(reader, clientConn)
	} else {
		s.logger.Debug("Unsupported protocol on proxy port", "first_byte", firstByte[0])
	}
}

// ==============================================================================
// SOCKS5 Protocol Handler (RFC 1928)
// ==============================================================================

func (s *ProxyServer) handleSOCKS5(reader *bufio.Reader, clientConn net.Conn) {
	// 1. Version identifier / method selection message
	ver, err := reader.ReadByte()
	if err != nil || ver != socks5Version {
		return
	}

	nMethods, err := reader.ReadByte()
	if err != nil || nMethods == 0 {
		return
	}

	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(reader, methods); err != nil {
		return
	}

	// 2. Authenticate
	useAuth := s.cfg.Username != ""
	selectedMethod := byte(socks5AuthNoAcceptable)

	for _, m := range methods {
		if !useAuth && m == socks5AuthNone {
			selectedMethod = socks5AuthNone
			break
		}
		if useAuth && m == socks5AuthUserPass {
			selectedMethod = socks5AuthUserPass
			break
		}
	}

	if _, err := clientConn.Write([]byte{socks5Version, selectedMethod}); err != nil {
		return
	}
	if selectedMethod == socks5AuthNoAcceptable {
		return
	}

	// Perform username/password auth if required (RFC 1929)
	if selectedMethod == socks5AuthUserPass {
		if !s.authenticateSOCKS5UserPass(reader, clientConn) {
			return
		}
	}

	// 3. Client connection request
	reqHeader := make([]byte, 4)
	if _, err := io.ReadFull(reader, reqHeader); err != nil {
		return
	}

	if reqHeader[0] != socks5Version || reqHeader[1] != socks5CmdConnect {
		// Only CONNECT command supported
		_ = sendSOCKS5Reply(clientConn, socks5RepGeneralFailure, nil, 0)
		return
	}

	atyp := reqHeader[3]
	var targetHost string

	switch atyp {
	case socks5AtypIPv4:
		ipv4 := make([]byte, 4)
		if _, err := io.ReadFull(reader, ipv4); err != nil {
			return
		}
		targetHost = net.IP(ipv4).String()

	case socks5AtypDomain:
		domainLen, err := reader.ReadByte()
		if err != nil {
			return
		}
		domainBytes := make([]byte, domainLen)
		if _, err := io.ReadFull(reader, domainBytes); err != nil {
			return
		}
		targetHost = string(domainBytes)

	case socks5AtypIPv6:
		ipv6 := make([]byte, 16)
		if _, err := io.ReadFull(reader, ipv6); err != nil {
			return
		}
		targetHost = net.IP(ipv6).String()

	default:
		_ = sendSOCKS5Reply(clientConn, socks5RepGeneralFailure, nil, 0)
		return
	}

	var portBytes [2]byte
	if _, err := io.ReadFull(reader, portBytes[:]); err != nil {
		return
	}
	targetPort := binary.BigEndian.Uint16(portBytes[:])

	// 4. Resolve domain name (with MagicDNS resolution for *.mesh)
	resolvedHost := s.resolveTargetHost(targetHost)
	targetAddr := net.JoinHostPort(resolvedHost, strconv.Itoa(int(targetPort)))

	// 5. Dial target
	targetConn, err := net.DialTimeout("tcp", targetAddr, s.cfg.DialTimeout)
	if err != nil {
		s.logger.Debug("SOCKS5 dial target failed", "target", targetAddr, "error", err)
		rep := byte(socks5RepHostUnreach)
		if errors.Is(err, context.DeadlineExceeded) {
			rep = socks5RepHostUnreach
		}
		_ = sendSOCKS5Reply(clientConn, rep, nil, 0)
		return
	}
	defer targetConn.Close()

	// 6. Send success response
	localAddr := targetConn.LocalAddr().(*net.TCPAddr)
	if err := sendSOCKS5Reply(clientConn, socks5RepSuccess, localAddr.IP, uint16(localAddr.Port)); err != nil {
		return
	}

	// 7. Relay data bidirectionally
	s.relay(clientConn, reader, targetConn)
}

func (s *ProxyServer) authenticateSOCKS5UserPass(reader *bufio.Reader, clientConn net.Conn) bool {
	ver, err := reader.ReadByte()
	if err != nil || ver != 0x01 {
		return false
	}

	uLen, err := reader.ReadByte()
	if err != nil {
		return false
	}
	userBytes := make([]byte, uLen)
	if _, err := io.ReadFull(reader, userBytes); err != nil {
		return false
	}

	pLen, err := reader.ReadByte()
	if err != nil {
		return false
	}
	passBytes := make([]byte, pLen)
	if _, err := io.ReadFull(reader, passBytes); err != nil {
		return false
	}

	success := string(userBytes) == s.cfg.Username && string(passBytes) == s.cfg.Password
	status := byte(0x00)
	if !success {
		status = 0x01
	}

	_, _ = clientConn.Write([]byte{0x01, status})
	return success
}

func sendSOCKS5Reply(w io.Writer, rep byte, bindIP net.IP, bindPort uint16) error {
	reply := []byte{socks5Version, rep, 0x00, socks5AtypIPv4, 0, 0, 0, 0, 0, 0}
	if bindIP != nil {
		if ipv4 := bindIP.To4(); ipv4 != nil {
			copy(reply[4:8], ipv4)
			binary.BigEndian.PutUint16(reply[8:10], bindPort)
		}
	}
	_, err := w.Write(reply)
	return err
}

// ==============================================================================
// HTTP CONNECT Protocol Handler (RFC 7231)
// ==============================================================================

func (s *ProxyServer) handleHTTP(reader *bufio.Reader, clientConn net.Conn) {
	req, err := http.ReadRequest(reader)
	if err != nil {
		return
	}

	if req.Method != http.MethodConnect {
		// Standard forward HTTP proxy request (e.g. GET http://host:port/path)
		targetHost := req.URL.Hostname()
		targetPort := req.URL.Port()
		if targetPort == "" {
			targetPort = "80"
		}
		resolvedHost := s.resolveTargetHost(targetHost)
		targetAddr := net.JoinHostPort(resolvedHost, targetPort)
		targetConn, err := net.DialTimeout("tcp", targetAddr, s.cfg.DialTimeout)
		if err != nil {
			s.logger.Debug("HTTP forward proxy dial failed", "target", targetAddr, "error", err)
			_, _ = clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"))
			return
		}
		defer targetConn.Close()

		// Strip proxy-specific headers and write request to target
		req.RequestURI = ""
		if err := req.Write(targetConn); err != nil {
			return
		}

		// Stream response back to client
		_, _ = io.Copy(clientConn, targetConn)
		return
	}

	// Parse host:port
	targetHost, targetPortStr, err := net.SplitHostPort(req.RequestURI)
	if err != nil {
		targetHost = req.RequestURI
		targetPortStr = "443"
	}

	resolvedHost := s.resolveTargetHost(targetHost)
	targetAddr := net.JoinHostPort(resolvedHost, targetPortStr)

	targetConn, err := net.DialTimeout("tcp", targetAddr, s.cfg.DialTimeout)
	if err != nil {
		s.logger.Debug("HTTP CONNECT dial failed", "target", targetAddr, "error", err)
		_, _ = clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer targetConn.Close()

	// 200 Connection Established
	_, err = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		return
	}

	s.relay(clientConn, reader, targetConn)
}

// resolveTargetHost resolves .mesh domains via local MagicDNS if available
func (s *ProxyServer) resolveTargetHost(raw string) string {
	lower := strings.ToLower(raw)
	if strings.HasSuffix(lower, ".mesh") {
		if s.cfg.DNSResolver != nil {
			if ip := s.cfg.DNSResolver.Lookup(lower); ip != nil {
				return ip.String()
			}
		}
	}
	return raw
}

// relay bidirectionally pipes data between client and target
func (s *ProxyServer) relay(clientConn net.Conn, clientReader *bufio.Reader, targetConn net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	// Client -> Target
	go func() {
		defer wg.Done()
		if clientReader.Buffered() > 0 {
			bufferedBytes := clientReader.Buffered()
			buf, _ := clientReader.Peek(bufferedBytes)
			_, _ = targetConn.Write(buf)
			_, _ = clientReader.Discard(bufferedBytes)
		}
		_, _ = io.Copy(targetConn, clientConn)
		if tcpConn, ok := targetConn.(*net.TCPConn); ok {
			_ = tcpConn.CloseWrite()
		}
	}()

	// Target -> Client
	go func() {
		defer wg.Done()
		_, _ = io.Copy(clientConn, targetConn)
		if tcpConn, ok := clientConn.(*net.TCPConn); ok {
			_ = tcpConn.CloseWrite()
		}
	}()

	wg.Wait()
}
