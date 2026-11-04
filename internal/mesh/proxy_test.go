package mesh

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/proxy"
)

func TestProxySecurityEnforcement(t *testing.T) {
	// Attempting to bind to 0.0.0.0 must be rejected
	cfg := ProxyConfig{
		ListenAddr: "0.0.0.0:1055",
		AllowLAN:   false,
	}
	_, err := NewProxyServer(cfg, nil)
	if err == nil {
		t.Fatalf("Expected error when binding proxy to 0.0.0.0 without AllowLAN, got nil")
	}
	if !strings.Contains(err.Error(), "security violation") {
		t.Errorf("Expected security violation error, got: %v", err)
	}

	// Loopback address must be accepted
	cfgLoopback := ProxyConfig{
		ListenAddr: "127.0.0.1:0",
		AllowLAN:   false,
	}
	server, err := NewProxyServer(cfgLoopback, nil)
	if err != nil {
		t.Fatalf("Expected loopback proxy config to succeed, got: %v", err)
	}
	if server == nil {
		t.Fatalf("Expected non-nil server")
	}
}

func TestSOCKS5ProxyConnect(t *testing.T) {
	// 1. Start a mock echo backend server
	echoListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start echo listener: %v", err)
	}
	defer echoListener.Close()

	go func() {
		for {
			conn, err := echoListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()

	// 2. Start SOCKS5 proxy server
	proxyCfg := ProxyConfig{
		ListenAddr:  "127.0.0.1:0",
		DialTimeout: 2 * time.Second,
	}
	proxyServer, err := NewProxyServer(proxyCfg, nil)
	if err != nil {
		t.Fatalf("Failed to create proxy server: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := proxyServer.Start(ctx); err != nil {
		t.Fatalf("Failed to start proxy server: %v", err)
	}
	defer proxyServer.Stop()

	// 3. Connect to echo backend through the SOCKS5 proxy
	dialer, err := proxy.SOCKS5("tcp", proxyServer.Addr().String(), nil, proxy.Direct)
	if err != nil {
		t.Fatalf("Failed to create SOCKS5 dialer: %v", err)
	}

	conn, err := dialer.Dial("tcp", echoListener.Addr().String())
	if err != nil {
		t.Fatalf("Failed to dial echo backend via SOCKS5: %v", err)
	}
	defer conn.Close()

	// 4. Test payload echo
	testPayload := "Hello FlareLens SOCKS5 Mesh!\n"
	if _, err := conn.Write([]byte(testPayload)); err != nil {
		t.Fatalf("Failed to write to proxied conn: %v", err)
	}

	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read from proxied conn: %v", err)
	}

	if line != testPayload {
		t.Errorf("Expected %q, got %q", testPayload, line)
	}
}

func TestSOCKS5MagicDNSResolution(t *testing.T) {
	// 1. Mock backend
	echoListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start echo listener: %v", err)
	}
	defer echoListener.Close()

	_, echoPort, _ := net.SplitHostPort(echoListener.Addr().String())

	go func() {
		for {
			conn, err := echoListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = c.Write([]byte("PONG\n"))
			}(conn)
		}
	}()

	// 2. Setup MagicDNS with a custom .mesh record pointing to 127.0.0.1
	dnsServer := NewMagicDNSServer(MagicDNSConfig{DomainSuffix: ".mesh"}, nil)
	dnsServer.UpdatePeers([]Peer{
		{
			ID:        "node-test",
			Name:      "node-test",
			OverlayIP: "127.0.0.1",
		},
	}, "", "")

	// 3. Start SOCKS5 proxy with MagicDNS attached
	proxyCfg := ProxyConfig{
		ListenAddr:  "127.0.0.1:0",
		DNSResolver: dnsServer,
	}
	proxyServer, err := NewProxyServer(proxyCfg, nil)
	if err != nil {
		t.Fatalf("Failed to create proxy server: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := proxyServer.Start(ctx); err != nil {
		t.Fatalf("Failed to start proxy server: %v", err)
	}
	defer proxyServer.Stop()

	// 4. Dial node-test.mesh via SOCKS5
	dialer, err := proxy.SOCKS5("tcp", proxyServer.Addr().String(), nil, proxy.Direct)
	if err != nil {
		t.Fatalf("Failed to create SOCKS5 dialer: %v", err)
	}

	conn, err := dialer.Dial("tcp", fmt.Sprintf("node-test.mesh:%s", echoPort))
	if err != nil {
		t.Fatalf("Failed to dial node-test.mesh via SOCKS5: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	resp, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read from conn: %v", err)
	}

	if resp != "PONG\n" {
		t.Errorf("Expected PONG, got %s", resp)
	}
}

func TestHTTPConnectProxy(t *testing.T) {
	// 1. Mock HTTP server
	httpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer httpListener.Close()

	go func() {
		for {
			conn, err := httpListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHELLO")
			}(conn)
		}
	}()

	// 2. Start Proxy
	proxyServer, err := NewProxyServer(ProxyConfig{ListenAddr: "127.0.0.1:0"}, nil)
	if err != nil {
		t.Fatalf("Failed to create proxy: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := proxyServer.Start(ctx); err != nil {
		t.Fatalf("Failed to start proxy: %v", err)
	}
	defer proxyServer.Stop()

	// 3. Send HTTP CONNECT request through the proxy
	proxyURL, _ := url.Parse("http://" + proxyServer.Addr().String())
	httpClient := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: 2 * time.Second,
	}

	resp, err := httpClient.Get("http://" + httpListener.Addr().String() + "/")
	if err != nil {
		t.Fatalf("HTTP request via proxy failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	if string(body) != "HELLO" {
		t.Errorf("Expected HELLO, got %s", string(body))
	}
}
