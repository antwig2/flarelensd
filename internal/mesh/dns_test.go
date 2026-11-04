package mesh

import (
	"context"
	"net"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestMagicDNSRecords(t *testing.T) {
	cfg := MagicDNSConfig{
		DomainSuffix: ".mesh",
	}
	server := NewMagicDNSServer(cfg, nil)

	peers := []Peer{
		{
			ID:        "node-1",
			Name:      "node-1",
			OverlayIP: "100.64.0.1",
		},
		{
			ID:        "node-2",
			Name:      "node-2",
			OverlayIP: "100.64.0.2",
		},
		{
			ID:          "client-abc",
			Name:        "laptop-john",
			TailscaleIP: "100.64.0.105",
		},
	}

	server.UpdatePeers(peers, "100.64.0.100", "my-laptop")

	tests := []struct {
		query    string
		expected string
	}{
		{"node-1.mesh", "100.64.0.1"},
		{"node-1.mesh.", "100.64.0.1"},
		{"NODE-1.MESH", "100.64.0.1"},
		{"node-2.mesh", "100.64.0.2"},
		{"laptop-john.mesh", "100.64.0.105"},
		{"my-laptop.mesh", "100.64.0.100"},
		{"unknown.mesh", ""},
		{"google.com", ""},
	}

	for _, tt := range tests {
		ip := server.Lookup(tt.query)
		if tt.expected == "" {
			if ip != nil {
				t.Errorf("Lookup(%q) = %v; want nil", tt.query, ip)
			}
		} else {
			if ip == nil || ip.String() != tt.expected {
				t.Errorf("Lookup(%q) = %v; want %s", tt.query, ip, tt.expected)
			}
		}
	}
}

func TestMagicDNSUDPQuery(t *testing.T) {
	cfg := MagicDNSConfig{
		ListenAddr:   "127.0.0.1:0", // OS allocates random free port
		DomainSuffix: ".mesh",
		QueryTimeout: 500 * time.Millisecond,
	}
	server := NewMagicDNSServer(cfg, nil)

	server.UpdatePeers([]Peer{
		{
			ID:        "srv-alpha",
			Name:      "alpha",
			OverlayIP: "100.64.0.10",
		},
	}, "", "")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := server.Start(ctx); err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer server.Stop()

	// Wait briefly for server to bind
	time.Sleep(50 * time.Millisecond)

	// Send DNS query over UDP
	conn, err := net.Dial("udp", server.conn.LocalAddr().String())
	if err != nil {
		t.Fatalf("Failed to connect to magicdns server: %v", err)
	}
	defer conn.Close()

	// Build DNS query for alpha.mesh
	queryName, _ := dnsmessage.NewName("alpha.mesh.")
	req := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:               1234,
			RecursionDesired: true,
		},
		Questions: []dnsmessage.Question{
			{
				Name:  queryName,
				Type:  dnsmessage.TypeA,
				Class: dnsmessage.ClassINET,
			},
		},
	}

	packedReq, err := req.Pack()
	if err != nil {
		t.Fatalf("Failed to pack query: %v", err)
	}

	if _, err := conn.Write(packedReq); err != nil {
		t.Fatalf("Failed to send query: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	respBuf := make([]byte, 1024)
	n, err := conn.Read(respBuf)
	if err != nil {
		t.Fatalf("Failed to read DNS response: %v", err)
	}

	var resp dnsmessage.Message
	if err := resp.Unpack(respBuf[:n]); err != nil {
		t.Fatalf("Failed to unpack DNS response: %v", err)
	}

	if resp.Header.RCode != dnsmessage.RCodeSuccess {
		t.Fatalf("Expected RCodeSuccess, got: %v", resp.Header.RCode)
	}

	if len(resp.Answers) == 0 {
		t.Fatalf("Expected at least 1 answer, got 0")
	}

	ans := resp.Answers[0]
	aRecord, ok := ans.Body.(*dnsmessage.AResource)
	if !ok {
		t.Fatalf("Expected *dnsmessage.AResource, got %T", ans.Body)
	}

	respIP := net.IP(aRecord.A[:]).String()
	if respIP != "100.64.0.10" {
		t.Errorf("Expected answer IP 100.64.0.10, got %s", respIP)
	}
}
