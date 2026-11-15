package mesh

import (
	"context"
	"encoding/binary"
	"io"
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

	time.Sleep(50 * time.Millisecond)

	conn, err := net.Dial("udp", server.conn.LocalAddr().String())
	if err != nil {
		t.Fatalf("Failed to connect to magicdns server: %v", err)
	}
	defer conn.Close()

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
	if ans.Header.TTL != DefaultMagicDNSPeerTTL {
		t.Errorf("Expected peer TTL %d, got %d", DefaultMagicDNSPeerTTL, ans.Header.TTL)
	}
	aRecord, ok := ans.Body.(*dnsmessage.AResource)
	if !ok {
		t.Fatalf("Expected *dnsmessage.AResource, got %T", ans.Body)
	}

	respIP := net.IP(aRecord.A[:]).String()
	if respIP != "100.64.0.10" {
		t.Errorf("Expected answer IP 100.64.0.10, got %s", respIP)
	}
}

func TestMagicDNSServiceEndpointsTTL5RoundRobinAndFailover(t *testing.T) {
	server := NewMagicDNSServer(MagicDNSConfig{
		ListenAddr:   "127.0.0.1:0",
		DomainSuffix: ".mesh",
		UpstreamDNS:  "127.0.0.1:1", // unreachable upstream proves zero leak on single-label/.mesh queries
		QueryTimeout: 200 * time.Millisecond,
	}, nil)

	server.UpdatePeers([]Peer{
		{ID: "node-1", Name: "node-1", OverlayIP: "100.64.0.1"},
		{ID: "node-2", Name: "node-2", OverlayIP: "100.64.0.2"},
		{ID: "node-3", Name: "node-3", OverlayIP: "100.64.0.3"},
	}, "100.64.0.1", "node-1")

	server.UpdateServiceEndpoints("100.64.0.1", []ClusterEndpoint{
		{
			Env:     "uat",
			Service: "workflow-engine",
			Aliases: []string{"workflow", "workflow-uat"},
			NodeID:  "node-2",
			MeshIP:  "100.64.0.2",
			Healthy: true,
		},
		{
			Env:     "uat",
			Service: "workflow-engine",
			Aliases: []string{"workflow", "workflow-uat"},
			NodeID:  "node-3",
			MeshIP:  "100.64.0.3",
			Healthy: true,
		},
		{
			Env:     "uat",
			Service: "workflow-engine",
			NodeID:  "node-dead",
			MeshIP:  "100.64.0.99",
			Healthy: false, // unhealthy replica must never be served
		},
		{
			Env:     "production",
			Service: "workflow-engine",
			Aliases: []string{"workflow"},
			NodeID:  "node-prod",
			MeshIP:  "100.64.0.20",
			Healthy: true,
		},
		{
			Env:     "uat",
			Service: "dragonfly",
			NodeID:  "node-2",
			MeshIP:  "100.64.0.2",
			Healthy: true,
		},
	})

	if err := server.Start(t.Context()); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer server.Stop()

	addr := server.LocalAddr()

	// 1. Multi-replica UDP query returns TTL=5 and rotates primary A record across healthy nodes
	resp1 := sendTestDNSQueryUDP(t, addr, "workflow.uat.mesh.", dnsmessage.TypeA)
	if resp1.Header.RCode != dnsmessage.RCodeSuccess || len(resp1.Answers) != 2 {
		t.Fatalf("want 2 A answers for workflow.uat.mesh, got rcode=%v answers=%d", resp1.Header.RCode, len(resp1.Answers))
	}
	if resp1.Answers[0].Header.TTL != 5 {
		t.Fatalf("want dynamic service TTL=5, got %d", resp1.Answers[0].Header.TTL)
	}
	firstA1 := aRecordString(t, resp1.Answers[0])
	firstA2 := aRecordString(t, resp1.Answers[1])
	if firstA1 != "100.64.0.2" || firstA2 != "100.64.0.3" {
		t.Fatalf("unexpected query #1 order: [%s, %s]", firstA1, firstA2)
	}

	resp2 := sendTestDNSQueryTCP(t, addr, "workflow.uat.mesh.", dnsmessage.TypeA)
	if resp2.Header.RCode != dnsmessage.RCodeSuccess || len(resp2.Answers) != 2 {
		t.Fatalf("want 2 TCP A answers for workflow.uat.mesh, got rcode=%v answers=%d", resp2.Header.RCode, len(resp2.Answers))
	}
	secondA1 := aRecordString(t, resp2.Answers[0])
	secondA2 := aRecordString(t, resp2.Answers[1])
	if secondA1 != "100.64.0.3" || secondA2 != "100.64.0.2" {
		t.Fatalf("expected round-robin rotation [100.64.0.3, 100.64.0.2], got [%s, %s]", secondA1, secondA2)
	}

	// 2. Strict environment isolation: prod resolves to 100.64.0.20, and ambiguous workflow.mesh is NOT created
	prodResp := sendTestDNSQueryUDP(t, addr, "workflow.prod.mesh.", dnsmessage.TypeA)
	if len(prodResp.Answers) != 1 || aRecordString(t, prodResp.Answers[0]) != "100.64.0.20" {
		t.Fatalf("expected workflow.prod.mesh -> 100.64.0.20, got %+v", prodResp.Answers)
	}
	ambiguousResp := sendTestDNSQueryUDP(t, addr, "workflow.mesh.", dnsmessage.TypeA)
	if ambiguousResp.Header.RCode != dnsmessage.RCodeNameError {
		t.Fatalf("expected NXDOMAIN for multi-env ambiguous workflow.mesh, got %v", ambiguousResp.Header.RCode)
	}

	// 3. Unambiguous single-env service (dragonfly -> redis) resolves both redis.uat.mesh and redis.mesh
	redisResp := sendTestDNSQueryUDP(t, addr, "redis.uat.mesh.", dnsmessage.TypeA)
	if len(redisResp.Answers) != 1 || aRecordString(t, redisResp.Answers[0]) != "100.64.0.2" {
		t.Fatalf("expected redis.uat.mesh -> 100.64.0.2, got %+v", redisResp.Answers)
	}
	redisShort := sendTestDNSQueryUDP(t, addr, "redis.mesh.", dnsmessage.TypeA)
	if len(redisShort.Answers) != 1 || aRecordString(t, redisShort.Answers[0]) != "100.64.0.2" {
		t.Fatalf("expected unambiguous redis.mesh -> 100.64.0.2, got %+v", redisShort.Answers)
	}

	// 4. Bare single-label query ("workflow.") returns immediate NXDOMAIN without leaking to unreachable upstream
	bareResp := sendTestDNSQueryUDP(t, addr, "workflow.", dnsmessage.TypeA)
	if bareResp.Header.RCode != dnsmessage.RCodeNameError {
		t.Fatalf("expected fast NXDOMAIN for bare single-label query, got %v", bareResp.Header.RCode)
	}

	// 5. TypeAAAA for existing IPv4 service returns RFC 4074 NODATA (RCodeSuccess, 0 answers) so musl/glibc succeed
	aaaaResp := sendTestDNSQueryUDP(t, addr, "workflow.uat.mesh.", dnsmessage.TypeAAAA)
	if aaaaResp.Header.RCode != dnsmessage.RCodeSuccess || len(aaaaResp.Answers) != 0 {
		t.Fatalf("expected RFC 4074 NODATA for TypeAAAA, got rcode=%v answers=%d", aaaaResp.Header.RCode, len(aaaaResp.Answers))
	}

	// 6. Live zero-restart failover: node-2 & node-3 go down, replacement spins up on node-4 (100.64.0.4)
	server.UpdateServiceEndpoints("100.64.0.1", []ClusterEndpoint{
		{
			Env:     "uat",
			Service: "workflow-engine",
			Aliases: []string{"workflow"},
			NodeID:  "node-4",
			MeshIP:  "100.64.0.4",
			Healthy: true,
		},
	})
	failoverResp := sendTestDNSQueryTCP(t, addr, "workflow.uat.mesh.", dnsmessage.TypeA)
	if len(failoverResp.Answers) != 1 || aRecordString(t, failoverResp.Answers[0]) != "100.64.0.4" {
		t.Fatalf("expected live failover to 100.64.0.4 without restart, got %+v", failoverResp.Answers)
	}
}

func sendTestDNSQueryUDP(t *testing.T, addr, qname string, qtype dnsmessage.Type) dnsmessage.Message {
	t.Helper()
	conn, err := net.DialTimeout("udp", addr, time.Second)
	if err != nil {
		t.Fatalf("udp dial: %v", err)
	}
	defer conn.Close()

	packed := packTestDNSQuery(t, qname, qtype)
	if _, err := conn.Write(packed); err != nil {
		t.Fatalf("udp write: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("udp read: %v", err)
	}
	var resp dnsmessage.Message
	if err := resp.Unpack(buf[:n]); err != nil {
		t.Fatalf("udp unpack: %v", err)
	}
	return resp
}

func sendTestDNSQueryTCP(t *testing.T, addr, qname string, qtype dnsmessage.Type) dnsmessage.Message {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("tcp dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))

	packed := packTestDNSQuery(t, qname, qtype)
	frame := make([]byte, 2+len(packed))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(packed)))
	copy(frame[2:], packed)
	if _, err := conn.Write(frame); err != nil {
		t.Fatalf("tcp write: %v", err)
	}

	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		t.Fatalf("tcp read len: %v", err)
	}
	respBuf := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
	if _, err := io.ReadFull(conn, respBuf); err != nil {
		t.Fatalf("tcp read body: %v", err)
	}
	var resp dnsmessage.Message
	if err := resp.Unpack(respBuf); err != nil {
		t.Fatalf("tcp unpack: %v", err)
	}
	return resp
}

func packTestDNSQuery(t *testing.T, qname string, qtype dnsmessage.Type) []byte {
	t.Helper()
	name, err := dnsmessage.NewName(qname)
	if err != nil {
		t.Fatalf("new name %q: %v", qname, err)
	}
	req := dnsmessage.Message{
		Header: dnsmessage.Header{ID: 4242, RecursionDesired: true},
		Questions: []dnsmessage.Question{
			{Name: name, Type: qtype, Class: dnsmessage.ClassINET},
		},
	}
	packed, err := req.Pack()
	if err != nil {
		t.Fatalf("pack query: %v", err)
	}
	return packed
}

func aRecordString(t *testing.T, res dnsmessage.Resource) string {
	t.Helper()
	body, ok := res.Body.(*dnsmessage.AResource)
	if !ok {
		t.Fatalf("expected *dnsmessage.AResource, got %T", res.Body)
	}
	return net.IP(body.A[:]).String()
}
