package mesh

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type mockExecutor struct {
	mu       sync.Mutex
	commands [][]string
	dumpOut  string
}

func (m *mockExecutor) Run(ctx context.Context, cmd string, args ...string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	call := append([]string{cmd}, args...)
	m.commands = append(m.commands, call)

	if cmd == "wg" && len(args) >= 2 && args[0] == "show" && args[1] == "dump" {
		return []byte(m.dumpOut), nil
	}

	return []byte(""), nil
}

func TestKeypairGeneration(t *testing.T) {
	priv, pub, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}

	if len(priv) < 40 {
		t.Errorf("Unexpected private key length: %s", priv)
	}
	if len(pub) < 40 {
		t.Errorf("Unexpected public key length: %s", pub)
	}

	derivedPub, err := DerivePublicKey(priv)
	if err != nil {
		t.Fatalf("DerivePublicKey failed: %v", err)
	}

	if derivedPub != pub {
		t.Errorf("Expected derived public key %s to match %s", derivedPub, pub)
	}
}

func TestInitInterfaceAndSyncPeers(t *testing.T) {
	mock := &mockExecutor{}
	priv, pub, _ := GenerateKeypair()
	cfg := Config{
		InterfaceName: "flarelens0",
		ListenPort:    51820,
		OverlayIP:     "10.42.0.1",
	}

	mgr := NewManager(cfg, priv, pub, mock, nil)
	ctx := context.Background()

	mockCtrl := &mockWGController{}
	mgr.SetWGController(mockCtrl)

	// 1. Test Interface Init
	if err := mgr.InitInterface(ctx); err != nil {
		t.Fatalf("InitInterface failed: %v", err)
	}

	if mockCtrl.configuredDevice != "flarelens0" {
		t.Errorf("Expected native ConfigureDevice called for flarelens0, got: %s", mockCtrl.configuredDevice)
	}

	// 2. Test SyncPeers with valid WireGuard keys
	_, peerPub1, _ := GenerateKeypair()
	_, peerPub2, _ := GenerateKeypair()
	peers := []Peer{
		{
			ID:        "node-2",
			Name:      "node-fra-02",
			PublicKey: peerPub1,
			OverlayIP: "10.42.0.2",
			Endpoint:  "159.69.10.5:51820",
			Type:      "node",
		},
		{
			ID:        "client-1",
			Name:      "operator-laptop",
			PublicKey: peerPub2,
			OverlayIP: "10.42.0.99",
			Type:      "client",
		},
	}

	if err := mgr.SyncPeers(ctx, peers); err != nil {
		t.Fatalf("SyncPeers failed: %v", err)
	}

	if !mockCtrl.lastConfig.ReplacePeers {
		t.Errorf("Expected ReplacePeers=true in native Netlink sync")
	}
	if len(mockCtrl.lastConfig.Peers) != 2 {
		t.Fatalf("Expected 2 peers in native Netlink sync, got %d", len(mockCtrl.lastConfig.Peers))
	}
}

func TestParseWGDump(t *testing.T) {
	nowUnix := time.Now().Unix()
	handshakeRecent := nowUnix - 30 // 30 seconds ago (active)
	handshakeStale := nowUnix - 600 // 10 minutes ago (inactive)

	dump := "privkey\tpubkey\t51820\toff\n" +
		"ABCDEF==\t(none)\t159.69.10.5:51820\t10.42.0.2/32\t" +
		strings.TrimSpace(string(int64ToString(handshakeRecent))) + "\t1048576\t2097152\t25\n" +
		"XYZXYZ==\t(none)\t(none)\t10.42.0.99/32\t" +
		strings.TrimSpace(string(int64ToString(handshakeStale))) + "\t512\t1024\t25\n"

	stats, err := ParseWGDump(dump)
	if err != nil {
		t.Fatalf("ParseWGDump failed: %v", err)
	}

	if len(stats) != 2 {
		t.Fatalf("Expected 2 peers, got %d", len(stats))
	}

	nodeStat, exists := stats["ABCDEF=="]
	if !exists {
		t.Fatalf("Expected stats for ABCDEF==")
	}
	if !nodeStat.Active {
		t.Errorf("Expected node peer with recent handshake to be Active")
	}
	if nodeStat.BytesRx != 1048576 || nodeStat.BytesTx != 2097152 {
		t.Errorf("Unexpected bytes: rx=%d, tx=%d", nodeStat.BytesRx, nodeStat.BytesTx)
	}
	if nodeStat.OverlayIP != "10.42.0.2" {
		t.Errorf("Expected overlay IP 10.42.0.2, got: %s", nodeStat.OverlayIP)
	}

	clientStat, exists := stats["XYZXYZ=="]
	if !exists {
		t.Fatalf("Expected stats for XYZXYZ==")
	}
	if clientStat.Active {
		t.Errorf("Expected client peer with stale handshake to NOT be Active")
	}
}

func int64ToString(n int64) string {
	return strings.TrimSpace(string([]byte{
		byte('0' + (n/1000000000)%10),
		byte('0' + (n/100000000)%10),
		byte('0' + (n/10000000)%10),
		byte('0' + (n/1000000)%10),
		byte('0' + (n/100000)%10),
		byte('0' + (n/10000)%10),
		byte('0' + (n/1000)%10),
		byte('0' + (n/100)%10),
		byte('0' + (n/10)%10),
		byte('0' + (n/1)%10),
	}))
}

type mockWGController struct {
	configuredDevice string
	lastConfig       wgtypes.Config
	device           *wgtypes.Device
}

func (m *mockWGController) ConfigureDevice(name string, cfg wgtypes.Config) error {
	m.configuredDevice = name
	m.lastConfig = cfg
	return nil
}

func (m *mockWGController) Device(name string) (*wgtypes.Device, error) {
	if m.device != nil {
		return m.device, nil
	}
	return &wgtypes.Device{Name: name}, nil
}

func (m *mockWGController) Close() error {
	return nil
}

func TestNativeWGControllerSync(t *testing.T) {
	priv, pub, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}

	mockCtrl := &mockWGController{}
	mockExec := &mockExecutor{}
	cfg := Config{
		InterfaceName: "flarelens0",
		ListenPort:    51820,
		OverlayIP:     "100.64.0.1",
	}

	mgr := NewManager(cfg, priv, pub, mockExec, nil)
	mgr.SetWGController(mockCtrl)

	ctx := context.Background()
	if err := mgr.InitInterface(ctx); err != nil {
		t.Fatalf("InitInterface with native controller failed: %v", err)
	}

	if mockCtrl.configuredDevice != "flarelens0" {
		t.Errorf("Expected native ConfigureDevice called for flarelens0, got: %s", mockCtrl.configuredDevice)
	}
	if mockCtrl.lastConfig.ListenPort == nil || *mockCtrl.lastConfig.ListenPort != 51820 {
		t.Errorf("Expected listen port 51820 in native config")
	}

	_, peerPub, _ := GenerateKeypair()
	peers := []Peer{
		{
			ID:        "peer-node",
			Name:      "node-1",
			PublicKey: peerPub,
			OverlayIP: "100.64.0.2",
			Endpoint:  "198.51.100.1:51820",
		},
	}

	if err := mgr.SyncPeers(ctx, peers); err != nil {
		t.Fatalf("SyncPeers with native controller failed: %v", err)
	}

	if !mockCtrl.lastConfig.ReplacePeers {
		t.Errorf("Expected ReplacePeers to be true in native peer sync")
	}
	if len(mockCtrl.lastConfig.Peers) != 1 {
		t.Fatalf("Expected 1 peer configured natively, got %d", len(mockCtrl.lastConfig.Peers))
	}
	if mockCtrl.lastConfig.Peers[0].PublicKey.String() != peerPub {
		t.Errorf("Expected configured peer public key %s, got %s", peerPub, mockCtrl.lastConfig.Peers[0].PublicKey.String())
	}
}
