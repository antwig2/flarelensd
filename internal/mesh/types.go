package mesh

// Peer represents a remote node or operator client in the WireGuard mesh
type Peer struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	PublicKey    string   `json:"public_key"`
	OverlayIP    string   `json:"overlay_ip"`
	TailscaleIP  string   `json:"tailscale_ip,omitempty"`
	Endpoint     string   `json:"endpoint,omitempty"`
	Type         string   `json:"type"` // "node" or "client"
	AllowedIPs   []string `json:"allowed_ips,omitempty"`
	SSHPublicKey string   `json:"ssh_public_key,omitempty"`
}

// PeerStats represents real-time kernel telemetry for a WireGuard peer
type PeerStats struct {
	PublicKey       string `json:"public_key"`
	OverlayIP       string `json:"overlay_ip"`
	LatestHandshake int64  `json:"latest_handshake"` // Unix timestamp
	BytesRx         int64  `json:"bytes_rx"`
	BytesTx         int64  `json:"bytes_tx"`
	Active          bool   `json:"active"` // Handshake within last 3 minutes
}

// MeshRegisterResponse is returned by Cloudflare Worker upon registration
type MeshRegisterResponse struct {
	Status string `json:"status"`
	Peer   Peer   `json:"peer"`
	Subnet string `json:"subnet"`
	Peers  []Peer `json:"peers"`
}

// Config defines local WireGuard mesh configuration
type Config struct {
	Enabled        bool   `json:"enabled" yaml:"enabled"`
	InterfaceName  string `json:"interface_name" yaml:"interface_name"`   // e.g. "flarelens0"
	ListenPort     int    `json:"listen_port" yaml:"listen_port"`         // default: 51820
	KeyPath        string `json:"key_path" yaml:"key_path"`               // e.g. "/etc/flarelens/mesh.key"
	OverlayIP      string `json:"overlay_ip" yaml:"overlay_ip"`           // allocated mesh IP e.g. "100.64.0.1"
	Subnet         string `json:"subnet" yaml:"subnet"`                   // default: "100.64.0.0/10"
	PublicEndpoint string `json:"public_endpoint" yaml:"public_endpoint"` // optional public IP:port override
}
