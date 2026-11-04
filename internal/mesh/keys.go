package mesh

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/curve25519"
)

// GenerateKeypair generates a cryptographically valid Curve25519 keypair for WireGuard
func GenerateKeypair() (string, string, error) {
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return "", "", fmt.Errorf("failed to read random bytes: %w", err)
	}

	// Standard WireGuard Curve25519 key clamping (RFC 7748)
	priv[0] &= 248
	priv[31] = (priv[31] & 127) | 64

	var pub [32]byte
	curve25519.ScalarBaseMult(&pub, &priv)

	privBase64 := base64.StdEncoding.EncodeToString(priv[:])
	pubBase64 := base64.StdEncoding.EncodeToString(pub[:])

	return privBase64, pubBase64, nil
}

// DerivePublicKey derives the Curve25519 public key from a base64 private key
func DerivePublicKey(privBase64 string) (string, error) {
	privBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(privBase64))
	if err != nil {
		return "", fmt.Errorf("invalid base64 private key: %w", err)
	}
	if len(privBytes) != 32 {
		return "", fmt.Errorf("invalid private key length: expected 32 bytes, got %d", len(privBytes))
	}

	var priv [32]byte
	copy(priv[:], privBytes)
	priv[0] &= 248
	priv[31] = (priv[31] & 127) | 64

	var pub [32]byte
	curve25519.ScalarBaseMult(&pub, &priv)

	return base64.StdEncoding.EncodeToString(pub[:]), nil
}

// LoadOrGenerateKeypair loads a private key from disk or creates and saves a new one
func LoadOrGenerateKeypair(keyPath string) (string, string, error) {
	if keyPath != "" {
		if data, err := os.ReadFile(keyPath); err == nil {
			priv := strings.TrimSpace(string(data))
			if pub, err := DerivePublicKey(priv); err == nil {
				return priv, pub, nil
			}
		}
	}

	priv, pub, err := GenerateKeypair()
	if err != nil {
		return "", "", err
	}

	if keyPath != "" {
		if err := os.MkdirAll(filepath.Dir(keyPath), 0700); err == nil {
			_ = os.WriteFile(keyPath, []byte(priv+"\n"), 0600)
		}
	}

	return priv, pub, nil
}
