package keys

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestInitializeKeys(t *testing.T) {
	InitializeKeys()

	if PrivateKey == nil {
		t.Fatal("Expected PrivateKey to be initialized, got nil")
	}
	if PublicKey == nil {
		t.Fatal("Expected PublicKey to be initialized, got nil")
	}
}

func TestExportPublicKeyPEM(t *testing.T) {
	InitializeKeys()

	pemData := ExportPublicKeyPEM()
	if len(pemData) == 0 {
		t.Fatal("Expected non-empty PEM data, got empty")
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		t.Fatalf("Failed to decode PEM block: %s", string(pemData))
	}
	if block.Type != "PUBLIC KEY" {
		t.Errorf("Expected PEM block type 'PUBLIC KEY', got %s", block.Type)
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse public key from PEM data: %v", err)
	}
	if pubKey == nil {
		t.Fatalf("Expected valid public key, got nil")
	}
}
