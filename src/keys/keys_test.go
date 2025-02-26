package keys

import (
	"crypto/x509"
	"encoding/base64"
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
func TestGetJWK_NilPublicKey(t *testing.T) {
	PublicKey = nil

	jwkMap, err := GetJWK()
	if err == nil {
		t.Error("Expected error when public key is nil, but got nil error")
	}
	if jwkMap != nil {
		t.Errorf("Expected returned map to be nil when public key is nil, but got: %v", jwkMap)
	}
}

func TestGetJWK_Valid(t *testing.T) {
	InitializeKeys()

	jwkMap, err := GetJWK()
	if err != nil {
		t.Fatalf("Unexpected error when getting JWK: %v", err)
	}

	keysEntry, ok := jwkMap["keys"]
	if !ok {
		t.Fatal("Expected key 'keys' in the returned map, but it was not found")
	}

	jwkSlice, ok := keysEntry.([]JWK)
	if !ok {
		t.Fatalf("Expected keys to be of type []JWK, got %T", keysEntry)
	}
	if len(jwkSlice) != 1 {
		t.Fatalf("Expected exactly one JWK in the slice, got %d", len(jwkSlice))
	}

	jwk := jwkSlice[0]
	if jwk.Kty != "RSA" {
		t.Errorf("Expected Kty to be 'RSA', got '%s'", jwk.Kty)
	}
	if jwk.Use != "sig" {
		t.Errorf("Expected Use to be 'sig', got '%s'", jwk.Use)
	}
	if jwk.Kid != "default" {
		t.Errorf("Expected Kid to be 'default', got '%s'", jwk.Kid)
	}
	if jwk.Alg != "RS256" {
		t.Errorf("Expected Alg to be 'RS256', got '%s'", jwk.Alg)
	}
	if jwk.N == "" {
		t.Error("Expected non-empty modulus (N)")
	}
	if jwk.E == "" {
		t.Error("Expected non-empty exponent (E)")
	}

	if _, err := base64.RawURLEncoding.DecodeString(jwk.N); err != nil {
		t.Errorf("Failed to decode modulus N: %v", err)
	}
	if _, err := base64.RawURLEncoding.DecodeString(jwk.E); err != nil {
		t.Errorf("Failed to decode exponent E: %v", err)
	}
}
