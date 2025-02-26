package keys

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log"
)

var (
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
)

func InitializeKeys() {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Error generating RSA key: %v", err)
	}
	PrivateKey = key
	PublicKey = &key.PublicKey
}

func ExportPublicKeyPEM() []byte {
	pubASN1, err := x509.MarshalPKIXPublicKey(PublicKey)
	if err != nil {
		log.Fatalf("Error marshaling public key: %v", err)
	}
	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubASN1,
	}
	return pem.EncodeToMemory(pemBlock)
}
