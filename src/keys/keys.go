package keys

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"log"
	"math/big"
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

// for verifing JWT signatures with a rsa key, the fields are enough. No need for optional fields.
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func GetJWK() (map[string]interface{}, error) {
	if PublicKey == nil {
		return nil, errors.New("public key is nil, did you call InitializeKeys?")
	}

	n := base64.RawURLEncoding.EncodeToString(PublicKey.N.Bytes())

	eBytes := big.NewInt(int64(PublicKey.E)).Bytes()
	e := base64.RawURLEncoding.EncodeToString(eBytes)

	jwk := JWK{
		Kty: "RSA",
		Use: "sig",
		Kid: "default", //this is for demo, originally it will be auto generated
		Alg: "RS256",
		N:   n,
		E:   e,
	}

	return map[string]any{
		"keys": []JWK{jwk},
	}, nil
}
