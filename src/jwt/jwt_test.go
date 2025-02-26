package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	jwtgo "github.com/dgrijalva/jwt-go"
)

func TestGenerateAndParseToken(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	publicKey := &privateKey.PublicKey

	// 2. Create example claims.
	now := time.Now().Unix()
	claims := Claims{
		StandardClaims: StandardClaims{
			Issuer:    "test-issuer",
			Subject:   "test-subject",
			IssuedAt:  now,
			ExpiresAt: now + 3600, // 1 hour from now
		},
	}

	tokenString, err := GenerateToken(claims, privateKey)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	parsedClaims, err := ParseToken(tokenString, publicKey)
	if err != nil {
		t.Fatalf("Failed to parse token: %v", err)
	}

	if parsedClaims.Issuer != claims.Issuer {
		t.Errorf("Issuer mismatch: got %s, want %s", parsedClaims.Issuer, claims.Issuer)
	}
	if parsedClaims.Subject != claims.Subject {
		t.Errorf("Subject mismatch: got %s, want %s", parsedClaims.Subject, claims.Subject)
	}
}

func TestParseToken_InvalidSignatureMethod(t *testing.T) {
	hmacKey := []byte("secret")
	token := jwtgo.NewWithClaims(jwtgo.SigningMethodHS256, &Claims{
		StandardClaims: StandardClaims{
			Issuer: "test-issuer",
		},
	})
	tokenString, err := token.SignedString(hmacKey)
	if err != nil {
		t.Fatalf("Failed to sign HMAC token: %v", err)
	}

	_, parseErr := ParseToken(tokenString, nil)
	if parseErr == nil {
		t.Error("Expected an error for invalid signing method, but got nil")
	}
}

func TestParseToken_BadToken(t *testing.T) {
	badTokenString := "this.is.not.a.valid.token"

	_, err := ParseToken(badTokenString, nil)
	if err == nil {
		t.Error("Expected ParseToken to return an error for an invalid token string, but got nil")
	}
}
