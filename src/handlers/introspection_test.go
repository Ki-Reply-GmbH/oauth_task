package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"oauth-basic/src/jwt"
	"oauth-basic/src/keys"
)

func TestIntrospectionHandler_MissingToken(t *testing.T) {
	req, err := http.NewRequest("GET", "/introspect", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	rr := httptest.NewRecorder()
	IntrospectionHandler(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status code %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestIntrospectionHandler_InvalidToken(t *testing.T) {
	req, err := http.NewRequest("GET", "/introspect?token=invalidtoken", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	rr := httptest.NewRecorder()
	IntrospectionHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, rr.Code)
	}

	var resp IntrospectionResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}
	if resp.Active {
		t.Error("Expected token to be inactive for an invalid token, but got active=true")
	}
}

func TestIntrospectionHandler_ValidToken(t *testing.T) {
	keys.InitializeKeys()

	now := time.Now().Unix()
	exp := time.Now().Add(time.Hour).Unix()
	claims := jwt.Claims{
		StandardClaims: jwt.StandardClaims{
			Issuer:    "oauth2-server",
			Subject:   "testuser",
			IssuedAt:  now,
			ExpiresAt: exp,
		},
		Role: jwt.RoleUser,
	}

	// Generate a valid token.
	tokenString, err := jwt.GenerateToken(claims, keys.PrivateKey)
	if err != nil {
		t.Fatalf("Error generating token: %v", err)
	}

	// Create a request with the valid token as query parameter.
	req, err := http.NewRequest("GET", "/introspect?token="+tokenString, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	rr := httptest.NewRecorder()
	IntrospectionHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, rr.Code)
	}

	var resp IntrospectionResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if !resp.Active {
		t.Error("Expected token to be active, but got active=false")
	}
	if resp.Issuer != claims.Issuer {
		t.Errorf("Expected issuer %s, got %s", claims.Issuer, resp.Issuer)
	}
	if resp.Subject != claims.Subject {
		t.Errorf("Expected subject %s, got %s", claims.Subject, resp.Subject)
	}
	if resp.Role != string(claims.Role) {
		t.Errorf("Expected role %s, got %s", claims.Role, resp.Role)
	}
	if resp.IssuedAt != claims.IssuedAt {
		t.Errorf("Expected issued at %d, got %d", claims.IssuedAt, resp.IssuedAt)
	}
	if resp.ExpiresAt != claims.ExpiresAt {
		t.Errorf("Expected expires at %d, got %d", claims.ExpiresAt, resp.ExpiresAt)
	}
}
