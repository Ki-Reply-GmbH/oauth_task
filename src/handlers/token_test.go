package handlers

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"oauth-basic/src/keys"
)

// checks if the function returns a valid jwt token when provided with valid credentials.
func TestTokenHandler_ValidCredentials(t *testing.T) {

	keys.InitializeKeys()

	req, err := http.NewRequest("GET", "/token", nil)
	if err != nil {
		t.Fatal(err)
	}

	cred := "testuser:testpassword"
	encodedCred := base64.StdEncoding.EncodeToString([]byte(cred))
	req.Header.Set("Authorization", "Basic "+encodedCred)

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(TokenHandler)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("TokenHandler returned wrong status code: got %v, want %v", status, http.StatusOK)
	}

	body, err := io.ReadAll(rr.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	var resp TokenResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("Failed to unmarshal JSON response: %v\nResponse body: %s", err, body)
	}

	if resp.AccessToken == "" {
		t.Error("Expected a non-empty access token, got empty string")
	}
	if resp.TokenType != "Bearer" {
		t.Errorf("Expected token type Bearer, got %s", resp.TokenType)
	}
	if resp.ExpiresIn != 3600 {
		t.Errorf("Expected expires_in of 3600, got %d", resp.ExpiresIn)
	}
}

// checks if invalid Basic Auth returns 401 Unauthorized.
func TestTokenHandler_InvalidCredentials(t *testing.T) {
	keys.InitializeKeys()

	req, err := http.NewRequest("GET", "/token", nil)
	if err != nil {
		t.Fatal(err)
	}

	cred := "wrong:credentials"
	encodedCred := base64.StdEncoding.EncodeToString([]byte(cred))
	req.Header.Set("Authorization", "Basic "+encodedCred)

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(TokenHandler)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusUnauthorized {
		t.Errorf("TokenHandler returned wrong status code: got %v, want %v", status, http.StatusUnauthorized)
	}
}

// checks behavior when no Authorization header is provided.
func TestTokenHandler_NoCredentials(t *testing.T) {
	keys.InitializeKeys()

	req, err := http.NewRequest("GET", "/token", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(TokenHandler)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusUnauthorized {
		t.Errorf("TokenHandler returned wrong status code for no credentials: got %v, want %v", status, http.StatusUnauthorized)
	}
}
