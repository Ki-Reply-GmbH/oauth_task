package auth

import (
	"encoding/base64"
	"net/http"
	"testing"
)

// check that valid credentials are extracted correctly.
func TestExtractBasicAuthCredentials_Valid(t *testing.T) {
	req, err := http.NewRequest("GET", "/dummy", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	credentials := "testuser:testpassword"
	encoded := base64.StdEncoding.EncodeToString([]byte(credentials))
	req.Header.Set("Authorization", "Basic "+encoded)

	user, pass, ok := ExtractBasicAuthCredentials(req)
	if !ok {
		t.Error("Expected credentials extraction to succeed but it failed")
	}
	if user != "testuser" {
		t.Errorf("Expected username 'testuser', got '%s'", user)
	}
	if pass != "testpassword" {
		t.Errorf("Expected password 'testpassword', got '%s'", pass)
	}
}

// check that extraction fails if no header is provided.
func TestExtractBasicAuthCredentials_MissingHeader(t *testing.T) {
	req, err := http.NewRequest("GET", "/dummy", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	_, _, ok := ExtractBasicAuthCredentials(req)
	if ok {
		t.Error("Expected credentials extraction to fail due to missing header, but it succeeded")
	}
}

// check that extraction fails if the prefix is not "Basic".
func TestExtractBasicAuthCredentials_InvalidPrefix(t *testing.T) {
	req, err := http.NewRequest("GET", "/dummy", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	req.Header.Set("Authorization", "Bearer sometoken")
	_, _, ok := ExtractBasicAuthCredentials(req)
	if ok {
		t.Error("Expected credentials extraction to fail due to invalid prefix, but it succeeded")
	}
}

// check that extraction fails if the base64 decoding fails.
func TestExtractBasicAuthCredentials_InvalidBase64(t *testing.T) {
	req, err := http.NewRequest("GET", "/dummy", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	req.Header.Set("Authorization", "Basic not-a-valid-base64")
	_, _, ok := ExtractBasicAuthCredentials(req)
	if ok {
		t.Error("Expected credentials extraction to fail due to invalid base64 data, but it succeeded")
	}
}

// check that extraction fails if the decoded string does not contain a colon.
func TestExtractBasicAuthCredentials_InvalidFormat(t *testing.T) {
	req, err := http.NewRequest("GET", "/dummy", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	encoded := base64.StdEncoding.EncodeToString([]byte("invalidformat"))
	req.Header.Set("Authorization", "Basic "+encoded)
	_, _, ok := ExtractBasicAuthCredentials(req)
	if ok {
		t.Error("Expected credentials extraction to fail due to missing colon in credentials, but it succeeded")
	}
}

// check that ValidateBasicAuth returns true for valid credentials.
func TestValidateBasicAuth_Valid(t *testing.T) {
	req, err := http.NewRequest("GET", "/dummy", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	credentials := "testuser:testpassword"
	encoded := base64.StdEncoding.EncodeToString([]byte(credentials))
	req.Header.Set("Authorization", "Basic "+encoded)

	if !ValidateBasicAuth(req) {
		t.Error("Expected ValidateBasicAuth to return true for valid credentials, but it returned false")
	}
}

// check that ValidateBasicAuth returns false if the password is wrong.
func TestValidateBasicAuth_InvalidPassword(t *testing.T) {
	req, err := http.NewRequest("GET", "/dummy", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	credentials := "testuser:wrongpassword"
	encoded := base64.StdEncoding.EncodeToString([]byte(credentials))
	req.Header.Set("Authorization", "Basic "+encoded)

	if ValidateBasicAuth(req) {
		t.Error("Expected ValidateBasicAuth to return false for wrong password, but it returned true")
	}
}

// check that ValidateBasicAuth returns false if the username is not found.
func TestValidateBasicAuth_InvalidUser(t *testing.T) {
	req, err := http.NewRequest("GET", "/dummy", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	credentials := "unknown:somepassword"
	encoded := base64.StdEncoding.EncodeToString([]byte(credentials))
	req.Header.Set("Authorization", "Basic "+encoded)

	if ValidateBasicAuth(req) {
		t.Error("Expected ValidateBasicAuth to return false for unknown user, but it returned true")
	}
}
