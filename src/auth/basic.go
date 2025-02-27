package auth

import (
	"encoding/base64"
	"errors"
	"net/http"
	. "oauth-basic/src/utils"
	"os"
	"strings"
)

// extracts the username and password from the Authorization header and returns as a string.
func ExtractBasicAuthCredentials(r *http.Request) (string, string, bool) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Basic ") {
		return "", "", false
	}

	encodedCredentials := strings.TrimPrefix(authHeader, "Basic ")
	decodedBytes, err := base64.StdEncoding.DecodeString(encodedCredentials)
	if err != nil {
		Logger.Printf("Failed to decode base64: %v", err)
		return "", "", false
	}
	credentials := string(decodedBytes)

	parts := strings.SplitN(credentials, ":", 2)
	if len(parts) != 2 {
		Logger.Println("Invalid credentials format")
		return "", "", false
	}
	return parts[0], parts[1], true
}

// checks if the provided credentials are valid.
func ValidateBasicAuth(r *http.Request) (string, bool) {
	providedclientID, providedClientSecret, ok := ExtractBasicAuthCredentials(r)
	if !ok {
		return "", false
	}

	expectedClientSecret, err := LookupClientSecret(providedclientID)
	if err != nil {
		return "", false
	}
	if providedClientSecret != expectedClientSecret {
		return "", false
	}

	return providedclientID, true
}

// lookup in db for the password with provided username and return it.
func LookupClientSecret(clientID string) (string, error) {
	// For demonstration, we assume that the client with "testid" has the password "testsecret".
	// This would be a db operation but for now we just check from environment variables.

	clientIDFromEnv, clientSecretFromEnv := LoadClientCredentialFromEnv()
	if clientID == clientIDFromEnv {
		return clientSecretFromEnv, nil
	}
	Logger.Printf("Client not found: %s", clientID)
	return "", errors.New("client not found")
}

func LoadClientCredentialFromEnv() (string, string) {
	clientIDFromEnv := os.Getenv("CLIENT_ID")
	clientSecretFromEnv := os.Getenv("CLIENT_SECRET")
	return clientIDFromEnv, clientSecretFromEnv
}
