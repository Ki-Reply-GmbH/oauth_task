package auth

import (
	"encoding/base64"
	"errors"
	"net/http"
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
		return "", "", false
	}
	credentials := string(decodedBytes)

	parts := strings.SplitN(credentials, ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	return parts[0], parts[1], true
}

// checks if the provided credentials are valid.
func ValidateBasicAuth(r *http.Request) bool {
	providedUserName, providedUserPass, ok := ExtractBasicAuthCredentials(r)
	if !ok {
		return false
	}

	expecteduserpassword, err := LookupClientSecret(providedUserName)
	if err != nil {
		return false
	}

	return providedUserPass == expecteduserpassword
}

// lookup in db for the password with provided username and return it.
func LookupClientSecret(userName string) (string, error) {
	// For demonstration, we assume that the client with "testuser" has the password "testpassword".
	// This would be a db operation but for now we just do hard coded check
	if userName == "testuser" {
		return "testpassword", nil
	}
	return "", errors.New("client not found")
}
