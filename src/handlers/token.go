package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"oauth-basic/src/auth"
	"oauth-basic/src/jwt"
	"oauth-basic/src/keys"
	"time"
)

// TokenResponse represents the JSON response returned by the /token endpoint.
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// TokenHandler handles the /token endpoint.
// It validates client credentials using Basic Authentication, then issues a JWT token.
func TokenHandler(w http.ResponseWriter, r *http.Request) {
	// Validate Basic Auth credentials and extract the client ID.
	userName, ok := auth.ValidateBasicAuth(r)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Set token expiration and issued time.
	now := time.Now().Unix()
	exp := time.Now().Add(time.Hour).Unix() // Token is valid for 1 hour.

	// Create JWT claims using the extracted userName and setting the role.
	claims := jwt.Claims{
		StandardClaims: jwt.StandardClaims{
			Issuer:    "oauth2-server",
			Subject:   userName,
			IssuedAt:  now,
			ExpiresAt: exp,
		},
		Role: jwt.RoleUser, // For example, set as RoleUser; this could vary.
	}

	// Validate the claims (e.g., ensuring role is valid).
	if err := claims.ValidateRole(); err != nil {
		log.Printf("Invalid claims: %v", err)
		http.Error(w, "Invalid token claims", http.StatusInternalServerError)
		return
	}

	// Generate the JWT token using the RSA private key.
	tokenString, err := jwt.GenerateToken(claims, keys.PrivateKey)
	if err != nil {
		http.Error(w, "Error generating token", http.StatusInternalServerError)
		return
	}

	// Build the JSON response.
	response := TokenResponse{
		AccessToken: tokenString,
		TokenType:   "Bearer",
		ExpiresIn:   3600,
	}

	// Set the response header and return the token in JSON format.
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
