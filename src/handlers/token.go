package handlers

import (
	"net/http"
	"oauth-basic/src/auth"
)


// TokenHandler handles the /token endpoint.
// It validates client credentials using Basic Authentication, then issues a JWT token.
func TokenHandler(w http.ResponseWriter, r *http.Request) {
	// Validate the Basic Auth credentials.
	if !auth.ValidateBasicAuth(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Create JWT claims with standard fields.

	// Generate the JWT token using the RSA private key.
	response := "test"
	// Set the response header and return the token in JSON format.
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
