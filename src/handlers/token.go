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

// TokenHandler godoc
// @Summary      Generate JWT Token
// @Description  Validates client credentials and returns a JWT token
// @Tags         token
// @Accept       json
// @Produce      json
// @Security     BasicAuth
// @Success      200  {object}  handlers.TokenResponse
// @Failure      401  {string}  string "Unauthorized"
// @Failure      500  {string}  string "Error generating token"
// @Router       /token [get]
func TokenHandler(w http.ResponseWriter, r *http.Request) {
	userName, ok := auth.ValidateBasicAuth(r)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	now := time.Now().Unix()
	exp := time.Now().Add(time.Hour).Unix()

	claims := jwt.Claims{
		StandardClaims: jwt.StandardClaims{
			Issuer:    "oauth2-server",
			Subject:   userName,
			IssuedAt:  now,
			ExpiresAt: exp,
		},
		Role: jwt.RoleUser,
	}

	if err := claims.ValidateRole(); err != nil {
		log.Printf("Invalid claims: %v", err)
		http.Error(w, "Invalid token claims", http.StatusInternalServerError)
		return
	}

	tokenString, err := jwt.GenerateToken(claims, keys.PrivateKey)
	if err != nil {
		http.Error(w, "Error generating token", http.StatusInternalServerError)
		return
	}

	response := TokenResponse{
		AccessToken: tokenString,
		TokenType:   "Bearer",
		ExpiresIn:   3600,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
