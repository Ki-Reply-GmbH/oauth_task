package handlers

import (
	"encoding/json"
	"net/http"
	"oauth-basic/src/jwt"
	"oauth-basic/src/keys"
)

type IntrospectionResponse struct {
	Active    bool   `json:"active"`
	Issuer    string `json:"iss,omitempty"`
	Subject   string `json:"sub,omitempty"`
	IssuedAt  int64  `json:"iat,omitempty"`
	ExpiresAt int64  `json:"exp,omitempty"`
	Role      string `json:"role,omitempty"`
}

func IntrospectionHandler(w http.ResponseWriter, r *http.Request) {
	tokenStr := r.URL.Query().Get("token")
	if tokenStr == "" {
		http.Error(w, "Missing token parameter", http.StatusBadRequest)
		return
	}

	claims, err := jwt.ParseToken(tokenStr, keys.PublicKey)
	if err != nil {
		response := IntrospectionResponse{Active: false}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
		return
	}

	// Optional: further validation such as checking expiration could be added here.
	// For now, if parsing succeeded and the token is valid, we consider it active.

	response := IntrospectionResponse{
		Active:    true,
		Issuer:    claims.Issuer,
		Subject:   claims.Subject,
		IssuedAt:  claims.IssuedAt,
		ExpiresAt: claims.ExpiresAt,
		Role:      string(claims.Role),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
