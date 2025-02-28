package handlers

import (
	"encoding/json"
	"net/http"
	"oauth-basic/src/jwt"
	"oauth-basic/src/keys"
	. "oauth-basic/src/utils"
	"strings"
)

type IntrospectionResponse struct {
	Active    bool   `json:"active"`
	Issuer    string `json:"iss,omitempty"`
	Subject   string `json:"sub,omitempty"`
	IssuedAt  int64  `json:"iat,omitempty"`
	ExpiresAt int64  `json:"exp,omitempty"`
	Role      string `json:"role,omitempty"`
}

// IntrospectionHandler godoc
// @Summary      Introspect JWT Token
// @Description  Validates a JWT token provided as a query parameter and returns its introspection result including active status and token claims.
// @Tags         introspection
// @Produce      json
// @Param        token   query     string  true  "JWT token to introspect"
// @Success      200     {object}  handlers.IntrospectionResponse "Token introspection result"
// @Failure      400     {string}  string "Missing token parameter"
// @Router       /introspection [get]
func IntrospectionHandler(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		Logger.Println("Missing Authorization header")
		http.Error(w, "Missing Authorization header", http.StatusBadRequest)
		return
	}

	// Extract the token from the Authorization header
	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenStr == authHeader {
		Logger.Println("Invalid Authorization header format")
		http.Error(w, "Invalid Authorization header format", http.StatusBadRequest)
		return
	}

	claims, err := jwt.ParseToken(tokenStr, keys.PublicKey)
	if err != nil {
		response := IntrospectionResponse{Active: false}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
		return
	} else {
		Logger.Printf("Token claims error: %+v", err)
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
