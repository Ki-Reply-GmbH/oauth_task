package handlers

import (
	"encoding/json"
	"log"
	"net/http"

	"oauth-basic/src/keys"
)

func KeysHandler(w http.ResponseWriter, r *http.Request) {
	jwk, err := keys.GetJWK()
	if err != nil {
		log.Printf("Error getting JWK: %v", err)
		http.Error(w, "Error getting keys", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(jwk); err != nil {
		log.Printf("Error encoding JWK: %v", err)
		http.Error(w, "Error encoding keys", http.StatusInternalServerError)
		return
	}
}
