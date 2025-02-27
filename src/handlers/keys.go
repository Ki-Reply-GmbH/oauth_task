package handlers

import (
	"encoding/json"
	"net/http"

	"oauth-basic/src/keys"
	. "oauth-basic/src/utils"
)

// KeysHandler godoc
// @Summary      Retrieve Public Signing Keys
// @Description  Returns the RSA public signing keys in JWK format, which can be used to verify JWT signatures.
// @Tags         keys
// @Produce      json
// @Success      200  {object}  map[string]interface{}
// @Failure      500  {string}  string "Error getting keys" or "Error encoding keys"
// @Router       /keys [get]
func KeysHandler(w http.ResponseWriter, r *http.Request) {
	jwk, err := keys.GetJWK()
	if err != nil {
		Logger.Println("Error getting JWK: %v", err)
		http.Error(w, "Error getting keys", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(jwk); err != nil {
		Logger.Printf("Error encoding JWK: %v", err)
		http.Error(w, "Error encoding keys", http.StatusInternalServerError)
		return
	}
}
