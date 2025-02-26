package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"oauth-basic/src/keys"
)

func TestKeysHandler_valid(t *testing.T) {
	keys.InitializeKeys()
	req, err := http.NewRequest("GET", "/keys", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()

	KeysHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("KeysHandler returned wrong status code: got %v, want %v", rr.Code, http.StatusOK)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to unmarshal JSON response: %v\nResponse body: %s", err, rr.Body.String())
	}
	keysField, exists := resp["keys"]
	if !exists {
		t.Error("Expected 'keys' field in response, got none")
	}
	keysList, ok := keysField.([]interface{})
	if !ok {
		t.Errorf("Expected 'keys' field to be a list, got %T", keysField)
	}
	if len(keysList) != 1 {
		t.Errorf("Expected 1 key in 'keys' field, got %d", len(keysList))
	}

}

func TestKeysHandler_error(t *testing.T) {
	keys.InitializeKeys()

	keys.PublicKey = nil

	req, err := http.NewRequest("GET", "/keys", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()

	KeysHandler(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("KeysHandler returned wrong status code: got %v, want %v", rr.Code, http.StatusInternalServerError)
	}
}
