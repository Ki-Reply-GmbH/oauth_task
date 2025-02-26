package main

import (
	"fmt"
	"net/http"
	"oauth-basic/src/handlers"
	"oauth-basic/src/keys"
)

func healthHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "Server is up")
}

func main() {

	keys.InitializeKeys()
	/* * because its a small project with small number of endpoint so i keep it in main
	but usually i would use Gorilla Mux, Chi, or the built-in http.ServeMux and register the routes in a separate file.
	*/
	http.HandleFunc("/health", healthHandler)
	http.HandleFunc("/token", handlers.TokenHandler)
	http.HandleFunc("/keys", handlers.KeysHandler)

	fmt.Println("Server is running on http://localhost:8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		fmt.Println("Error starting server:", err)
	}
}
