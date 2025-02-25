package main

import (
	"fmt"
	"net/http"
)

// healthHandler responds with "Server is up" when /health is requested.
func healthHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "Server is up")
}

func main() {
	// Register the /health route with its handler
	http.HandleFunc("/health", healthHandler)

	// Start the server on port 8080
	fmt.Println("Server is running on http://localhost:8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		fmt.Println("Error starting server:", err)
	}
}
