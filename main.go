// Package main swagger documentation.
//
// @title           OAuth2 Server API
// @version         1.0
// @description     This is an OAuth2 server that issues JWT access tokens.
// @termsOfService  http://swagger.io/terms/
//
// @contact.name   Pratik Saha
// @contact.email  p.saha@reply.de
//
// @license.name  Apache 2.0
// @license.url   http://www.apache.org/licenses/LICENSE-2.0.html
//
// @host      localhost:30080
// @BasePath  /
//
// @securityDefinitions.basic BasicAuth

package main

import (
	"fmt"
	"log"
	"net/http"
	_ "oauth-basic/docs"
	"oauth-basic/src/config"
	"oauth-basic/src/handlers"
	"oauth-basic/src/keys"
	. "oauth-basic/src/utils"

	httpSwagger "github.com/swaggo/http-swagger"
)

func healthHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "Server is up")
}

func main() {
	// Load configuration (e.g., port, key paths)
	cfg := config.Load()
	keys.InitializeKeys()

	// Initialize logger
	Logger.Println("Starting OAuth2 Server...")

	/* * because its a small project with small number of endpoint so i keep it in main
	but usually i would use Gorilla Mux, Chi, or the built-in http.ServeMux and register the routes in a separate file.
	*/
	mux := http.NewServeMux()
	mux.HandleFunc("/token", handlers.TokenHandler)
	mux.HandleFunc("/keys", handlers.KeysHandler)
	mux.HandleFunc("/introspect", handlers.IntrospectionHandler)
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/docs/", httpSwagger.WrapHandler)

	// Start HTTP server
	addr := fmt.Sprintf(":%s", cfg.Port)
	Logger.Println("Server running on", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("Error starting server: %v", err)
	}

	fmt.Println("Server is running on http://localhost:8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		fmt.Println("Error starting server:", err)
	}
}
