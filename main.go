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
// @host      localhost:8080
// @BasePath  /
//
// @securityDefinitions.basic BasicAuth

package main

import (
	"fmt"
	"net/http"
	_ "oauth-basic/docs"
	"oauth-basic/src/handlers"
	"oauth-basic/src/keys"

	httpSwagger "github.com/swaggo/http-swagger"
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
	http.HandleFunc("/introspection", handlers.IntrospectionHandler)
	http.Handle("/docs/", httpSwagger.WrapHandler)

	fmt.Println("Server is running on http://localhost:8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		fmt.Println("Error starting server:", err)
	}
}
