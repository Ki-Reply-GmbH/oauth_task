package config

import (
	"log"
	"os"

	"github.com/joho/godotenv"
)

// Config holds the configuration values for the application.
type Config struct {
	Port string
	// You might add other configuration like client credentials, etc.
}

// Load reads configuration from environment variables.
func Load() Config {
	if err := godotenv.Load(); err != nil {
		log.Printf("No .env file found or error loading .env file: %v", err)
	}
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080" // default port
	}
	return Config{
		Port: port,
	}
}
