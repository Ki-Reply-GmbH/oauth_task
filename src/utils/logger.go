package utils

import (
	"log"
	"os"
)

// Logger is a pre-configured logger for the application.
var Logger = log.New(os.Stdout, "INFO: ", log.LstdFlags)
