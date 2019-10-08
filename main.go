package main

import (
	"github.com/Kifen/go-jwt/common"
	"log"
	"net/http"
	"os"
)

func main() {
	router := common.HandleRequests()
	os.Setenv("PORT", ":3000")
	port := os.Getenv("PORT")
	// Start a basic HTTP server
	if err := http.ListenAndServe(port, router); err != nil {
		log.Fatal(err)
	}
}
