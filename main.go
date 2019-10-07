package main

import (
	"github.com/Kifen/go-jwt/common"
	"log"
	"net/http"
)

func main() {
	router := common.HandleRequests()
	// Start a basic HTTP server
	if err := http.ListenAndServe(":8000", router); err != nil {
		log.Fatal(err)
	}
}
