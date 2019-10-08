package main

import (
	"fmt"
	"github.com/Kifen/go-jwt/common"
	"log"
	"net/http"
	"os"
)

func main() {
	router := common.HandleRequests()
	fmt.Println("listening...")
	err := http.ListenAndServe(GetPort(), router)
	if err !=nil {
		log.Fatal("ListenAndServe: ", err)
	}
}

func GetPort() string {
	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
		fmt.Println("INFO: No PORT environment variable detected, defaulting to " + port)
	}

	return ":" + port
}
