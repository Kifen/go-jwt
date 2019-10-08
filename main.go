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
	port := os.Getenv("PORT")
	log.Printf("Port is = %s",port)
	if port == "" {
		port = "3000"
	}
	fmt.Printf("Listening on port :%s", port)
	err := http.ListenAndServe(":" + port, router)
	if err !=nil {
		log.Fatal("ListenAndServe: ", err)
	}
}

