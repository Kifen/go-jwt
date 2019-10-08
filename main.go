package main

import (
	"fmt"
	"github.com/Kifen/go-jwt/common"
	"log"
	"net/http"
)

func main() {
	router := common.HandleRequests()
	fmt.Println("listening...")
	err := http.ListenAndServe(":3000", router)
	if err !=nil {
		log.Fatal("ListenAndServe: ", err)
	}
}

