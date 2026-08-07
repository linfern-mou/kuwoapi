package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"kuwoapi/server"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}
	host := os.Getenv("HOST")

	srv := server.New()
	addr := fmt.Sprintf("%s:%s", host, port)
	log.Printf("server running @ http://%s", addr)
	log.Fatal(http.ListenAndServe(addr, srv))
}
