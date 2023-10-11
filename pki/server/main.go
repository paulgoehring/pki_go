/*
 * pki.in GO
 *
 * pki in API docs
 *
 * API version: 1.0.0
 * Contact: paul.goehring@student.uni-tuebingen.de
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */
package main

import (
	"log"
	"net/http"

	// WARNING!
	// Change this to a fully-qualified import path
	// once you place this file into your project.
	// For example,
	//
	//    sw "github.com/myname/myrepo/go"
	//
	server "server/go"
)

func main() {
	log.Printf("Server started")

	log.Printf("Init Server")

	server.Initialize()

	router := server.NewRouter()

	// for testing root:8080, server: 443, client:80
	log.Fatal(http.ListenAndServe(":8081", router))
}
