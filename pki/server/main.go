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

/*
Marblerun Manifest data which the app Needs:
"Env": {
	"MARBLE_ROOT_CA": "{{ pem .MarbleRun.RootCA.Cert }}",
	"MARBLE_CERT": "{{ pem .MarbleRun.MarbleCert.Cert }}",
	"MARBLE_KEY": "{{ pem .MarbleRun.MarbleCert.Private }}",
	"PKI_ROOT_CA": paste root cert here,
	"Layer": "0"     //acces via os.Getenv("Layer") etc
}
}

*/

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

	server1 := http.Server{
		Addr:      ":" + server.OwnPortSecure,
		TLSConfig: server.DefineTLSConfig(),
	}

	server2 := http.Server{
		Addr: ":" + server.OwnPortInsecure,
	}

	router := server.NewRouter()
	router2 := server.NewRouter2()
	server1.Handler = router
	server2.Handler = router2

	// for testing root:8080, server: 443, client:80
	go func() {
		log.Fatal(server1.ListenAndServeTLS("", ""))
	}()
	log.Fatal(server2.ListenAndServe())
}
