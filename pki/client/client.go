package main

import (
	"fmt"

	client "client/clientutils"
	myutils "client/myutils"
)

var PathMarbleCrt string = "marbleClientCert.crt"
var PathMarbleRootCrt string = "marblerunCA.crt"

// var PathRPKICrt string = "rootPKI.crt"
var PathMarbleKey string = "marbleClient.key"
var PathOwnCrt string = "clientPKI.crt"
var PathIdentityToken string = "client.jwt"
var PathOwnKey string = "private.key"

// for testing client port 80, pkis port 443, rpkis port 8080
func main() {
	// get challenge
	fmt.Println("HelloWorld! End of Code")

	// get certificate
}

func init() {
	myutils.CreateKeyPair("private.key")
	client.GetCertificate("private.key", PathIdentityToken, PathMarbleKey, PathMarbleCrt, PathOwnCrt, "asd123", true)
	client.RenewCertificate(PathIdentityToken, PathOwnCrt, PathOwnKey, false, "asd123")

	//client.VerifyJwt()
}
