package main

import (
	"crypto/rsa"
	"fmt"

	client "client/clientutils"
	myutils "client/myutils"
)

var privateKey *rsa.PrivateKey
var publicKey *rsa.PublicKey

// for testing client port 80, pkis port 443, rpkis port 8080
func main() {
	// get challenge
	fmt.Println("HelloWorld! End of Code")

	// get certificate
}

func init() {
	myutils.CreateKeyPair("private.key")
	client.GetCertificate()
}
