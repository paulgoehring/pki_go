package main

import (
	"fmt"
	"os"

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

var AppName = "PKI Client"

var ServerIp = "localhost"
var ServerPortInsecure = "8082"
var ServerPortSecure = "8081"

var RootIp = "localhost"
var RootPort = "8443"

// for testing client port 80, pkis port 443, rpkis port 8080
func main() {
	// get challenge
	fmt.Println("HelloWorld! End of Code")

	// get certificate
}

func init() {
	myutils.CreateKeyPair(PathOwnKey)
	client.GetCertificate(PathOwnKey, PathIdentityToken, PathMarbleKey, PathMarbleCrt,
		AppName, ServerIp, ServerPortSecure)
	client.RenewCertificate(ServerIp, ServerPortInsecure, PathIdentityToken,
		PathOwnKey, AppName, false)

	token, err := os.ReadFile(PathIdentityToken)
	if err != nil {
		fmt.Println("Error reading JWT file:", err)
		return
	}
	client.VerifyICT(RootIp, RootPort, string(token))

	go client.CheckTokenExpirationPeriodically(PathIdentityToken, ServerIp, ServerPortInsecure, PathIdentityToken,
		PathOwnKey, AppName, false)

	select {}
}
