package main

import (
	"fmt"
	"math/rand"
	"os"
	"time"

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

var AppName string

var ServerIp string
var ServerPortInsecure string
var ServerPortSecure string

var RootIp string
var RootPort string

// for testing client port 80, pkis port 443, rpkis port 8080
func main() {
	// get challenge
	fmt.Println("HelloWorld! End of Code")

	// get certificate
}

func init() {
	AppName = "PKI Client" + fmt.Sprint(rand.Intn(1000))

	err := os.WriteFile(PathMarbleRootCrt, []byte(os.Getenv("MARBLE_ROOT_CA")), 0644)
	if err != nil {
		fmt.Println("Error Writing Marble Root Certificate", err)
	}

	err = os.WriteFile(PathMarbleCrt, []byte(os.Getenv("MARBLE_CERT")), 0644)
	if err != nil {
		fmt.Println("Error Writing Marble Own Certificate", err)
	}

	err = os.WriteFile(PathMarbleKey, []byte(os.Getenv("MARBLE_KEY")), 0644)
	if err != nil {
		fmt.Println("Error Writing Marble Private Key", err)
	}

	ServerIp = os.Getenv("SERVER_IP")
	ServerPortInsecure = os.Getenv("SERVER_PORT_INSECURE")
	ServerPortSecure = os.Getenv("SERVER_PORT_SECURE")

	RootIp = os.Getenv("ROOT_IP")
	RootPort = os.Getenv("ROOT_PORT")

	fmt.Println(AppName)
	myutils.CreateKeyPair(PathOwnKey)
	client.GetCertificate(PathOwnKey, PathIdentityToken, PathMarbleKey, PathMarbleCrt,
		AppName, ServerIp, ServerPortSecure)
	//client.RenewCertificate(ServerIp, ServerPortInsecure, PathIdentityToken,
	//	PathOwnKey, AppName, false)

	token, err := os.ReadFile(PathIdentityToken)
	if err != nil {
		fmt.Println("Error reading JWT file:", err)
		return
	}
	client.VerifyICT(RootIp, RootPort, string(token))

	//go client.CheckTokenExpirationPeriodically(PathIdentityToken, ServerIp, ServerPortInsecure, PathIdentityToken,
	//PathOwnKey, AppName, false)

	// implement Client Logic Here
	for i := 0; i < 20; i++ {
		//_ = testFibonacci()
		//_ = testKeys()
		_ = test1Minute()
	}
}

func test1Minute() int {
	start := time.Now() // Record the start time

	count := 0 // Initialize a counter for generated keys

	oldICT, err := os.ReadFile(PathIdentityToken)
	if err != nil {
		fmt.Println("Error reading JWT file:", err)
	}
	privateKeyOld, err := client.LoadPrivateKeyFromFile(PathOwnKey)
	if err != nil {
		fmt.Println("Error loading private key", err)
	}

	// Loop until one minute has passed
	for time.Since(start) < time.Minute {
		// Generate an RSA key
		client.RenewCertificate(privateKeyOld, oldICT, ServerIp, ServerPortInsecure, PathIdentityToken, PathOwnKey, AppName, false)
		count++ // Increment the counter for each generated key
	}
	fmt.Printf("Number Server interactions: %d\n", count)
	return count
}
