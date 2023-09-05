package main

import (
	"crypto/rsa"
	"fmt"
	"io"
	"net/http"

	client "server/clientutils"
	myutils "server/myutils"
	server "server/serverutils"
)

// for testing client port 80, pkis port 443, rpkis port 8080

var privateKey *rsa.PrivateKey
var publicKey *rsa.PublicKey

// maybe add expire date for challenge
var challenges map[string]myutils.ChallengeObject

func main() {

	// listen to requests and issue certificates
	http.HandleFunc("/getChallenge", HandleGetChallenge)
	http.HandleFunc("/getCert", HandleGetCert)
	http.ListenAndServe(":443", nil)

	// when certificate expired request new certificate

}

func init() {
	// create key pair
	myutils.CreateKeyPair("private.key")
	challenges = make(map[string]myutils.ChallengeObject)

	// get certificate from root pkis
	// same as in client
	go client.GetCertificate()

}

func HandleGetCert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "No valid Method", http.StatusMethodNotAllowed)
		return
	}
	address := r.RemoteAddr
	// verify if appID is valid ID(valid Hash)
	//appID := challenges[address].ID
	nonceToken := challenges[address].NonceToken

	// here has to be url from challenger
	request1, err := http.Get(fmt.Sprintf("http://localhost:80//.well-known/acme-challenge/%v", nonceToken))
	if err != nil {
		fmt.Println("Could not reach Server", err)
		return
	}
	defer request1.Body.Close()
	// here check results
	signedFingerprint, err := io.ReadAll(request1.Body)
	fingerprintString := string(signedFingerprint)

	// check here if token and request stuff is in database
	// if yes send back signed cert and delete from data
	// challenge: encrypted app id (fingerabdruck) under the link of token

	csrPem, err := io.ReadAll(r.Body)
	publicKey1 := server.GetPublicKeyFromCSR(csrPem)

	// TODO fix this mess, make it work

	ver, err := server.VerifySignature(nonceToken, fingerprintString, publicKey1)
	if ver == false {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Println("could not verify")
		fmt.Println("nonce:", nonceToken)
		fmt.Println("finger:", fingerprintString)
		//fmt.Print(ver, publicKey, csrPem)

		fmt.Fprint(w, string("Could not verify"))
		return
	}

	if err != nil {
		http.Error(w, "Error reading request Body", http.StatusInternalServerError)
	}

	certBytes := server.CrsToCrt(csrPem)

	w.Header().Set("Content-Type", "application/x-pem-file")
	w.WriteHeader(http.StatusOK)
	w.Write(certBytes)
}

func HandleGetChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "No valid Method", http.StatusMethodNotAllowed)
		return
	}

	address := r.RemoteAddr
	appID := r.URL.Query().Get("appID")
	nonce := server.GenerateNonce()

	if appID != "" {
		newRequest := myutils.ChallengeObject{
			ID:         appID,
			URL:        address,
			NonceToken: nonce,
		}
		fmt.Println(newRequest.ID, newRequest.URL, newRequest.NonceToken)
		challenges[address] = newRequest
	} else {
		fmt.Println("value for AppID missing")
		nonce = "Value for AppID missing"
	}

	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprint(w, nonce)

}
