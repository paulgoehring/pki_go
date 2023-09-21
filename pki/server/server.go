package main

import (
	"crypto/rsa"
	"fmt"
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
	if r.Method != http.MethodGet {
		http.Error(w, "No valid Method", http.StatusMethodNotAllowed)
		return
	}
	fmt.Println("Got Certification request")
	signedFingerprint := string(r.URL.Query().Get("fingerprint"))

	if signedFinerprint != "" { // here check if nonce + appID correct, every nonce needs a number for map i guess, after delete from data structure

	}
}

func HandleGetChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "No valid Method", http.StatusMethodNotAllowed)
		return
	}
	fmt.Println("Got Challenge Request")
	address := r.RemoteAddr
	appID := r.URL.Query().Get("appID")
	nonce := server.GenerateNonce()
	if appID != "" {
		newRequest := myutils.ChallengeObject{
			ID:         appID,
			URL:        address,
			NonceToken: nonce,
		}
		//fmt.Println(newRequest.ID, newRequest.URL, newRequest.NonceToken)
		challenges[address] = newRequest
	} else {
		fmt.Println("value for AppID missing")
		nonce = "Value for AppID missing"
	}
	fmt.Println(fmt.Sprintf("Sent challenge: %v", nonce))

	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprint(w, nonce)
}
