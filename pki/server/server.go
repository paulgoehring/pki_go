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

// look up backend id, format is [frontendID]backendID
var tableAppIDs map[string]string

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
	tableAppIDs = make(map[string]string)

	tableAppIDs["asd123"] = "123asd"

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
	frontendAppID := r.URL.Query().Get("appID")
	signedFingerprint := string(r.URL.Query().Get("fingerprint"))
	publicKey := challenges[frontendAppID].pubKey // take from jwt

	fingerprintToVerify := challenges[frontendAppID].NonceToken + challenges[frontendAppID].ID

	if signedFingerprint != "" { // here check if nonce + appID correct, every nonce needs a number for map i guess, after delete from data structure
		ver, err := server.VerifySignature(fingerprintToVerify, signedFingerprint, publicKey)

	}
}

func HandleGetChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "No valid Method", http.StatusMethodNotAllowed)
		return
	}
	fmt.Println("Got Challenge Request")

	frontendAppID := r.URL.Query().Get("appID")
	publicKey := r.URL.Query().Get("pubKey") //how to send pubKey
	backendAppID := tableAppIDs[frontendAppID]

	nonce := server.GenerateNonce()
	if frontendAppID != "" {
		newRequest := myutils.ChallengeObject{
			ID:         backendAppID,
			NonceToken: nonce,
			PubKey:     publicKey,
		}
		//fmt.Println(newRequest.ID, newRequest.URL, newRequest.NonceToken)
		challenges[frontendAppID] = newRequest
	} else {
		fmt.Println("value for AppID missing")
		nonce = "Value for AppID missing"
	}
	fmt.Println(fmt.Sprintf("Sent challenge: %v", nonce))

	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprint(w, nonce)
}
