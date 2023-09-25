package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"

	"github.com/golang-jwt/jwt"

	//client "server/clientutils"
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

	tableAppIDs["asd123"] = "asd123"

	// get certificate from root pkis
	// same as in client
	// go client.GetCertificate()

}

func HandleGetCert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "No valid Method", http.StatusMethodNotAllowed)
		return
	}
	fmt.Println("Got Certification request")
	tokenString := r.Header.Get("Authorization")[7:]

	parsedToken, _ := jwt.Parse(tokenString, nil)

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		// handle invalid claims ?
		fmt.Println("Invalid JWT claims")
		return
	}

	publicKeyData := claims["jwk"].(map[string]interface{})
	n1, _ := publicKeyData["n"].(string)
	e1, _ := publicKeyData["e"].(string)

	n2 := new(big.Int)
	n2.SetString(n1, 10)

	e2 := new(big.Int)
	e2.SetString(e1, 10)

	recreatePubKey := &rsa.PublicKey{
		N: n2,
		E: int(e2.Int64()),
	}
	publicKeyPEM22 := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(recreatePubKey),
	}
	fmt.Println("\nPublic Key in PEM Format:")
	publicKeyString := string(pem.EncodeToMemory(publicKeyPEM22))
	fmt.Println(publicKeyString)

	//modulus := new(big.Int)
	//modulus.SetString(publicKeyJSON.n, 10)

	//frontendAppID := r.URL.Query().Get("appID")
	signedFingerprint := claims["fingerprint"].(string)
	frontendAppID := claims["sub"].(string)

	fingerprintToVerify := challenges[frontendAppID].NonceToken + challenges[frontendAppID].ID

	// here check if nonce + appID correct, every nonce needs a number for map i guess, after delete from data structure
	ver, err := server.VerifySignature(fingerprintToVerify, signedFingerprint, recreatePubKey)
	if ver {
		fmt.Println("Verification successfull")
	} else {
		fmt.Println("Unsuccessfull", err)
	}

	// Now give back jwt signed by server as response, validate at rpki endpoint at the end

}

func HandleGetChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "No valid Method", http.StatusMethodNotAllowed)
		return
	}
	fmt.Println("Got Challenge Request")

	frontendAppID := r.URL.Query().Get("appID")
	backendAppID := tableAppIDs[frontendAppID]

	nonce := server.GenerateNonce()
	if frontendAppID != "" {
		newRequest := myutils.ChallengeObject{
			ID:         backendAppID,
			NonceToken: nonce,
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
