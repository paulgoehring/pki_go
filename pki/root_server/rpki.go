package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt"

	myutils "rpki/myutils"
	root "rpki/rootutils"
	server "rpki/serverutils"
)

var privateKey *rsa.PrivateKey
var publicKey *rsa.PublicKey
var ca *x509.Certificate
var PublicKeyMap = sync.Map{}

var challenges map[string]myutils.ChallengeObject

// store root cert and issued certs
var issued []string

// look up backend id, format is [frontendID]backendID
var tableAppIDs map[string]string

// var root cert

func main() {
	// for testing client port 80, pkis port 443, rpkis port 8080
	// listen to requests and give out challenges and if successfull issue certificates
	http.HandleFunc("/getChallenge", HandleGetChallenge)
	http.HandleFunc("/getCert", HandleGetCert)
	http.HandleFunc("/.well-known/certs", HandleCerts)
	http.ListenAndServe(":8080", nil)

	// make certificates available at ./well-known etc and delete certificates which expired

}

func init() {
	//nonceTokens = make(map[string]int)
	// create key pair
	myutils.CreateKeyPair("private.key")

	challenges = make(map[string]myutils.ChallengeObject)
	tableAppIDs = make(map[string]string)

	PublicKeyMap = sync.Map{}

	tableAppIDs["asd123"] = "asd123"

	// create root certificate
	//createRootCert("test", "test12", "test123", "test1234", "test12345", "test123456", "ca.crt")
}

func HandleGetCert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "No valid Method", http.StatusMethodNotAllowed)
		return
	}
	fmt.Println("Got Certification request")
	tokenString := r.Header.Get("Authorization")[7:]

	parsedToken, _ := jwt.Parse(tokenString, nil)
	privateKey, err := server.LoadPrivateKeyFromFile("private.key")

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

	newJwt, newValidJwt := root.CreateJwt(privateKey, frontendAppID, recreatePubKey)

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, newJwt)

	PublicKeyMap.Store(newValidJwt.Kid, newValidJwt)

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

func HandleCerts(w http.ResponseWriter, r *http.Request) {
	deleteExpiredCerts()
	keyID := r.URL.Query().Get("kid")
	fmt.Println(keyID)
	if keyID != "" {
		GetKeyDataByKid(w, keyID)
	} else {
		showCerts(w)
	}
}

func GetKeyDataByKid(w http.ResponseWriter, kid string) {
	privateKey, err := myutils.LoadPrivateKeyFromFile("private.key")
	if err != nil {
		fmt.Println("Could not load private Key")
	}
	w.Header().Set("Content-Type", "application/json")
	PublicKeyMap.Range(func(key, value interface{}) bool {
		if key == kid {
			kidJwt := root.GiveKeyJwt(privateKey, value.(root.PublicKeyInfo))
			fmt.Fprint(w, kidJwt)
		}
		return true
	})
}

func showCerts(w http.ResponseWriter) {

	// give out all valid stuff
	w.Header().Set("Content-Type", "text/plain")
	PublicKeyMap.Range(func(key, value interface{}) bool {
		fmt.Fprintf(w, "Key: %v\nValue: %+v\n", key, value)
		return true
	})

}

func displayCertificate(cert *x509.Certificate, w http.ResponseWriter) {
	// TODO: Access relevant fields
	w.Write([]byte("Subject: " + cert.Subject.CommonName + "\n"))
	w.Write([]byte("Issuer: " + cert.Issuer.CommonName + "\n"))
	w.Write([]byte("Serial Number: " + cert.SerialNumber.String() + "\n"))
	w.Write([]byte("Not Before: " + cert.NotBefore.String() + "\n"))
	w.Write([]byte("Not After: " + cert.NotAfter.String() + "\n"))
	w.Write([]byte("\n"))
}

func deleteExpiredCerts() {
	PublicKeyMap.Range(func(key, value interface{}) bool {
		if publicKeyInfo, ok := value.(*root.PublicKeyInfo); ok {
			if publicKeyInfo.Exp.Before(time.Now()) {
				PublicKeyMap.Delete(key)
			}
		}
		return true
	})
}
