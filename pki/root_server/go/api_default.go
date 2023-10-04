/*
 * pki.in GO
 *
 * pki in API docs
 *
 * API version: 1.0.0
 * Contact: paul.goehring@student.uni-tuebingen.de
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */
package swagger

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/golang-jwt/jwt"
)

var PublicKeyMap = sync.Map{}
var challenges map[string]ChallengeObject
var tableAppIDs map[string]string

type ChallengeObject struct {
	ID         string
	URL        string
	NonceToken string
}

type PublicKeyInfo struct {
	E   string    `json:"e"`
	Kid string    `json:"kid"`
	N   string    `json:"n"`
	Use string    `json:"use"`
	Kty string    `json:"kty"`
	Alg string    `json:"alg"`
	Exp time.Time `json:"exp"`
}

type myJWKClaims struct {
	KeyType   string `json:"kty"`
	Usage     string `json:"use"`
	KeyID     string `json:"kid"`
	Algorithm string `json:"alg"`
	Exponent  string `json:"e"`
	Modulus   string `json:"n"`
}

func WellKnownCertsGet(w http.ResponseWriter, r *http.Request) {
	DeleteExpiredCerts()
	keyID := r.URL.Query().Get("kid")
	fmt.Println(keyID)
	if keyID != "" {
		GetKeyDataByKid(w, keyID)
	} else {
		ShowCerts(w)
	}
}

func GetChallengeGet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "No valid Method", http.StatusMethodNotAllowed)
		return
	}
	fmt.Println("Got Challenge Request")

	frontendAppID := r.URL.Query().Get("appID")
	backendAppID := tableAppIDs[frontendAppID]

	nonce := GenerateNonce()
	if frontendAppID != "" {
		newRequest := ChallengeObject{
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

func GetTokenGet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "No valid Method", http.StatusMethodNotAllowed)
		return
	}
	fmt.Println("Got Certification request")
	tokenString := r.Header.Get("Authorization")[7:]

	parsedToken, _ := jwt.Parse(tokenString, nil)
	privateKey, err := LoadPrivateKeyFromFile("private.key")

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

	signedFingerprint := claims["fingerprint"].(string)
	frontendAppID := claims["sub"].(string)

	fingerprintToVerify := challenges[frontendAppID].NonceToken + challenges[frontendAppID].ID

	// here check if nonce + appID correct, every nonce needs a number for map i guess, after delete from data structure
	ver, err := VerifySignature(fingerprintToVerify, signedFingerprint, recreatePubKey)
	if ver {
		fmt.Println("Verification successfull")
	} else {
		fmt.Println("Unsuccessfull", err)
		w.WriteHeader(http.StatusUnauthorized)
		message := "Access Denied: You do not have permission to access this resource."
		fmt.Fprintln(w, message)
		return
	}

	newJwt, newValidJwt := CreateJwt(privateKey, frontendAppID, recreatePubKey)

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, newJwt)

	PublicKeyMap.Store(newValidJwt.Kid, newValidJwt)

	// Now give back jwt signed by server as response, validate at rpki endpoint at the end
}

func Initialize() {
	//nonceTokens = make(map[string]int)
	// create key pair
	CreateKeyPair("private.key")

	challenges = make(map[string]ChallengeObject)
	tableAppIDs = make(map[string]string)

	PublicKeyMap = sync.Map{}

	tableAppIDs["asd123"] = "asd123"
	privateKey, _ := LoadPrivateKeyFromFile("private.key")
	publicKey := &privateKey.PublicKey
	expiration := time.Now().Add(time.Hour * 8760)
	publicKeyData := PublicKeyInfo{
		E:   strconv.Itoa(publicKey.E),
		Kid: GenerateKIDFromPublicKey(publicKey),
		N:   publicKey.N.String(),
		Use: "sig",
		Kty: "RSA",
		Alg: "RS256",
		Exp: expiration,
	}
	PublicKeyMap.Store(publicKeyData.Kid, publicKeyData)

	// create root certificate
	//createRootCert("test", "test12", "test123", "test1234", "test12345", "test123456", "ca.crt")
}

func GetKeyDataByKid(w http.ResponseWriter, kid string) {
	privateKey, err := LoadPrivateKeyFromFile("private.key")
	if err != nil {
		fmt.Println("Could not load private Key")
	}
	w.Header().Set("Content-Type", "application/json")
	PublicKeyMap.Range(func(key, value interface{}) bool {
		if key == kid {
			kidJwt := GiveKeyJwt(privateKey, value.(PublicKeyInfo))
			fmt.Fprint(w, kidJwt)
		}
		return true
	})
}

func LoadPrivateKeyFromFile(filename string) (*rsa.PrivateKey, error) {
	keyFile, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(keyFile)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("invalid private key format")
	}

	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func ShowCerts(w http.ResponseWriter) {

	// give out all valid stuff
	w.Header().Set("Content-Type", "text/plain")
	PublicKeyMap.Range(func(key, value interface{}) bool {
		fmt.Fprintf(w, "Key: %v\nValue: %+v\n", key, value)
		return true
	})

}

func DeleteExpiredCerts() {
	PublicKeyMap.Range(func(key, value interface{}) bool {
		if publicKeyInfo, ok := value.(*PublicKeyInfo); ok {
			if publicKeyInfo.Exp.Before(time.Now()) {
				PublicKeyMap.Delete(key)
			}
		}
		return true
	})
}

func CreateKeyPair(keyPath string) {
	// create and store key Pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println("Key pair could not get generated", err)
		return
	}

	// TODO: store private key securely
	privateKeyPem := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}
	err = os.WriteFile(keyPath, pem.EncodeToMemory(privateKeyPem), 0644)
	if err != nil {
		fmt.Println("Private key could not get stored", err)
		return
	}
	publicKey := &privateKey.PublicKey
	publicKeyPem := &pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(publicKey)}
	err = os.WriteFile("public.key", pem.EncodeToMemory(publicKeyPem), 0644)
	if err != nil {
		fmt.Println("Public key could not get stored", err)
	}

}

func GenerateKIDFromPublicKey(publicKey *rsa.PublicKey) string {
	hash := sha256.Sum256(publicKey.N.Bytes())
	kid := hex.EncodeToString(hash[:])
	return kid
}

func CreateJwt(privKey *rsa.PrivateKey, frontEndID string, publicKey *rsa.PublicKey) (string, PublicKeyInfo) {
	// Create a new JWT OR NEW CERT
	expiration := time.Now().Add(time.Hour * 1)
	myClaims := myJWKClaims{
		KeyType:   "RSA",
		Usage:     "sig",
		KeyID:     GenerateKIDFromPublicKey(publicKey), // here maybe hash of the key idk how this works
		Algorithm: "RS256",
		Exponent:  strconv.Itoa(publicKey.E),
		Modulus:   publicKey.N.String(),
	}
	claims := jwt.MapClaims{
		"sub": frontEndID,
		"iss": "server",
		"kid": GenerateKIDFromPublicKey(&privKey.PublicKey),
		"exp": expiration.Unix(),
		"jwk": myClaims,
	}
	publicKeyData := PublicKeyInfo{
		E:   strconv.Itoa(publicKey.E),
		Kid: GenerateKIDFromPublicKey(publicKey),
		N:   publicKey.N.String(),
		Use: "sig",
		Kty: "RSA",
		Alg: "RS256",
		Exp: expiration,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(privKey)
	if err != nil {
		return "", publicKeyData
	}
	return tokenString, publicKeyData
}

func GiveKeyJwt(privKey *rsa.PrivateKey, pubKey PublicKeyInfo) string {
	// give out specific Jwt
	claims := jwt.MapClaims{

		"e":   pubKey.E,
		"kid": pubKey.Kid,
		"n":   pubKey.N,
		"use": pubKey.Use,
		"kty": pubKey.Kty,
		"alg": pubKey.Alg,
		"exp": pubKey.Exp,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["alg"] = "RS256"
	token.Header["typ"] = "JWT"
	tokenString, err := token.SignedString(privKey)
	if err != nil {
		return "error"
	}
	return tokenString
}

func VerifySignature(token, signature string, publicKey *rsa.PublicKey) (bool, error) {
	decodedSignature, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false, err
	}

	hashed := sha256.Sum256([]byte(token))
	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed[:], decodedSignature)
	if err != nil {
		return false, nil // Verification failed
	}
	//fmt.Println(token, signature, decodedSignature, hashed)
	return true, nil // Verification successful
}

func ServerCreateJwt(privKey *rsa.PrivateKey, frontEndID string, publicKey *rsa.PublicKey) string {
	myClaims := myJWKClaims{
		KeyType:   "RSA",
		Usage:     "sig",
		KeyID:     GenerateKIDFromPublicKey(publicKey), // here maybe hash of the key idk how this works
		Algorithm: "RS256",
		Exponent:  strconv.Itoa(publicKey.E),
		Modulus:   publicKey.N.String(),
	}
	claims := jwt.MapClaims{
		"sub": frontEndID,
		"iss": "server",
		"kid": GenerateKIDFromPublicKey(&privKey.PublicKey),
		"exp": time.Now().Add(time.Hour * 1).Unix(),
		"jwk": myClaims,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(privKey)
	if err != nil {
		return ""
	}
	return tokenString
}

func GenerateNonce() string {
	// TODO check if in nonce map
	nonceBytes := make([]byte, 32)
	_, err := rand.Read(nonceBytes)
	if err != nil {
		fmt.Println("Nonce could not be generated", err)
	}
	nonce := base64.StdEncoding.EncodeToString(nonceBytes)
	//fmt.Println(nonce)
	return nonce
}
