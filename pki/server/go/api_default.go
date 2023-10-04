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
	"io"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt"
)

// maybe add expire date for challenge
var challenges map[string]ChallengeObject

// look up backend id, format is [frontendID]backendID
var tableAppIDs map[string]string

type myJWKClaims struct {
	KeyType   string `json:"kty"`
	Usage     string `json:"use"`
	KeyID     string `json:"kid"`
	Algorithm string `json:"alg"`
	Exponent  string `json:"e"`
	Modulus   string `json:"n"`
}

type ChallengeObject struct {
	ID         string
	NonceToken string
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

	//modulus := new(big.Int)
	//modulus.SetString(publicKeyJSON.n, 10)

	//frontendAppID := r.URL.Query().Get("appID")
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

	newJwt := CreateJwt(privateKey, frontendAppID, recreatePubKey)

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, newJwt)

	// Now give back jwt signed by server as response, validate at rpki endpoint at the end
}

func Initialize() {
	// create key pair
	CreateKeyPair("private.key")
	challenges = make(map[string]ChallengeObject)
	tableAppIDs = make(map[string]string)

	tableAppIDs["asd123"] = "asd123"

	// get certificate from root pkis
	// same as in client
	go GetCertificate()
}

func GetCertificate() {
	// placeholder
	appID := "asd123"
	nonceToken := GetChallenge()
	challenge := string(nonceToken)

	fmt.Println("Request Token")

	fingerprint := challenge + appID
	privateKey, err := LoadPrivateKeyFromFile("private.key")
	if err != nil {
		fmt.Println("Error loading private key", err)
	}

	signedToken, err := SignToken(fingerprint, privateKey)
	if err != nil {
		fmt.Println("Error signing token", err)
	}

	newJwt, err := ClientCreateJwt(privateKey, signedToken, appID)
	if err != nil {
		fmt.Println("Error creating JWT token", err)
	}
	fmt.Println(newJwt)

	req, err := http.NewRequest("GET", "http://localhost:8080/getCert", nil)
	req.Header.Set("Authorization", "Bearer "+newJwt)
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)

	fmt.Println("Response: ")
	fmt.Println(string(body))

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

func GenerateKIDFromPublicKey(publicKey *rsa.PublicKey) string {
	hash := sha256.Sum256(publicKey.N.Bytes())
	kid := hex.EncodeToString(hash[:])
	return kid
}

func CreateJwt(privKey *rsa.PrivateKey, frontEndID string, publicKey *rsa.PublicKey) string {
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

func ClientCreateJwt(privKey *rsa.PrivateKey, fingerprint string, frontEndID string) (string, error) {
	myClaims := myJWKClaims{
		KeyType:   "RSA",
		Usage:     "sig",
		KeyID:     GenerateKIDFromPublicKey(&privKey.PublicKey),
		Algorithm: "RS256",
		Exponent:  strconv.Itoa(privKey.PublicKey.E),
		Modulus:   privKey.PublicKey.N.String(),
	}
	claims := jwt.MapClaims{
		"sub":         frontEndID,
		"iss":         "client",
		"fingerprint": fingerprint,
		"exp":         time.Now().Add(time.Hour * 1).Unix(),
		"jwk":         myClaims,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(privKey)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func SignToken(token string, privateKey *rsa.PrivateKey) (string, error) {
	hashed := sha256.Sum256([]byte(token))
	result, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return "Could not sign Token", err
	}
	encodedResult := base64.StdEncoding.EncodeToString(result)
	return encodedResult, nil

}

func GetChallenge() []byte {
	request1, err := http.Get(fmt.Sprintf("http://localhost:8080/getChallenge?appID=%v", "asd123"))
	if err != nil {
		fmt.Println("Could not reach Server", err)
		return nil
	}
	defer request1.Body.Close()

	nonceToken, err := io.ReadAll(request1.Body)
	fmt.Println(fmt.Sprintf("Got Challenge: %v", string(nonceToken)))
	return nonceToken
}
