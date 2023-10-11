package clientutils

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
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt"
)

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

	newJwt, err := createJwt(privateKey, signedToken, appID)
	if err != nil {
		fmt.Println("Error creating JWT token", err)
	}
	fmt.Println(newJwt)

	req, err := http.NewRequest("GET", "http://localhost:8081/getCert", nil)
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

func SignToken(token string, privateKey *rsa.PrivateKey) (string, error) {
	hashed := sha256.Sum256([]byte(token))
	result, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return "Could not sign Token", err
	}
	encodedResult := base64.StdEncoding.EncodeToString(result)
	return encodedResult, nil

}

type myJWKClaims struct {
	KeyType   string `json:"kty"`
	Usage     string `json:"use"`
	KeyID     string `json:"kid"`
	Algorithm string `json:"alg"`
	Exponent  string `json:"e"`
	Modulus   string `json:"n"`
}

func GenerateKIDFromPublicKey(publicKey *rsa.PublicKey) string {
	hash := sha256.Sum256(publicKey.N.Bytes())
	kid := hex.EncodeToString(hash[:])
	return kid
}

func createJwt(privKey *rsa.PrivateKey, fingerprint string, frontEndID string) (string, error) {
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

func GetChallenge() []byte {
	request1, err := http.Get(fmt.Sprintf("http://localhost:8081/getChallenge?appID=%v", "asd123"))
	if err != nil {
		fmt.Println("Could not reach Server", err)
		return nil
	}
	defer request1.Body.Close()

	nonceToken, err := io.ReadAll(request1.Body)
	fmt.Println(fmt.Sprintf("Got Challenge: %v", string(nonceToken)))
	return nonceToken
}

// maybe utils
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
