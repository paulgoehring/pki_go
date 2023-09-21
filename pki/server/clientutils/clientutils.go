package clientutils

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
)

func GetCertificate() {
	// placeholder
	appID := "asd123"
	nonceToken := getChallenge()
	challenge := string(nonceToken)
	fmt.Println("Request Token")

	fingerprint := challenge + appID
	privateKey, err := loadPrivateKeyFromFile("private.key")
	if err != nil {
		fmt.Println("Error loading private key", err)
	}
	signedToken, err := signToken(fingerprint, privateKey)
	request, err := http.Get((fmt.Sprintf("http://localhost:8080/getCert?fingerprint=%v", signedToken)))
	if err != nil {
		fmt.Println("Could not reach Server", err)
		return
	}
	defer request.Body.Close()
	result, err := io.ReadAll(request.Body)
	if err != nil {
		fmt.Println("Bad result", err)
		return
	}
	fmt.Println("Token is:")
	fmt.Println(result)
	fmt.Println(string(result))

}

func signToken(token string, privateKey *rsa.PrivateKey) (string, error) {
	hashed := sha256.Sum256([]byte(token))
	result, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return "Could not sign Token", err
	}
	encodedResult := base64.StdEncoding.EncodeToString(result)
	return encodedResult, nil

}

func getChallenge() []byte {
	request1, err := http.Get(fmt.Sprintf("http://localhost:443/getChallenge?appID=%v", "asd123"))
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
func loadPrivateKeyFromFile(filename string) (*rsa.PrivateKey, error) {
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
