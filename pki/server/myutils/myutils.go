package myutils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

type ChallengeObject struct {
	ID         string
	NonceToken string
}

type MyJWTClaims struct {
	typ           string
	alg           string
	frontendAppID string
	exp           string
	fingerprint   string
	jwk           myJWKClaims
}

type myJWKClaims struct {
	KeyType   string `json:"kty"`
	Usage     string `json:"use"`
	KeyID     string `json:"kid"`
	Algorithm string `json:"alg"`
	Exponent  string `json:"e"`
	Modulus   string `json:"n"`
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
