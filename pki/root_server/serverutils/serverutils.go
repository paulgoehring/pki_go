package serverutils

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
)

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
