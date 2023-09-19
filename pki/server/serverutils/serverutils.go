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
	"math/big"
	"os"
	"time"
)

func CrsToCrt(csr []byte) []byte {
	// load CA key pair
	//      public key
	caPublicKeyFile, err := os.ReadFile("server.crt")
	if err != nil {
		panic(err)
	}
	pemBlock, _ := pem.Decode(caPublicKeyFile)
	if pemBlock == nil {
		panic("pem.Decode failed")
	}
	caCRT, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		panic("bla")
	}

	//      private key
	caPrivateKey, err := loadPrivateKeyFromFile("private.key")

	// load client certificate request
	//clientCSRFile, err := os.ReadFile("client.csr")
	//if err != nil {
	//	panic(err)
	//}
	pemBlock, _ = pem.Decode(csr)
	if pemBlock == nil {
		panic("pem.Decode failed")
	}
	clientCSR, err := x509.ParseCertificateRequest(pemBlock.Bytes)
	if err != nil {
		panic(err)
	}
	if err = clientCSR.CheckSignature(); err != nil {
		panic(err)
	}

	// create client certificate template
	clientCRTTemplate := x509.Certificate{
		Signature:          clientCSR.Signature,
		SignatureAlgorithm: clientCSR.SignatureAlgorithm,

		PublicKeyAlgorithm: clientCSR.PublicKeyAlgorithm,
		PublicKey:          clientCSR.PublicKey,

		SerialNumber: big.NewInt(2),
		Issuer:       caCRT.Subject,
		Subject:      clientCSR.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	// create client certificate from template and CA public key
	clientCRTRaw, err := x509.CreateCertificate(rand.Reader, &clientCRTTemplate, caCRT, clientCSR.PublicKey, caPrivateKey)
	if err != nil {
		panic(err)
	}
	//clientCRTPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientCRTRaw})
	clientCRTFile, err := os.Create("client.crt")
	if err != nil {
		panic(err)
	}
	pem.Encode(clientCRTFile, &pem.Block{Type: "CERTIFICATE", Bytes: clientCRTRaw})
	clientCRTFile.Close()

	return clientCRTRaw
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

func GetPublicKeyFromCSR(csrPEM []byte) *rsa.PublicKey {
	data, _ := pem.Decode([]byte(csrPEM))
	if data == nil || data.Type != "CERTIFICATE REQUEST" {
		fmt.Println("Can`t decode CSR")
		return nil
	}
	csr, err := x509.ParseCertificateRequest(data.Bytes)
	if err != nil {
		fmt.Println("Can`t parse CSR", err)
		return nil
	}
	publicKey := csr.PublicKey.(*rsa.PublicKey)
	return publicKey
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
