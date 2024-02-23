package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

func main() {
	CreateKeyPair("root.key")
	marbleTemplate := Generatex509Template("Marblerun Coordinator", 200, "root")
	marbleKey, err := LoadPrivateKeyFromFile("root.key")

	marbleCertDER, err := x509.CreateCertificate(rand.Reader, &marbleTemplate, &marbleTemplate, &marbleKey.PublicKey, marbleKey)
	if err != nil {
		fmt.Println("Error creating root certificate:", err)
		return
	}
	// Create and write the root certificate to a file (root.crt)
	rootCertFile, err := os.Create("marblerunCA.crt")
	if err != nil {
		fmt.Println("Error creating root.crt file:", err)
		return
	}
	defer rootCertFile.Close()
	pem.Encode(rootCertFile, &pem.Block{Type: "CERTIFICATE", Bytes: marbleCertDER})
	fmt.Println("END of code")

	CreateMarbleCert("marbleServer.key", "marbleServerCert.crt", "marblerunCA.crt",
		"root.key", "PKI Server", 200, "intermediate")

	CreateMarbleCert("marbleClient.key", "marbleClientCert.crt", "marblerunCA.crt",
		"root.key", "PKI Client", 200, "client")
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

func LoadPublicKeyFromFile(filename string) (*rsa.PublicKey, error) {
	keyFile, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(keyFile)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("invalid private key format")
	}

	return x509.ParsePKCS1PublicKey(block.Bytes)
}

func CreateMarbleCert(keyPath string, certPath string, rootCertPath string,
	rootKeyPath string, marbleName string, validHours int, certType string) error {
	CreateKeyPair(keyPath)
	marbleKey, err := LoadPrivateKeyFromFile(keyPath)
	if err != nil {
		fmt.Println("Error loading Private Key")
	}

	rootCertPEM, err := os.ReadFile(rootCertPath)
	rootKeyPEM, err := LoadPrivateKeyFromFile(rootKeyPath)
	rootCert, err := parseCertificatePEM(rootCertPEM)
	marbleTemplate := Generatex509Template(marbleName, validHours, certType)
	marbleCertDER, err := x509.CreateCertificate(rand.Reader, &marbleTemplate, rootCert,
		&marbleKey.PublicKey, rootKeyPEM)
	if err != nil {
		fmt.Println(err)
	}
	marbleCertFile, err := os.Create(certPath)
	defer marbleCertFile.Close()

	pem.Encode(marbleCertFile, &pem.Block{Type: "CERTIFICATE", Bytes: marbleCertDER})

	return nil
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

func parseCertificatePEM(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("failed to decode PEM block containing certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing certificate: %v", err)
	}

	return cert, nil
}

func Generatex509Template(subjectName string, validHours int, certType string) x509.Certificate {
	if certType == "root" {
		certTemplate := x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{Organization: []string{subjectName}},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().Add(time.Duration(validHours) * time.Hour), // Valid for 10 years
			BasicConstraintsValid: true,
			IsCA:                  true,

			// do i need key usage fields ?
			KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			//IsCA:        true,
			//BasicConstraintsValid: true,
		}
		return certTemplate
	} else if certType == "intermediate" {
		certTemplate := x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{Organization: []string{subjectName}},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(time.Duration(validHours) * time.Hour), // Valid for 10 years

			// do i need key usage fields ?
			KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			//IsCA:        isCA,
		}
		return certTemplate
	} else {
		certTemplate := x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{Organization: []string{subjectName}},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(time.Duration(validHours) * time.Hour), // Valid for 10 years
			KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		}
		return certTemplate
	}
}
