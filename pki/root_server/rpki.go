package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"sync"
	"time"
)

var privateKey *rsa.PrivateKey
var publicKey *rsa.PublicKey
var ca *x509.Certificate
var nonceTokenNew string = ""
var (
	certificatesMutex sync.RWMutex
	validCertificates []*x509.Certificate
)

// store root cert and issued certs
var issued []string

// var root cert

func main() {

	// listen to requests and give out challenges and if successfull issue certificates
	http.HandleFunc("/getChallenge", handleGetChallenge)
	http.HandleFunc("/getCert", handleGetCert)
	http.HandleFunc("/.well-known/certs", showCerts)
	http.ListenAndServe(":8080", nil)

	// make certificates available at ./well-known etc and delete certificates which expired

}

func init() {
	//nonceTokens = make(map[string]int)
	// create key pair
	createKeyPair("private.key")

	// create root certificate
	createRootCert("test", "test12", "test123", "test1234", "test12345", "test123456", "ca.crt")
}

func createKeyPair(keyPath string) {
	// create and store key Pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println("Key pair could not get generated", err)
		return
	}
	publicKey = &privateKey.PublicKey
	//fmt.Println(publicKey)
	// TODO: store private key securely
	privateKeyPem := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}
	err = os.WriteFile(keyPath, pem.EncodeToMemory(privateKeyPem), 0644)
	if err != nil {
		fmt.Println("Private key could not get stored", err)
		return
	}

}

func createRootCert(organization string, country string, province string, locality string, streedAddress string, postalCode string, crtPath string) {
	// creates a root certificate and stores it under
	// create (Root)Signing - Certificate template
	privateKey, err := loadPrivateKeyFromFile("private.key")
	publicKey := &privateKey.PublicKey
	//fmt.Println(publicKey, privateKey)
	ca := createCertificateTemplate(organization, country, province, locality, streedAddress, postalCode)
	certCa, err := x509.CreateCertificate(rand.Reader, ca, ca, publicKey, privateKey)
	if err != nil {
		fmt.Println("create ca failed", err)
		return
	}
	// Store Certificate
	certOut, err := os.Create(crtPath)
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certCa})
	certOut.Close()
	fmt.Print("written cert\n")

	cert, err := x509.ParseCertificate(certCa)
	if err != nil {
		return
	}
	certificatesMutex.Lock()
	defer certificatesMutex.Unlock()
	validCertificates = append(validCertificates, cert)

}

func handleGetCert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "No valid Method", http.StatusMethodNotAllowed)
		return
	}
	// get parameters: pubKey , id and token
	//publicKey := r.URL.Query().Get("pubKey")

	// here has to be url from challenger
	request1, err := http.Get(fmt.Sprintf("http://localhost:443//.well-known/acme-challenge/%v", nonceTokenNew))
	if err != nil {
		fmt.Println("Could not reach Server", err)
		return
	}
	defer request1.Body.Close()
	// here check results
	signedFingerprint, err := io.ReadAll(request1.Body)
	fingerprintString := string(signedFingerprint)

	// check here if token and request stuff is in database
	// if yes send back signed cert and delete from data
	// challenge: encrypted app id (fingerabdruck) under the link of token

	csrPem, err := io.ReadAll(r.Body)
	publicKey1 := getPublicKeyFromCSR(csrPem)

	// TODO fix this mess, make it work

	ver, err := verifySignature(nonceTokenNew, fingerprintString, publicKey1)
	if ver == false {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Println("could not verify")
		fmt.Println("nonce:", nonceTokenNew)
		fmt.Println("finger:", fingerprintString)
		//fmt.Print(ver, publicKey, csrPem)

		fmt.Fprint(w, string("Could not verify"))
		return
	}

	if err != nil {
		http.Error(w, "Error reading request Body", http.StatusInternalServerError)
	}

	certBytes := crsToCrt(csrPem)
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return
	}
	certificatesMutex.Lock()
	defer certificatesMutex.Unlock()
	// delete all expired Certificates in Data structure
	validCertificates = deleteExpiredCerts(validCertificates)
	validCertificates = append(validCertificates, cert)
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.WriteHeader(http.StatusOK)
	w.Write(certBytes)
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

func verifySignature(token, signature string, publicKey *rsa.PublicKey) (bool, error) {
	decodedSignature, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false, err
	}

	hashed := sha256.Sum256([]byte(token))
	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed[:], decodedSignature)
	if err != nil {
		return false, nil // Verification failed
	}
	fmt.Println(token, signature, decodedSignature, hashed)
	return true, nil // Verification successful
}

func getPublicKeyFromCSR(csrPEM []byte) *rsa.PublicKey {
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

func handleGetChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "No valid Method", http.StatusMethodNotAllowed)
		return
	}
	nonce := generateNonce() // maybe save additional data with nonce to id 100%
	// open here http listener for challenge maybe???
	//nonceTokens[noncesCount] = nonce
	//noncesCount = noncesCount + 1
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprint(w, nonce)

}

func generateNonce() string {
	// TODO check if in nonce map
	nonceBytes := make([]byte, 32)
	_, err := rand.Read(nonceBytes)
	if err != nil {
		fmt.Println("Nonce could not be generated", err)
	}
	nonce := base64.StdEncoding.EncodeToString(nonceBytes)
	fmt.Println(nonce)
	nonceTokenNew = nonce
	return nonce
}

func createCertificateTemplate(organization string, country string, province string, locality string, streedAddress string, postalCode string) *x509.Certificate {
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1653),
		Subject: pkix.Name{
			Organization:  []string{organization},
			Country:       []string{country},
			Province:      []string{province},
			Locality:      []string{locality},
			StreetAddress: []string{streedAddress},
			PostalCode:    []string{postalCode},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	return ca

}

// make data structure for dns/ip data or whatever and nonce challenge and if request comes from this url then look up nonce and try to get it
func crsToCrt(csr []byte) []byte {
	// load CA key pair
	//      public key
	caPublicKeyFile, err := os.ReadFile("ca.crt")
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

func showCerts(w http.ResponseWriter, r *http.Request) {
	certificatesMutex.RLock()
	defer certificatesMutex.RUnlock()
	w.Header().Set("Content-Type", "text/plain")
	for _, cert := range validCertificates {
		displayCertificate(cert, w)
		w.Write([]byte("/n/n"))
	}
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

func deleteExpiredCerts(certificates []*x509.Certificate) []*x509.Certificate {
	currentTime := time.Now()
	var filtered []*x509.Certificate

	for _, cert := range certificates {
		if currentTime.Before(cert.NotAfter) {
			filtered = append(filtered, cert)
		}
	}

	return filtered
}
