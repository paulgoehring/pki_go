package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"sync"
	"time"

	myutils "rpki/myutils"
	server "rpki/serverutils"
)

var privateKey *rsa.PrivateKey
var publicKey *rsa.PublicKey
var ca *x509.Certificate
var (
	certificatesMutex sync.RWMutex
	validCertificates []*x509.Certificate
)

var challenges map[string]myutils.ChallengeObject

// store root cert and issued certs
var issued []string

// var root cert

func main() {
	// for testing client port 80, pkis port 443, rpkis port 8080
	// listen to requests and give out challenges and if successfull issue certificates
	http.HandleFunc("/getChallenge", HandleGetChallenge)
	http.HandleFunc("/getCert", handleGetCert)
	http.HandleFunc("/.well-known/certs", showCerts)
	http.ListenAndServe(":8080", nil)

	// make certificates available at ./well-known etc and delete certificates which expired

}

func init() {
	//nonceTokens = make(map[string]int)
	// create key pair
	myutils.CreateKeyPair("private.key")

	challenges = make(map[string]myutils.ChallengeObject)

	// create root certificate
	createRootCert("test", "test12", "test123", "test1234", "test12345", "test123456", "ca.crt")
}

func createRootCert(organization string, country string, province string, locality string, streedAddress string, postalCode string, crtPath string) {
	// creates a root certificate and stores it under
	// create (Root)Signing - Certificate template
	privateKey, err := myutils.LoadPrivateKeyFromFile("private.key")
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

	address := r.RemoteAddr
	// verify if appID is valid ID(valid Hash)
	//appID := challenges[address].ID
	nonceToken := challenges[address].NonceToken

	// here has to be url from challenger
	request1, err := http.Get(fmt.Sprintf("http://localhost:443//.well-known/acme-challenge/%v", nonceToken))
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
	publicKey1 := server.GetPublicKeyFromCSR(csrPem)

	// TODO fix this mess, make it work

	ver, err := server.VerifySignature(nonceToken, fingerprintString, publicKey1)
	if ver == false {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Println("could not verify")
		fmt.Println("nonce:", nonceToken)
		fmt.Println("finger:", fingerprintString)
		//fmt.Print(ver, publicKey, csrPem)

		fmt.Fprint(w, string("Could not verify"))
		return
	}

	if err != nil {
		http.Error(w, "Error reading request Body", http.StatusInternalServerError)
	}

	certBytes := server.CrsToCrt(csrPem)
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

func HandleGetChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "No valid Method", http.StatusMethodNotAllowed)
		return
	}

	address := r.RemoteAddr
	appID := r.URL.Query().Get("appID")
	nonce := server.GenerateNonce()

	if appID != "" {
		newRequest := myutils.ChallengeObject{
			ID:         appID,
			URL:        address,
			NonceToken: nonce,
		}
		fmt.Println(newRequest.ID, newRequest.URL, newRequest.NonceToken)
		challenges[address] = newRequest
	} else {
		fmt.Println("value for AppID missing")
		nonce = "Value for AppID missing"
	}

	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprint(w, nonce)

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
