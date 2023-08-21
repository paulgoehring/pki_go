package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"time"
)

// for testing client port 80, pkis port 443, rpkis port 8080

var privateKey *rsa.PrivateKey
var publicKey *rsa.PublicKey
var nonceTokenNew string = ""

func main() {

	// listen to requests and issue certificates
	http.HandleFunc("/getChallenge", handleGetChallenge)
	http.HandleFunc("/getCert", handleGetCert)
	http.ListenAndServe(":443", nil)

	// when certificate expired request new certificate

}

func init() {
	// create key pair
	createKeyPair("private.key")

	// get certificate from root pkis
	// same as in client
	go getCertificate()

}

func IssueCertificate(template *x509.Certificate, parent *x509.Certificate, publicKeyToSign any, privateKeySign any) []byte {
	cert, err := x509.CreateCertificate(rand.Reader, template, parent, publicKeyToSign, privateKeySign)
	if err != nil {
		fmt.Println("Failed to Create certificate for %v", publicKeyToSign, err)
		return nil
	}
	return cert
}

func handleGetCert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "No valid Method", http.StatusMethodNotAllowed)
		return
	}
	// get parameters: pubKey , id and token
	//publicKey := r.URL.Query().Get("pubKey")

	// here has to be url from challenger
	request1, err := http.Get(fmt.Sprintf("http://localhost:80//.well-known/acme-challenge/%v", nonceTokenNew))
	if err != nil {
		fmt.Println("Could not reach Server", err)
		return
	}
	defer request1.Body.Close()
	// here check results
	//signedFingerprint, err := io.ReadAll(request1.Body)
	//fingerprintString := string(signedFingerprint)

	// check here if token and request stuff is in database
	// if yes send back signed cert and delete from data
	// challenge: encrypted app id (fingerabdruck) under the link of token

	csrPem, err := io.ReadAll(r.Body)
	//publicKey := getPublicKeyFromCSR(csrPem)

	// TODO fix this mess, make it work

	//ver, err := verifySignature(nonceTokenNew, fingerprintString, publicKey)
	//if ver == false {
	//	w.Header().Set("Content-Type", "text/plain")
	//	fmt.Println("could not verify")
	//	fmt.Print(ver, publicKey, csrPem)

	//	fmt.Fprint(w, string("Could not verify"))
	//	return
	//}

	if err != nil {
		http.Error(w, "Error reading request Body", http.StatusInternalServerError)
	}

	w.Header().Set("Content-Type", "application/x-pem-file")
	w.WriteHeader(http.StatusOK)
	w.Write(crsToCrt(csrPem))
}

// make data structure for dns/ip data or whatever and nonce challenge and if request comes from this url then look up nonce and try to get it
func crsToCrt(csr []byte) []byte {
	// load CA key pair
	//      public key
	caPublicKeyFile, err := os.ReadFile("ica.crt")
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

func createKeyPair(keyPath string) {
	// create and store key Pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println("Key pair could not get generated", err)
		return
	}
	publicKey := &privateKey.PublicKey
	fmt.Println(publicKey)
	// TODO: store private key securely
	privateKeyPem := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}
	err = os.WriteFile(keyPath, pem.EncodeToMemory(privateKeyPem), 0644)
	if err != nil {
		fmt.Println("Private key could not get stored", err)
		return
	}

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

func getCertificate() {
	// get token
	nonceToken := getChallenge()
	challenge := string(nonceToken)
	fmt.Println(challenge)
	// upload token + proof of possession +
	go http.HandleFunc(fmt.Sprintf("/.well-known/acme-challenge/%v", challenge), uploadToken(nonceToken))
	go http.ListenAndServe(":443", nil)
	//time.Sleep(10 * time.Second)
	// create csr and send it
	csrPEM := createCSR()
	fmt.Println(csrPEM)
	request, err := http.Post("http://localhost:8080/getCert", "application/x-pem-file", bytes.NewReader(csrPEM))
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
	certFile, err := os.Create("ica.crt")
	if err != nil {
		fmt.Println("Error creating file", err)
		return
	}
	pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: result})
	certFile.Close()
}

func getChallenge() []byte {
	request1, err := http.Get("http://localhost:8080/getChallenge")
	if err != nil {
		fmt.Println("Could not reach Server", err)
		return nil
	}
	defer request1.Body.Close()

	nonceToken, err := io.ReadAll(request1.Body)
	return nonceToken
}

func uploadToken(nonceToken []byte) http.HandlerFunc { //this maybe async or else probably blocking
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "No valid Method", http.StatusMethodNotAllowed)
			return
		}
		//privateKey, err := loadPrivateKeyFromFile("private_client.key")
		//if err != nil {
		//	fmt.Println("Error loading private key", err)
		//}
		//encryptedToken, err := encryptToken(privateKey, nonceToken)
		//if err != nil {
		//	fmt.Println("Error encrypting token", err)
		//}
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, string(nonceToken)) // upload here finger print, proof of possession
		// public key should be sent earlier

	}

}

func createCSR() []byte {
	//privateKey, err := loadPrivateKeyFromFile("private_client.key")
	//if err != nil {
	//	fmt.Println("Could not load Private key")
	//}
	privateKey, err := loadPrivateKeyFromFile("private.key")
	data := pkix.Name{
		Country:            []string{"TESTESTETSTSAT"},
		Organization:       []string{"tetasdasd"},
		OrganizationalUnit: []string{"asdasdasd"},
		CommonName:         "localhost.com",
	}
	template := x509.CertificateRequest{
		Subject:            data,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &template, privateKey)
	if err != nil {
		fmt.Println("Error creating CSR:", err)
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})
	return csrPEM

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
