package clientutils

import (
	"bytes"
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
	"net/http"
	"os"
)

func GetCertificate() {
	// get token
	nonceToken := getChallenge()
	challenge := string(nonceToken)
	fmt.Println(challenge)
	// upload token + proof of possession of public key(encrypt hashed appID) +
	go http.HandleFunc(fmt.Sprintf("/.well-known/acme-challenge/%v", challenge), uploadToken(nonceToken))
	go http.ListenAndServe(":443", nil)

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
	// receive certificate and store in file
	certFile, err := os.Create("server.crt")
	if err != nil {
		fmt.Println("Error creating file", err)
		return
	}
	pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: result})
	certFile.Close()
}

func uploadToken(nonceToken []byte) http.HandlerFunc {
	// TODO: encrypt hashed app id(finger print) to make proof of possession of public key
	// get app id from marblerun certificate
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "No valid Method", http.StatusMethodNotAllowed)
			return
		}
		privateKey, err := loadPrivateKeyFromFile("private.key")
		if err != nil {
			fmt.Println("Error loading private key", err)
		}
		// Use here later AppID/Fingerprint since we have token already in URL
		signedToken, err := signToken(string(nonceToken), privateKey)
		if err != nil {
			fmt.Println("Error encrypting token", err)
		}
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, signedToken)

	}

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
	request1, err := http.Get(fmt.Sprintf("http://localhost:8080/getChallenge?appID=%v", "blaAppId1"))
	if err != nil {
		fmt.Println("Could not reach Server", err)
		return nil
	}
	defer request1.Body.Close()

	nonceToken, err := io.ReadAll(request1.Body)
	fmt.Println(string(nonceToken))
	return nonceToken
}

func createCSR() []byte {

	privateKey, err := loadPrivateKeyFromFile("private.key")
	if err != nil {
		fmt.Println("Could not load Private key")
	}
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
