/*
 * pki.in GO
 *
 * pki in API docs
 *
 * API version: 1.0.0
 * Contact: paul.goehring@student.uni-tuebingen.de
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */
package swagger

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt"
)

var PublicKeys []PublicKeyInfo
var challenges map[string]ChallengeObject
var PathOwnCrt string = "root.crt"
var PathMarbleRootCrt string = "marblerunCA.crt"
var PathServerKey string = "private.key"
var PathRootCrt string = "root.crt"
var SerialNumber = big.NewInt(0)
var AppName string = "RootPkiServer"
var RootUrl string
var RootPort string

//maybe load private key and cert here for better performance

type ChallengeObject struct {
	// APP ID and Nonce Token for this App
	ID         string
	NonceToken string
}

type PublicKeyInfo struct {
	E   string    `json:"e"`
	Kid string    `json:"kid"`
	N   string    `json:"n"`
	Use string    `json:"use"`
	Kty string    `json:"kty"`
	Alg string    `json:"alg"`
	Exp time.Time `json:"exp"`
}

type KeyResponse struct {
	Keys []PublicKeyInfo `json:"keys"`
}

type myJWKClaims struct {
	KeyType   string `json:"kty"`
	Usage     string `json:"use"`
	KeyID     string `json:"kid"`
	Algorithm string `json:"alg"`
	Exponent  string `json:"e"`
	Modulus   string `json:"n"`
}

type OpenIDConfiguration struct {
	Issuer        string `json:"issuer"`
	JWKSURI       string `json:"jwks_uri"`
	TokenEndpoint string `json:"token_endpoint"`
}

func Initialize() {
	// Initializing Data structures, creating Key Pairs
	// and Certificates

	// create key pair
	CreateKeyPair(PathServerKey)

	challenges = make(map[string]ChallengeObject)
	challenges = make(map[string]ChallengeObject)

	privateKey, _ := LoadPrivateKeyFromFile(PathServerKey)
	publicKey := &privateKey.PublicKey

	RootUrl = os.Getenv("ownUrl")
	RootPort = os.Getenv("ownPort")
	if RootUrl == "" {
		RootUrl = "localhost"
	}
	if RootPort == "" {
		RootPort = "8091"
	}
	// how long own Key Pair is valid
	expiration := time.Now().Add(time.Hour * 8760)
	publicKeyData := PublicKeyInfo{
		E:   strconv.Itoa(publicKey.E),
		Kid: GenerateKIDFromPublicKey(publicKey),
		N:   publicKey.N.String(),
		Use: "sig",
		Kty: "RSA",
		Alg: "RS256",
		Exp: expiration,
	}
	PublicKeys = append(PublicKeys, publicKeyData)

	// create root certificate
	rootCert := CreateCert(SerialNumber, publicKey, "", PathServerKey, AppName, 1000, "root")

	certFile, err := os.Create(PathOwnCrt)
	if err != nil {
		fmt.Println(err)
	}
	defer certFile.Close()
	_, err = certFile.Write(rootCert)
	if err != nil {
		fmt.Println(err)
	}

}

func CreateCert(SerialNumber *big.Int, pubKey *rsa.PublicKey, signingCertPath string,
	signingKeyPath string, issuedName string, validHours int, certType string) []byte {
	// Creates a x.509 Certificate

	certTemplate := Generatex509Template(SerialNumber, issuedName, validHours, certType)
	var signingCert *x509.Certificate
	var certDER []byte
	signingKey, err := LoadPrivateKeyFromFile(signingKeyPath)
	if err != nil {
		fmt.Println("Error loading Private Key")
	}
	if signingCertPath != "" {
		signingCertPEM, err := os.ReadFile(signingCertPath)
		if err != nil {
			fmt.Println("Error loading signing Certificate")
		}
		signingCert, err = parseCertificatePEM(signingCertPEM)
		if err != nil {
			fmt.Println("Error parsing signing Certificate PEM")
		}
		certDER, err = x509.CreateCertificate(rand.Reader, &certTemplate, signingCert,
			pubKey, signingKey)
		if err != nil {
			fmt.Println("Could not Create Certificate")
		}
	} else {
		certDER, err = x509.CreateCertificate(rand.Reader, &certTemplate, &certTemplate,
			pubKey, signingKey)
		if err != nil {
			fmt.Println("Could not Create Certificate")
		}
	}

	SerialNumber.Add(SerialNumber, big.NewInt(1))
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
}

func parseCertificatePEM(certPEM []byte) (*x509.Certificate, error) {
	// parse a x.509 Certificate from a PEM file
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

func Generatex509Template(serialNumber *big.Int, subjectName string, validHours int, certType string) x509.Certificate {
	// Generates a x.509 Certificate Template
	if certType == "root" {
		certTemplate := x509.Certificate{
			SerialNumber: serialNumber,
			Subject:      pkix.Name{Organization: []string{subjectName}},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(time.Duration(validHours) * time.Hour),
			KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			IsCA:         true,
		}
		return certTemplate
	} else if certType == "intermediate" {
		certTemplate := x509.Certificate{
			SerialNumber: serialNumber,
			Subject:      pkix.Name{Organization: []string{subjectName}},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(time.Duration(validHours) * time.Hour),

			// do i need key usage fields ?
			KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			//IsCA:        isCA,
		}
		return certTemplate
	} else {
		certTemplate := x509.Certificate{
			SerialNumber: serialNumber,
			Subject:      pkix.Name{Organization: []string{subjectName}},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(time.Duration(validHours) * time.Hour),
		}
		return certTemplate
	}
}

func WellKnownConfigurationGet(w http.ResponseWriter, r *http.Request) {
	configuration := OpenIDConfiguration{
		Issuer:        "Root PKI Server",
		JWKSURI:       "http//localhost:8443/.well-known/certs", // Replace with your JWKS URI
		TokenEndpoint: "httpw//localhost:8443/.getNewCert",
	}
	w.Header().Set("Content-Type", "application/json")
	encodedConfig, err := json.MarshalIndent(configuration, "", "  ")
	if err != nil {
		http.Error(w, "Failed to marshal JSON: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(encodedConfig)
}

func WellKnownCertsGet(w http.ResponseWriter, r *http.Request) {
	// Get all valid public keys or a specific key by kid
	// if kid is given in the request
	PublicKeys = DeleteExpiredCerts(PublicKeys)
	keyID := r.URL.Query().Get("kid")

	if keyID != "" {
		GetKeyDataByKid(w, keyID)
	} else {
		ShowCerts(w)
	}
}

func GetChallengeGet(w http.ResponseWriter, r *http.Request) {
	// Get a challenge for a specific AppID and send it to the client
	if r.Method != http.MethodGet {
		http.Error(w, "No valid Method", http.StatusMethodNotAllowed)
		return
	}
	fmt.Println("Got Challenge Request")

	frontendAppID := r.URL.Query().Get("appID")

	nonce := GenerateNonce()
	if frontendAppID != "" {
		newRequest := ChallengeObject{
			ID:         frontendAppID,
			NonceToken: nonce,
		}
		challenges[frontendAppID] = newRequest
	} else {
		fmt.Println("value for AppID missing")
		nonce = "Value for AppID missing"
	}
	fmt.Printf("Sent challenge to: %v \n", frontendAppID)

	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprint(w, nonce)
}

func GetTokenGet(w http.ResponseWriter, r *http.Request) {
	// Get a new token for a specific AppID and send it to the client
	// if the client could be authenticated by the marblerun certificate
	if r.Method != http.MethodGet {
		http.Error(w, "No valid Method", http.StatusMethodNotAllowed)
		return
	}
	fmt.Println("Got Certification request")
	tokenString := r.Header.Get("Authorization")[7:]

	parsedToken, _ := jwt.Parse(tokenString, nil)
	privateKey, err := LoadPrivateKeyFromFile(PathServerKey)
	if err != nil {
		fmt.Println("Could not load private Key")
	}

	caCert, err := os.ReadFile(PathRootCrt)
	if err != nil {
		fmt.Println("Error loading CA certificate:", err)
		return
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// check if used certificate is issued by marblerun and
	// issued in last 5 min since they do not expire
	marblerunCACert, err := os.ReadFile(PathMarbleRootCrt)
	if err != nil {
		fmt.Println("Error loading marblerun CA certificate:", err)
		return
	}

	marblerunCACertPool := x509.NewCertPool()
	marblerunCACertPool.AppendCertsFromPEM(marblerunCACert)

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		fmt.Println("Invalid JWT claims")
		return
	}

	publicKeyData := claims["jwk"].(map[string]interface{})
	n1, _ := publicKeyData["n"].(string)
	e1, _ := publicKeyData["e"].(string)

	n2 := new(big.Int)
	n2.SetString(n1, 10)

	e2 := new(big.Int)
	e2.SetString(e1, 10)

	recreatePubKey := &rsa.PublicKey{
		N: n2,
		E: int(e2.Int64()),
	}
	/*
		// To Debug show Public Key
		publicKeyPEM22 := &pem.Block{
			Type:  "RSCreateJwtA PUBLIC KEY",
			Bytes: x509.MarshalPKCS1PublicKey(recreatePubKey),
		}
		fmt.Println("\nPublic Key in PEM Format:")
		publicKeyString := string(pem.EncodeToMemory(publicKeyPEM22))
		fmt.Println(publicKeyString)
	*/

	signedFingerprint := claims["fingerprint"].(string)
	frontendAppID := claims["sub"].(string)

	fingerprintToVerify := challenges[frontendAppID].NonceToken + challenges[frontendAppID].ID

	// here check if signed nonce + appID correct, after delete from data structure for further requests
	ver, err := VerifySignature(fingerprintToVerify, signedFingerprint, recreatePubKey)
	if ver {
		fmt.Println("Verification successfull")
		delete(challenges, frontendAppID)
	} else {
		fmt.Println("Unsuccessfull", err)
		w.WriteHeader(http.StatusUnauthorized)
		message := "Access Denied: You do not have permission to access this resource."
		fmt.Fprintln(w, message)
		return
	}

	newJwt, newValidJwt := CreateJwt(privateKey, frontendAppID, recreatePubKey, frontendAppID)

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, newJwt)

	// add Server Public Key to intermediate Public Keys which are valid to sign Tokens
	PublicKeys = append(PublicKeys, newValidJwt)
}

func GetKeyDataByKid(w http.ResponseWriter, kid string) {
	// Get a specific public key by kid and send it to the client
	privateKey, err := LoadPrivateKeyFromFile(PathServerKey)
	if err != nil {
		fmt.Println("Could not load private Key")
	}
	w.Header().Set("Content-Type", "application/json")
	for _, key := range PublicKeys {
		if key.Kid == kid {
			kidJwt := GiveKeyJwt(privateKey, key)
			fmt.Fprint(w, kidJwt)
		}
	}
}

func LoadPrivateKeyFromFile(filename string) (*rsa.PrivateKey, error) {
	// Load a private key from a file
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

func ShowCerts(w http.ResponseWriter) {
	// give out all valid public Keys
	response := KeyResponse{Keys: PublicKeys}

	jsonResponse, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonResponse)

}

func DeleteExpiredCerts(keys []PublicKeyInfo) []PublicKeyInfo {
	// Delete all expired public keys
	currentTime := time.Now()
	var validKeys []PublicKeyInfo
	for _, key := range keys {
		if key.Exp.After(currentTime) {
			validKeys = append(validKeys, key)
		}
	}
	return validKeys
}

func CreateKeyPair(keyPath string) {
	// create and store key Pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println("Key pair could not get generated", err)
		return
	}

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

func GenerateKIDFromPublicKey(publicKey *rsa.PublicKey) string {
	// Generate a Key ID from a public key
	hash := sha256.Sum256(publicKey.N.Bytes())
	kid := hex.EncodeToString(hash[:])
	return kid
}

func CreateJwt(privKey *rsa.PrivateKey, frontEndID string,
	publicKey *rsa.PublicKey, issuerName string) (string, PublicKeyInfo) {
	// Create a JWT for a specific AppID

	iat := time.Now()
	expiration := iat.Add(time.Hour * 1)
	myClaims := myJWKClaims{
		KeyType:   "RSA",
		Usage:     "sig",
		KeyID:     GenerateKIDFromPublicKey(publicKey),
		Algorithm: "RS256",
		Exponent:  strconv.Itoa(publicKey.E),
		Modulus:   publicKey.N.String(),
	}
	claims := jwt.MapClaims{
		"sub": frontEndID,
		"iss": fmt.Sprintf("http://%v:%v", RootUrl, RootPort),
		"iat": iat.Unix(),
		"exp": expiration.Unix(),
		"jwk": myClaims,
	}
	header := jwt.MapClaims{
		"alg": "RS256",
		"typ": "JWT",
		"kid": GenerateKIDFromPublicKey(&privKey.PublicKey),
	}
	publicKeyData := PublicKeyInfo{
		E:   strconv.Itoa(publicKey.E),
		Kid: GenerateKIDFromPublicKey(publicKey),
		N:   publicKey.N.String(),
		Use: "sig",
		Kty: "RSA",
		Alg: "RS256",
		Exp: expiration,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header = header
	tokenString, err := token.SignedString(privKey)
	if err != nil {
		return "", publicKeyData
	}
	return tokenString, publicKeyData
}

func GiveKeyJwt(privKey *rsa.PrivateKey, pubKey PublicKeyInfo) string {
	// create Jwt for a specific Key
	claims := jwt.MapClaims{
		"e":   pubKey.E,
		"kid": pubKey.Kid,
		"n":   pubKey.N,
		"use": pubKey.Use,
		"kty": pubKey.Kty,
		"alg": pubKey.Alg,
		"exp": pubKey.Exp,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["alg"] = "RS256"
	token.Header["typ"] = "JWT"
	tokenString, err := token.SignedString(privKey)
	if err != nil {
		return "error"
	}
	return tokenString
}

func VerifySignature(token, signature string, publicKey *rsa.PublicKey) (bool, error) {

	// Verify a signature for a specific token

	decodedSignature, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false, err
	}

	hashed := sha256.Sum256([]byte(token))
	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed[:], decodedSignature)
	if err != nil {
		return false, nil // Verification failed
	}

	return true, nil // Verification successful
}

func GenerateNonce() string {
	// Generate a random nonce
	nonceBytes := make([]byte, 32)
	_, err := rand.Read(nonceBytes)
	if err != nil {
		fmt.Println("Nonce could not be generated", err)
	}
	nonce := base64.StdEncoding.EncodeToString(nonceBytes)
	return nonce
}

func DefineTLSConfig() *tls.Config {
	// define TLS Config for Server Side
	// Check if Client has a valid Marblerun Certificate which was
	// issued in the last 5 minutes
	var tlsConfig *tls.Config

	ownCert, err := tls.LoadX509KeyPair(PathOwnCrt, PathServerKey)
	if err != nil {
		fmt.Println("Error Loading Server cert", err)
		return nil
	}

	caCert, err := os.ReadFile(PathRootCrt)
	// for Root PKI Same
	if err != nil {
		fmt.Println("Error loading CA certificate:", err)
		return nil
	}

	marbleCert, err := os.ReadFile(PathMarbleRootCrt)
	if err != nil {
		fmt.Println("Error loading marble root certificate:", err)
		return nil
	}

	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(marbleCert)
	certPool.AppendCertsFromPEM(caCert)

	tlsConfig = &tls.Config{
		Certificates: []tls.Certificate{ownCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    certPool,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			// Check if there are any verified chains
			if len(verifiedChains) == 0 {
				return fmt.Errorf("no verified chains found")
			}

			// Extract the leaf certificate from the first chain
			leafCert := verifiedChains[0][0]

			// Check if the "NotBefore" field of the leaf certificate is not older than 5 minutes ago
			iat := leafCert.NotBefore
			maxAge := 5 * time.Minute // Change to 5 later
			if time.Since(iat) > maxAge {
				return fmt.Errorf("client certificate is too old (issued more than 5 minutes ago)")
			}

			return nil
		},
	}
	return tlsConfig
}

func GetNewChallengeGet(w http.ResponseWriter, r *http.Request) {
	// Get a new challenge for a specific AppID and send it to the client
	if r.Method != http.MethodGet {
		http.Error(w, "No valid Method", http.StatusMethodNotAllowed)
		return
	}
	fmt.Println("Got Challenge Request")

	frontendAppID := r.URL.Query().Get("appID")

	nonce1 := GenerateNonce()

	if frontendAppID != "" {
		newRequest := ChallengeObject{
			ID:         frontendAppID,
			NonceToken: nonce1,
		}

		challenges[frontendAppID] = newRequest

		// Respond with a JSON containing both nonces
		response := map[string]string{
			"nonceNewKey": nonce1,
		}

		responseJSON, err := json.Marshal(response)
		if err != nil {
			http.Error(w, "Error encoding JSON response", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(responseJSON)
		return
	}

	fmt.Println("value for AppID missing")
	nonce := "Value for AppID missing"

	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprint(w, nonce)
}

func GetNewTokenGet(w http.ResponseWriter, r *http.Request) {
	// Get a new token for a specific AppID and send it to the client
	// after it has been authenticated with the old token

	if r.Method != http.MethodGet {
		http.Error(w, "No valid Method", http.StatusMethodNotAllowed)
		return
	}
	fmt.Println("Got Certification request")

	tokenString := r.Header.Get("Authorization")[7:]

	parsedToken, _ := jwt.Parse(tokenString, nil)

	privateKey, err := LoadPrivateKeyFromFile(PathServerKey)
	if err != nil {
		fmt.Println("Could not load private Key")
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		fmt.Println("Invalid JWT claims")
		return
	}

	oldIct, ok := claims["ict"].(string)
	if !ok {
		http.Error(w, "No ict found in request", http.StatusUnauthorized)
		return
	}

	valid, err := VerifyICT(&privateKey.PublicKey, oldIct)
	if !valid {
		fmt.Println("Unsuccessfull", err)
		w.WriteHeader(http.StatusUnauthorized)
		message := "Access Denied: You do not have permission to access this resource."
		fmt.Fprintln(w, message)
		return
	}

	parsedIct, _ := jwt.Parse(oldIct, nil)

	ictClaims, ok := parsedIct.Claims.(jwt.MapClaims)
	if !ok {
		fmt.Println("Invalid JWT claims")
		return
	}

	oldPublicKeyData := ictClaims["jwk"].(map[string]interface{})
	n1, _ := oldPublicKeyData["n"].(string)
	e1, _ := oldPublicKeyData["e"].(string)

	n2 := new(big.Int)
	n2.SetString(n1, 10)

	e2 := new(big.Int)
	e2.SetString(e1, 10)

	recreateOldPubKey := &rsa.PublicKey{
		N: n2,
		E: int(e2.Int64()),
	}

	newPublicKeyData := claims["jwk"].(map[string]interface{})
	n11, _ := newPublicKeyData["n"].(string)
	e11, _ := newPublicKeyData["e"].(string)
	n22 := new(big.Int)
	n22.SetString(n11, 10)

	e22 := new(big.Int)
	e22.SetString(e11, 10)

	recreateNewPubKey := &rsa.PublicKey{
		N: n22,
		E: int(e22.Int64()),
	}

	// check if token got signed by old key for verify old key
	signedNewFingerprint := claims["fingerprintnewkey"].(string)
	frontendAppID := claims["sub"].(string)

	newFingerprintToVerify := challenges[frontendAppID].NonceToken + challenges[frontendAppID].ID

	tokenValid, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return recreateOldPubKey, nil
	})

	if err == nil && tokenValid.Valid {
		fmt.Println("JWT is valid.")
	} else {
		fmt.Println("Unsuccessfull", err)
		w.WriteHeader(http.StatusUnauthorized)
		message := "Access Denied: You do not have permission to access this resource."
		fmt.Fprintln(w, message)
		return
	}

	ver, err := VerifySignature(newFingerprintToVerify, signedNewFingerprint, recreateNewPubKey)
	if ver {
		fmt.Println("Verification of new Key successfull")
	} else {
		fmt.Println("Unsuccessfull", err)
		w.WriteHeader(http.StatusUnauthorized)
		message := "Access Denied: You do not have permission to access this resource."
		fmt.Fprintln(w, message)
		return
	}

	newJwt, newValidJwt := CreateJwt(privateKey, frontendAppID, recreateNewPubKey, frontendAppID)

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, newJwt)

	// delete old KID from list
	oldKid := oldPublicKeyData["kid"].(string)

	PublicKeys = DeleteKeyByKid(PublicKeys, oldKid)

	// append new KID to list
	PublicKeys = append(PublicKeys, newValidJwt)

}

func DeleteKeyByKid(keys []PublicKeyInfo, kidToDelete string) []PublicKeyInfo {

	// Delete a specific public key by kid

	var updatedKeys []PublicKeyInfo

	for _, key := range keys {
		if key.Kid != kidToDelete {
			// Add keys with a different Kid to the updatedKeys array
			updatedKeys = append(updatedKeys, key)
		}
	}

	return updatedKeys
}

func VerifyICT(pubKey *rsa.PublicKey, tokenString string) (bool, error) {

	token, _ := jwt.Parse(tokenString, nil)

	kid, ok := token.Header["kid"].(string)

	if !ok {
		fmt.Println("Kid field is missing in token header or is not a string")
		return false, nil
	}

	// search publicKey in  Show Cert, root PKI can just look it up
	// get signer kid from jwt
	// recreate PublicKey
	// verify
	var publicKeyKid PublicKeyInfo
	for _, key := range PublicKeys {
		if key.Kid == kid {
			publicKeyKid = key
		}
	}
	n := new(big.Int)
	n.SetString(publicKeyKid.N, 10)
	e := new(big.Int)
	e.SetString(publicKeyKid.E, 10)
	recreatePubKey := &rsa.PublicKey{
		N: n,
		E: int(e.Int64()),
	}
	tokenValid, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return recreatePubKey, nil
	})
	if err == nil && tokenValid.Valid {
		fmt.Println("JWT is valid.")
		return true, nil
	} else {
		fmt.Println("JWT is not valid")
		return false, err
	}

}
