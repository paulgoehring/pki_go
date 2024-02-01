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
var tableAppIDs map[string]string
var PathOwnCrt string = "root.crt"
var PathMarbleRootCrt string = "marblerunCA.crt"
var PathServerKey string = "private.key"
var PathRootCrt string = "root.crt"
var SerialNumber = big.NewInt(0)
var AppName string = "RootPkiServer"
var PemCertChain []string

var challengesRenew map[string]ChallengeObjectRenew

//maybe load private key and cert here for better performance

type ChallengeObject struct {
	// APP ID and Nonce Token for this App
	ID         string
	NonceToken string
}

type ChallengeObjectRenew struct {
	ID               string
	NonceTokenOldKey string
	NonceTokenNewKey string
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

func Initialize() {
	//nonceTokens = make(map[string]int)
	// create key pair
	CreateKeyPair("private.key")

	challenges = make(map[string]ChallengeObject)
	challengesRenew = make(map[string]ChallengeObjectRenew)
	tableAppIDs = make(map[string]string)

	// TODO: List of valid APP IDs, search in marble cert !!
	tableAppIDs["asd123"] = "asd123"
	privateKey, _ := LoadPrivateKeyFromFile("private.key")
	publicKey := &privateKey.PublicKey
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
	fmt.Println(PublicKeys)
	fmt.Println(publicKeyData)

	// create root certificate
	rootCert := CreateCert(SerialNumber, publicKey, "", "private.key", "RPKI", 1000, "root")
	//createRootCert("test", "test12", "test123", "test1234", "test12345", "test123456", "ca.crt")
	certFile, err := os.Create(PathOwnCrt)
	if err != nil {
		fmt.Println(err)
	}
	defer certFile.Close()
	_, err = certFile.Write(rootCert)
	if err != nil {
		fmt.Println(err)
	}

	// root cert not necessary needed
	//PemCertChain = append(PemCertChain, base64.StdEncoding.EncodeToString(rootCert))

}

func CreateCert(SerialNumber *big.Int, pubKey *rsa.PublicKey, signingCertPath string,
	signingKeyPath string, issuedName string, validHours int, certType string) []byte {

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
	} else {
		certDER, err = x509.CreateCertificate(rand.Reader, &certTemplate, &certTemplate,
			pubKey, signingKey)
	}

	SerialNumber.Add(SerialNumber, big.NewInt(1))
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
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

func Generatex509Template(serialNumber *big.Int, subjectName string, validHours int, certType string) x509.Certificate {
	if certType == "root" {
		certTemplate := x509.Certificate{
			SerialNumber: serialNumber,
			Subject:      pkix.Name{Organization: []string{subjectName}},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(time.Duration(validHours) * time.Hour), // Valid for 10 years

			// do i need key usage fields ?
			KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			IsCA:        true,
		}
		return certTemplate
	} else if certType == "intermediate" {
		certTemplate := x509.Certificate{
			SerialNumber: serialNumber,
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
			SerialNumber: serialNumber,
			Subject:      pkix.Name{Organization: []string{subjectName}},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(time.Duration(validHours) * time.Hour), // Valid for 10 years
		}
		return certTemplate
	}
}

func WellKnownCertsGet(w http.ResponseWriter, r *http.Request) {
	PublicKeys = DeleteExpiredCerts(PublicKeys)
	keyID := r.URL.Query().Get("kid")
	fmt.Println(keyID)
	if keyID != "" {
		GetKeyDataByKid(w, keyID)
	} else {
		ShowCerts(w)
	}
}

func GetChallengeGet(w http.ResponseWriter, r *http.Request) {
	// TODO: add query parameter new PubKey
	// check if appID in marble cert valid
	// app ID not needed, since coordinator just gives certificates to valid apps
	if r.Method != http.MethodGet {
		http.Error(w, "No valid Method", http.StatusMethodNotAllowed)
		return
	}
	fmt.Println("Got Challenge Request")

	frontendAppID := r.URL.Query().Get("appID")
	// backendAppID := tableAppIDs[frontendAppID]

	nonce := GenerateNonce()
	if frontendAppID != "" {
		// maybe check here for valid appid and just give challenges for valid ones
		// check if valid in marblerun x509, better
		newRequest := ChallengeObject{
			// ID: backendAppID,
			ID:         frontendAppID,
			NonceToken: nonce,
		}
		//fmt.Println(newRequest.ID, newRequest.URL, newRequest.NonceToken)
		challenges[frontendAppID] = newRequest
	} else {
		fmt.Println("value for AppID missing")
		nonce = "Value for AppID missing"
	}
	fmt.Println(fmt.Sprintf("Sent challenge: %v", nonce))

	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprint(w, nonce)
}

func GetTokenGet(w http.ResponseWriter, r *http.Request) {
	// wrap in correct tls method, check for root stuff,
	if r.Method != http.MethodGet {
		http.Error(w, "No valid Method", http.StatusMethodNotAllowed)
		return
	}
	fmt.Println("Got Certification request")
	tokenString := r.Header.Get("Authorization")[7:]

	parsedToken, _ := jwt.Parse(tokenString, nil)
	privateKey, err := LoadPrivateKeyFromFile("private.key")

	/*
		serverCert, err := tls.LoadX509KeyPair(PathServerCrt, PathServerKey)
		if err != nil {
			fmt.Println("Error loading server certificate:", err)
			return
		}
	*/
	caCert, err := os.ReadFile(PathRootCrt)
	if err != nil {
		fmt.Println("Error loading CA certificate:", err)
		return
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// on Marblerun Certificates check additional if they are
	// issued in last 5 min since they do not expire
	marblerunCACert, err := os.ReadFile(PathMarbleRootCrt)
	if err != nil {
		fmt.Println("Error loading marblerun CA certificate:", err)
		return
	}

	marblerunCACertPool := x509.NewCertPool()
	marblerunCACertPool.AppendCertsFromPEM(marblerunCACert)

	// Create a TLS configuration for the server
	/*tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caCertPool,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			// Perform additional checks only on certificates issued by a specific CA
			for _, chain := range verifiedChains {
				for _, cert := range chain {
					// Check if the certificate is issued by the specific CA
					if marblerunCACert.Issuer == cert.Issuer {
						// Additional checks on certificates from the specific CA
						if time.Now().After(cert.NotAfter) || time.Now().Before(cert.NotBefore) {
							return fmt.Errorf("client certificate from specific CA is expired or not yet valid")
						}
						// Add more checks as needed
					}
				}
			}
			return nil
		},
	}
	*/

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		// handle invalid claims ?
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
	publicKeyPEM22 := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(recreatePubKey),
	}
	fmt.Println("\nPublic Key in PEM Format:")
	publicKeyString := string(pem.EncodeToMemory(publicKeyPEM22))
	fmt.Println(publicKeyString)

	signedFingerprint := claims["fingerprint"].(string)
	frontendAppID := claims["sub"].(string)

	fingerprintToVerify := challenges[frontendAppID].NonceToken + challenges[frontendAppID].ID

	// here check if nonce + appID correct, every nonce needs a number for map i guess, after delete from data structure
	ver, err := VerifySignature(fingerprintToVerify, signedFingerprint, recreatePubKey)
	if ver {
		fmt.Println("Verification successfull")
	} else {
		fmt.Println("Unsuccessfull", err)
		w.WriteHeader(http.StatusUnauthorized)
		message := "Access Denied: You do not have permission to access this resource."
		fmt.Fprintln(w, message)
		return
	}

	newCert := base64.StdEncoding.EncodeToString(CreateCert(SerialNumber, recreatePubKey, PathOwnCrt, PathServerKey,
		frontendAppID, 1, "intermediate"))
	newJwt, newValidJwt := CreateJwt(privateKey, frontendAppID, recreatePubKey, newCert, PemCertChain)

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, newJwt)

	PublicKeys = append(PublicKeys, newValidJwt)

	// Now give back jwt signed by server as response, validate at rpki endpoint at the end
}

func GetKeyDataByKid(w http.ResponseWriter, kid string) {
	privateKey, err := LoadPrivateKeyFromFile("private.key")
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

	// give out all valid stuff
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

func GenerateKIDFromPublicKey(publicKey *rsa.PublicKey) string {
	hash := sha256.Sum256(publicKey.N.Bytes())
	kid := hex.EncodeToString(hash[:])
	return kid
}

func CreateJwt(privKey *rsa.PrivateKey, frontEndID string,
	publicKey *rsa.PublicKey, issuedCert string, certChain []string) (string, PublicKeyInfo) {
	// x5cField := append([]string{issuedCert}, certChain...)
	// Create a new JWT OR NEW CERT
	// TODO: add CertChain and Certificate claims (in header?)
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
		"iss": "server",
		"kid": GenerateKIDFromPublicKey(&privKey.PublicKey),
		"iat": iat.Unix(),        // maybe without Unix?
		"exp": expiration.Unix(), // maybe without unix
		"jwk": myClaims,
	}
	header := jwt.MapClaims{
		"alg":    "RS256",
		"typ":    "JWT",
		"x5c":    certChain,  // x5cField certificate Chain to validate jwt and if certificate needed
		"x5cert": issuedCert, // maybe move to claims
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
	// give out specific Jwt
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

/*
func ServerCreateJwt(privKey *rsa.PrivateKey, frontEndID string, publicKey *rsa.PublicKey) string {
	// add Certchain and certificate in header? check which create JWT is needed
	myClaims := myJWKClaims{
		KeyType:   "RSA",
		Usage:     "sig",
		KeyID:     GenerateKIDFromPublicKey(publicKey), // here maybe hash of the key idk how this works
		Algorithm: "RS256",
		Exponent:  strconv.Itoa(publicKey.E),
		Modulus:   publicKey.N.String(),
	}
	claims := jwt.MapClaims{
		"sub": frontEndID,
		"iss": "server",
		"kid": GenerateKIDFromPublicKey(&privKey.PublicKey),
		"exp": time.Now().Add(time.Hour * 1).Unix(),
		"jwk": myClaims,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(privKey)
	if err != nil {
		return ""
	}
	return tokenString
}
*/

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

/*
func ApplyMTLSConfig(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var tlsConfig *tls.Config

		ownCert, err := tls.LoadX509KeyPair(PathOwnCrt, PathServerKey)
		if err != nil {
			fmt.Println("Error Loading Server cert", err)
			return
		}

		caCert, err := os.ReadFile(PathRootCrt)
		// for Root PKI Same
		if err != nil {
			fmt.Println("Error loading CA certificate:", err)
			return
		}

		marbleCert, err := os.ReadFile(PathMarbleRootCrt)
		if err != nil {
			fmt.Println("Error loading marble root certificate:", err)
			return
		}

		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		marbleCaCertPool := x509.NewCertPool()
		marbleCaCertPool.AppendCertsFromPEM(marbleCert)

		// Check if the "renew" query parameter is present
		if r.URL.Query().Get("renew") == "true" {
			// Apply a custom mTLS configuration for renewal
			fmt.Println("Applying custom mTLS configuration for renewal")
			// Configure TLS for renewal...
			tlsConfig = &tls.Config{
				Certificates: []tls.Certificate{ownCert},
				ClientAuth: tls.RequireAndVerifyClientCert,
				ClientCAs: caCertPool,
			}
		} else {
			// Apply the default mTLS configuration
			fmt.Println("Applying default mTLS configuration")
			// Configure default TLS...
			tlsConfig = &tls.Config{
				Certificates: []tls.Certificate{ownCert},
				ClientAuth:   tls.RequireAndVerifyClientCert,
				ClientCAs:    marbleCaCertPool,
				VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
					// Perform additional checks on the client certificate
					for _, chain := range verifiedChains {
						for _, cert := range chain {
							// Check if the "iat" field is not older than 5 minutes ago
							iat := cert.NotBefore
							maxAge := 5 * time.Minute
							if time.Since(iat) > maxAge {
								return fmt.Errorf("client certificate is too old (issued more than 5 minutes ago)")
							}
						}
					}
					return nil
				},
			}

		}
		r.TLSConfig = tlsConfig

		// Call the next handler in the chain
		next.ServeHTTP(w, r)
	})

} */

func DefineTLSConfig() *tls.Config {
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
	certPool.AppendCertsFromPEM(caCert)
	certPool.AppendCertsFromPEM(marbleCert)

	tlsConfig = &tls.Config{
		Certificates: []tls.Certificate{ownCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    certPool,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			// Perform additional checks on the client certificate
			for _, chain := range verifiedChains {
				for _, cert := range chain {
					// Check if the "iat" field is not older than 5 minutes ago
					iat := cert.NotBefore
					maxAge := 10000 * time.Minute // change to 5 later

					// Perform the additional check only if one of the specified root CAs is used
					//if cert.Issuer.CommonName == "Marblerun Coordinator" {
					if time.Since(iat) > maxAge {
						return fmt.Errorf("client certificate is too old (issued more than 5 minutes ago)")
					}
					//}
				}
			}
			return nil
		},
	}
	return tlsConfig

}

func GetChallengeRenewGet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "No valid Method", http.StatusMethodNotAllowed)
		return
	}
	fmt.Println("Got Challenge Request")

	frontendAppID := r.URL.Query().Get("appID")

	nonce1 := GenerateNonce()
	nonce2 := GenerateNonce()

	if frontendAppID != "" {
		newRequest := ChallengeObjectRenew{
			ID:               frontendAppID,
			NonceTokenOldKey: nonce1,
			NonceTokenNewKey: nonce2,
		}

		challengesRenew[frontendAppID] = newRequest

		// Respond with a JSON containing both nonces
		response := map[string]string{
			"nonce1": nonce1,
			"nonce2": nonce2,
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

func GetNewChallengeGet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "No valid Method", http.StatusMethodNotAllowed)
		return
	}
	fmt.Println("Got Challenge Request")

	frontendAppID := r.URL.Query().Get("appID")

	nonce1 := GenerateNonce()
	nonce2 := GenerateNonce()

	if frontendAppID != "" {
		newRequest := ChallengeObjectRenew{
			ID:               frontendAppID,
			NonceTokenOldKey: nonce1,
			NonceTokenNewKey: nonce2,
		}

		challengesRenew[frontendAppID] = newRequest

		// Respond with a JSON containing both nonces
		response := map[string]string{
			"nonceOldKey": nonce1,
			"nonceNewKey": nonce2,
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
	// TODO: add query parameter new PubKey
	// check if appID in marble cert valid
	// app ID not needed, since coordinator just gives certificates to valid apps
	if r.Method != http.MethodGet {
		http.Error(w, "No valid Method", http.StatusMethodNotAllowed)
		return
	}
	fmt.Println("Got Certification request")

	tokenString := r.Header.Get("Authorization")[7:]

	parsedToken, _ := jwt.Parse(tokenString, nil)

	privateKey, err := LoadPrivateKeyFromFile("private.key")

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		// handle invalid claims ?
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

	parsedIct, err := jwt.Parse(oldIct, nil)

	ictClaims, ok := parsedIct.Claims.(jwt.MapClaims)
	if !ok {
		fmt.Println("Invalid JWT claims")
		return
	}

	fmt.Println("OldICT:   " + parsedIct.Raw)

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
	// first sign the token with old key
	signedOldFingerprint := claims["fingerprintoldkey"].(string)
	signedNewFingerprint := claims["fingerprintnewkey"].(string)
	frontendAppID := claims["sub"].(string)

	oldFingerprintToVerify := challengesRenew[frontendAppID].NonceTokenOldKey + challenges[frontendAppID].ID
	newFingerprintToVerify := challengesRenew[frontendAppID].NonceTokenNewKey + challenges[frontendAppID].ID

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

	ver, err := VerifySignature(oldFingerprintToVerify, signedOldFingerprint, recreateOldPubKey)
	if ver {
		fmt.Println("Verification of old Key and ICT successfull")
	} else {
		fmt.Println("Unsuccessfull", err)
		w.WriteHeader(http.StatusUnauthorized)
		message := "Access Denied: You do not have permission to access this resource."
		fmt.Fprintln(w, message)
		return
	}

	ver, err = VerifySignature(newFingerprintToVerify, signedNewFingerprint, recreateNewPubKey)
	if ver {
		fmt.Println("Verification of new Key successfull")
	} else {
		fmt.Println("Unsuccessfull", err)
		w.WriteHeader(http.StatusUnauthorized)
		message := "Access Denied: You do not have permission to access this resource."
		fmt.Fprintln(w, message)
		return
	}

	newCert := base64.StdEncoding.EncodeToString(CreateCert(SerialNumber, recreateNewPubKey, PathOwnCrt, PathServerKey,
		frontendAppID, 1, "client"))

	newJwt, newValidJwt := CreateJwt(privateKey, frontendAppID, recreateNewPubKey, newCert, PemCertChain)

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, newJwt)

	// delete old KID from list
	oldKid := oldPublicKeyData["kid"].(string)

	PublicKeys = DeleteKeyByKid(PublicKeys, oldKid)

	// append new KID to list
	PublicKeys = append(PublicKeys, newValidJwt)

}

func DeleteKeyByKid(keys []PublicKeyInfo, kidToDelete string) []PublicKeyInfo {
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

	PathRootCert := PathOwnCrt

	token, _ := jwt.Parse(tokenString, nil)
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		fmt.Println("Invalid Claims")
	}

	x5cChainHeader, ok := token.Header["x5c"]
	if !ok {
		// maybe here try verify with just root public key
		fmt.Println("x5c chain not found in token header")
		return false, nil
	}

	if x5cChainHeader != nil && PathRootCert != "" {

		x5cChainStr, ok := x5cChainHeader.([]interface{})
		if !ok {
			fmt.Println("Invalid x5c chain format in token header")
			return false, nil
		}

		var x5cChain []string
		for _, cert := range x5cChainStr {
			certStr, ok := cert.(string)
			if !ok {
				fmt.Println("Invalid certificate format in x5c chain")
				return false, nil
			}
			x5cChain = append(x5cChain, certStr)
		}
		// append root cert at the end

		rootCACertData, err := os.ReadFile(PathRootCert)
		if err != nil {
			fmt.Println("Error reading root CA certificate:", err)
			return false, err
		}
		x5cChain = append(x5cChain, string(rootCACertData))

		// Decode the PEM-encoded certificates from the x5c chain
		var certs []*x509.Certificate
		for _, certStr := range x5cChain {
			certBytes, err := base64.StdEncoding.DecodeString(certStr)
			if err != nil {
				fmt.Println("Error decoding certificate:", err)
				return false, err
			}

			block, _ := pem.Decode(certBytes)
			if block == nil {
				fmt.Println("Failed to decode PEM block from certificate")
				return false, err
			}

			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				fmt.Println("Error parsing certificate:", err)
				return false, err
			}

			// Validate the certificate against the next one in the chain
			if len(certs) > 0 {
				if err := certs[len(certs)-1].CheckSignatureFrom(cert); err != nil {
					fmt.Println("Certificate validation failed:", err)
					return false, err
				} //  TODO :: check if issued and issuer matches
			}

			certs = append(certs, cert)
		}
		// at the end check if first public key is the one that signed jwt
		publicKeySigner := certs[0].PublicKey.(*rsa.PublicKey)
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return publicKeySigner, nil
		})
		if err == nil && token.Valid {
			return true, nil
		}
		return false, err
	} else if PathRootCert != "" {
		// search publicKey in  Show Cert, root PKI can just look it up
		// try get x509 cert
		// get signer kid from jwt
		// recreate PublicKey
		// verify
		var publicKeyKid PublicKeyInfo
		for _, key := range PublicKeys {
			if key.Kid == claims["kid"] {
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
	return false, nil
}
