package clientutils

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt"
)

func GetCertificate(keyPath string, tokenPath string, marbleKeyPath string, marbleCertPath string, certPath string, appID string, initialContact bool) {
	// keyPath  : the path where the private Key of the client is stored
	// tokenPath: the path where the workload identity token(jwt) should be stored
	// marbleKeyPath:
	// marbleCertPath: the path where the marblerun certificate for the initial
	//            	   mtls connection is stored
	// certPath : the path where the own x.509 Certificate should be stored
	// initialContact : the marblerun Certificate gets used in the initial contact for
	//                  authentication and the old Workload Identity Token afterwards
	//                  Make sure to request a new Workload Identity Token BEFORE the old
	//                  expires
	mtlsConfig := DefineClientTLSConfig(marbleCertPath, marbleKeyPath)
	nonceToken := GetChallenge(mtlsConfig)
	challenge := string(nonceToken)

	fmt.Println("Request Token")

	fingerprint := challenge + appID
	privateKey, err := LoadPrivateKeyFromFile(keyPath)
	if err != nil {
		fmt.Println("Error loading private key", err)
	}

	signedToken, err := SignToken(fingerprint, privateKey)
	if err != nil {
		fmt.Println("Error signing token", err)
	}

	newJwt, err := createJwt(privateKey, signedToken, appID)
	if err != nil {
		fmt.Println("Error creating JWT token", err)
	}
	fmt.Println(newJwt)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: mtlsConfig,
		},
	}

	req, err := http.NewRequest("GET", "https://localhost:8081/getCert", nil)
	req.Header.Set("Authorization", "Bearer "+newJwt)

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)

	fmt.Println("Response: ")
	fmt.Println(string(body))

	jwtResponse := string(body)

	err = os.WriteFile(tokenPath, body, 0644)
	if err != nil {
		fmt.Println("JWT could not be stored", err)
	}

	token, _, err := new(jwt.Parser).ParseUnverified(jwtResponse, jwt.MapClaims{})
	if err != nil {
		fmt.Println("Error parsing JWT:", err)
		return
	}

	x5c, ok := token.Header["x5c"]
	if !ok {
		fmt.Println("No x5c field in Header")
		return
	}

	firstX5C := ""
	if x5cArray, isArray := x5c.([]interface{}); isArray && len(x5cArray) > 0 {
		if firstElement, isString := x5cArray[0].(string); isString {
			firstX5C = firstElement
		}
	}

	firstx5cPEM, err := base64.StdEncoding.DecodeString(firstX5C)
	if err != nil {
		fmt.Println("Error decoding x5c", err)
		return
	}
	certFile, err := os.Create(certPath)
	defer certFile.Close()
	_, err = certFile.Write(firstx5cPEM)

}

func SignToken(token string, privateKey *rsa.PrivateKey) (string, error) {
	hashed := sha256.Sum256([]byte(token))
	result, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return "Could not sign Token", err
	}
	encodedResult := base64.StdEncoding.EncodeToString(result)
	return encodedResult, nil

}

type myJWKClaims struct {
	KeyType   string `json:"kty"`
	Usage     string `json:"use"`
	KeyID     string `json:"kid"`
	Algorithm string `json:"alg"`
	Exponent  string `json:"e"`
	Modulus   string `json:"n"`
}

func GenerateKIDFromPublicKey(publicKey *rsa.PublicKey) string {
	hash := sha256.Sum256(publicKey.N.Bytes())
	kid := hex.EncodeToString(hash[:])
	return kid
}

func createJwt(privKey *rsa.PrivateKey, fingerprint string, frontEndID string) (string, error) {
	myClaims := myJWKClaims{
		KeyType:   "RSA",
		Usage:     "sig",
		KeyID:     GenerateKIDFromPublicKey(&privKey.PublicKey),
		Algorithm: "RS256",
		Exponent:  strconv.Itoa(privKey.PublicKey.E),
		Modulus:   privKey.PublicKey.N.String(),
	}
	claims := jwt.MapClaims{
		"sub":         frontEndID,
		"iss":         "client",
		"fingerprint": fingerprint,
		"exp":         time.Now().Add(time.Hour * 1).Unix(),
		"jwk":         myClaims,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(privKey)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func createNewJwt(oldICT []byte, privKey *rsa.PrivateKey, fingerprintOld string, fingerprintNew string,
	frontEndID string) (string, error) {
	myClaims := myJWKClaims{
		KeyType:   "RSA",
		Usage:     "sig",
		KeyID:     GenerateKIDFromPublicKey(&privKey.PublicKey),
		Algorithm: "RS256",
		Exponent:  strconv.Itoa(privKey.PublicKey.E),
		Modulus:   privKey.PublicKey.N.String(),
	}
	claims := jwt.MapClaims{
		"sub":               frontEndID,
		"iss":               "client",
		"fingerprintoldkey": fingerprintOld,
		"fingerprintnewkey": fingerprintNew,
		"exp":               time.Now().Add(time.Hour * 1).Unix(),
		"jwk":               myClaims,
		"ict":               string(oldICT),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(privKey)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func GetChallenge(tlsConfiguration *tls.Config) []byte {
	client := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfiguration,
		},
	}
	request1, err := client.Get(fmt.Sprintf("https://localhost:8081/getChallenge?appID=%v", "asd123"))
	if err != nil {
		fmt.Println("Could not reach Server", err)
		return nil
	}
	defer request1.Body.Close()

	nonceToken, err := io.ReadAll(request1.Body)
	fmt.Println(fmt.Sprintf("Got Challenge: %v", string(nonceToken)))
	return nonceToken
}

// maybe utils
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

func DefineClientTLSConfig(pathCrt string, pathKey string) *tls.Config {
	var tlsConfig *tls.Config

	ownCert, err := tls.LoadX509KeyPair(pathCrt, pathKey)
	if err != nil {
		fmt.Println("Error Loading Server cert", err)
		return nil
	}

	tlsConfig = &tls.Config{
		Certificates:       []tls.Certificate{ownCert},
		InsecureSkipVerify: true,
	}

	return tlsConfig

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
	fmt.Println(token, signature, decodedSignature, hashed)
	return true, nil // Verification successful
}

func RenewCertificate(pathJwt string, certPath string, pathKey string, newKey bool, appID string) {
	// get new challenge
	// if new key then you need two proof of possession
	// formulate new jwt, including old jwt

	nonceOldKey, nonceNewKey := GetNewChallenge()

	fmt.Println("Request Token")

	oldICT, err := os.ReadFile(pathJwt)

	fingerprintOld := nonceOldKey + appID
	fingerprintNew := nonceNewKey + appID
	privateKeyOld, err := LoadPrivateKeyFromFile(pathKey)
	if err != nil {
		fmt.Println("Error loading private key", err)
	}

	privateKeyNew := privateKeyOld // create Key Pair if new one requested

	signedTokenOld, err := SignToken(fingerprintOld, privateKeyOld)
	if err != nil {
		fmt.Println("Error signing old token", err)
	}

	signedTokenNew, err := SignToken(fingerprintNew, privateKeyNew)
	if err != nil {
		fmt.Println("Error signing new token", err)
	}

	newJwt, err := createNewJwt(oldICT, privateKeyNew, signedTokenOld, signedTokenNew, appID)
	if err != nil {
		fmt.Println("Error creating JWT token", err)
	}

	client := &http.Client{
		Transport: &http.Transport{},
	}
	req, err := http.NewRequest("GET", "http://localhost:8082/getNewCert", nil)
	req.Header.Set("Authorization", "Bearer "+newJwt)

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)

	fmt.Println("Response: ")
	fmt.Println(string(body))

	jwtResponse := string(body)

	err = os.WriteFile(pathJwt, body, 0644)
	if err != nil {
		fmt.Println("JWT could not be stored", err)
	}

	token, _, err := new(jwt.Parser).ParseUnverified(jwtResponse, jwt.MapClaims{})
	if err != nil {
		fmt.Println("Error parsing JWT:", err)
		return
	}

	x5c, ok := token.Header["x5c"]
	if !ok {
		fmt.Println("No x5c field in Header")
		return
	}

	firstX5C := ""
	if x5cArray, isArray := x5c.([]interface{}); isArray && len(x5cArray) > 0 {
		if firstElement, isString := x5cArray[0].(string); isString {
			firstX5C = firstElement
		}
	}

	firstx5cPEM, err := base64.StdEncoding.DecodeString(firstX5C)
	if err != nil {
		fmt.Println("Error decoding x5c", err)
		return
	}
	certFile, err := os.Create(certPath)
	defer certFile.Close()
	_, err = certFile.Write(firstx5cPEM)

}

func GetNewChallenge() (string, string) {

	// TODO Correct IP and port
	request1, err := http.Get(fmt.Sprintf("http://localhost:8082/getNewChallenge?appID=%v", "asd123"))
	if err != nil {
		fmt.Println("Could not reach Server", err)
		return "", ""
	}
	defer request1.Body.Close()

	var data map[string]string
	err = json.NewDecoder(request1.Body).Decode(&data)
	if err != nil {
		fmt.Println("Error decoding JSON response:", err)
		return "", ""
	}
	nonceOldKey := data["nonceOldKey"]
	nonceNewKey := data["nonceNewKey"]
	return nonceOldKey, nonceNewKey
}

func VerifyJwt(pathJwt string, pathRootCert string) {
	if pathRootCert != "" {
		// verify key chain, verify token
	} else {
		// get key pair from /well-known/ enpoint and verify token
	}
	return

}
