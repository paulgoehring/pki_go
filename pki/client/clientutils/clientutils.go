package clientutils

import (
	myutils "client/myutils"
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
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt"
)

type KeyResponse struct {
	Keys []PublicKeyInfo `json:"keys"`
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

func GetCertificate(keyPath string, tokenPath string, marbleKeyPath string, marbleCertPath string, appID string,
	serverIp string, serverPort string) {
	// keyPath  : the path where the private Key of the client is stored
	// tokenPath: the path where the workload identity token(jwt) should be stored
	// marbleKeyPath:
	// marbleCertPath: the path where the marblerun certificate for the initial
	//            	   mtls connection is stored
	mtlsConfig := DefineClientTLSConfig(marbleCertPath, marbleKeyPath)
	nonceToken := GetChallenge(mtlsConfig, serverIp, serverPort, appID)
	challenge := string(nonceToken)

	fmt.Println("Requesting Workload Identity Token")

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

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: mtlsConfig,
		},
	}
	url := fmt.Sprintf("https://%v:%v/getCert", serverIp, serverPort)
	req, err := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+newJwt)

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)

	err = os.WriteFile(tokenPath, body, 0644)
	if err != nil {
		fmt.Println("JWT could not be stored", err)
	}

	fmt.Println("Successfully received Workload Identity Token")

}

func CheckTokenExpirationPeriodically(jwtFilePath string, ipServer string, portServerInsecure string, pathJWT string, pathOwnKey string, appName string, newKey bool) {
	// checks if the JWT is about to expire and renews it if necessary
	for {
		// Read the JWT from the file
		jwtBytes, err := os.ReadFile(jwtFilePath)
		if err != nil {
			fmt.Println("Error reading JWT file:", err)
			return
		}

		// Parse the JWT token
		token, _, err := new(jwt.Parser).ParseUnverified(string(jwtBytes), jwt.MapClaims{})
		if err != nil {
			fmt.Println("Error parsing JWT:", err)
			return
		}

		// Extract the expiration time from the token claims
		expirationTime := time.Unix(int64(token.Claims.(jwt.MapClaims)["exp"].(float64)), 0)

		// Calculate the exact wait time until 5 minutes before expiration
		timeToWait := time.Until(expirationTime.Add(-5 * time.Minute))

		// Check if the token will expire within 5 minutes
		if timeToWait > 0 {
			// Wait until 5 minutes before expiration
			fmt.Printf("Waiting until %v before renewing certificate...\n", timeToWait)
			time.Sleep(timeToWait)

			// Call the RenewCertificate function
			RenewCertificate(ipServer, portServerInsecure, pathJWT, pathOwnKey, appName, false)
		}

		// Sleep for a short duration before checking expiration again
		time.Sleep(1 * time.Minute)
	}
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

func createNewJwt(oldICT []byte, privKey *rsa.PrivateKey, fingerprintNew string,
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

func GetChallenge(tlsConfiguration *tls.Config, serverIp string,
	serverPort string, appID string) []byte {

	client := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfiguration,
		},
	}
	u, err := url.Parse(fmt.Sprintf("https://%s:%s/getChallenge", serverIp, serverPort))
	if err != nil {
		log.Fatal(err)
	}
	q := u.Query()
	q.Set("appID", appID)
	u.RawQuery = q.Encode()

	request1, err := client.Get(u.String())
	if err != nil {
		fmt.Println("Could not reach Server", err)
		return nil
	}
	defer request1.Body.Close()

	nonceToken, err := io.ReadAll(request1.Body)
	fmt.Println("Received Challenge")
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

	return true, nil // Verification successful
}

func RenewCertificate(serverIp string, serverPort string, pathJwt string, pathKey string, appID string, newKey bool) {
	// get new challenge
	// if new key then you need two proof of possession
	// formulate new jwt, including old jwt

	nonce := GetNewChallenge(serverIp, serverPort, appID)

	fmt.Println("Request new Workload Identity Token")

	oldICT, err := os.ReadFile(pathJwt)
	if err != nil {
		fmt.Println("Error reading JWT file:", err)
		return
	}

	fingerprintNew := string(nonce) + appID
	privateKeyOld, err := LoadPrivateKeyFromFile(pathKey)
	if err != nil {
		fmt.Println("Error loading private key", err)
	}

	var privateKeyNew *rsa.PrivateKey
	if newKey {
		// create new key pair
		myutils.CreateKeyPair(pathKey)
		privateKeyNew, err = LoadPrivateKeyFromFile(pathKey)
		if err != nil {
			fmt.Println("Error loading private key", err)
		}
	} else {
		privateKeyNew = privateKeyOld
	}

	signedTokenNew, err := SignToken(fingerprintNew, privateKeyNew)
	if err != nil {
		fmt.Println("Error signing new token", err)
	}

	// sign Jwt with old Key to make proof of possession
	newJwt, err := createNewJwt(oldICT, privateKeyOld, signedTokenNew, appID)
	if err != nil {
		fmt.Println("Error creating JWT token", err)
	}

	client := &http.Client{
		Transport: &http.Transport{},
	}
	serverUrl := fmt.Sprintf("http://%v:%v/getNewCert", serverIp, serverPort)
	req, err := http.NewRequest("GET", serverUrl, nil)
	req.Header.Set("Authorization", "Bearer "+newJwt)

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)

	err = os.WriteFile(pathJwt, body, 0644)
	if err != nil {
		fmt.Println("JWT could not be stored", err)
	}

	fmt.Println("Successfuly Received new Workload Identity Token")

}

func GetNewChallenge(serverIp string, serverPort string, appID string) string {

	// TODO Correct IP and port
	u, err := url.Parse(fmt.Sprintf("http://%s:%s/getNewChallenge", serverIp, serverPort))
	if err != nil {
		fmt.Println("Could not parse URL", err)
		return ""
	}
	q := u.Query()
	q.Set("appID", appID)
	u.RawQuery = q.Encode()

	request1, err := http.Get(u.String())
	if err != nil {
		fmt.Println("Could not reach Server", err)
		return ""
	}
	defer request1.Body.Close()

	fmt.Println("Received New Challenge")

	var data map[string]string
	err = json.NewDecoder(request1.Body).Decode(&data)
	if err != nil {
		fmt.Println("Error decoding JSON response:", err)
		return ""
	}

	nonceNewKey := data["nonceNewKey"]

	return nonceNewKey
}

func VerifyICT(pathRootIp string, rootPort string, tokenString string) bool {
	//token, _ := jwt.Parse(tokenString, nil)

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		//resp, err := http.Get(pathRootIp + ":" + rootPort + "/.well-known/certs")
		resp, err := http.Get(fmt.Sprintf("http://%v:%v/.well-known/certs", pathRootIp, rootPort))
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}

		var jwks = KeyResponse{}
		err = json.Unmarshal(body, &jwks)
		if err != nil {
			return nil, err
		}

		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, errors.New("kid field is missing from token or is not a string")
		}

		var publicKeyKid PublicKeyInfo

		keyFound := false
		for _, key := range jwks.Keys {
			if key.Kid == kid {
				publicKeyKid = key
				keyFound = true
				break
				//rsaPublicKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(key.N))
				//if err != nil {
				//	return nil, err
				//}
				//return rsaPublicKey, nil
			}
		}
		if !keyFound {
			return nil, errors.New("unable to find appropriate key")
		}
		//if publicKeyKid == (PublicKeyInfo{}) {
		//	return nil, errors.New("unable to find appropriate key")
		//}

		n := new(big.Int)
		n.SetString(publicKeyKid.N, 10)
		e := new(big.Int)
		e.SetString(publicKeyKid.E, 10)
		recreatePubKey := &rsa.PublicKey{
			N: n,
			E: int(e.Int64()),
		}
		return recreatePubKey, nil
	})

	if err != nil {
		fmt.Println("Error while parsing token: ", err)
		return false
	}

	if _, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		fmt.Println("Token is valid.")
		return true
	} else {
		fmt.Println("Invalid token")
		return false
	}
}
