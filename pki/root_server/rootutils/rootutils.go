package rootutils

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt"
)

type PublicKeyInfo struct {
	E   string    `json:"e"`
	Kid string    `json:"kid"`
	N   string    `json:"n"`
	Use string    `json:"use"`
	Kty string    `json:"kty"`
	Alg string    `json:"alg"`
	Exp time.Time `json:"exp"`
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

func CreateJwt(privKey *rsa.PrivateKey, frontEndID string, publicKey *rsa.PublicKey) (string, PublicKeyInfo) {
	// Create a new JWT OR NEW CERT
	expiration := time.Now().Add(time.Hour * 1)
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
		"exp": expiration.Unix(),
		"jwk": myClaims,
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
