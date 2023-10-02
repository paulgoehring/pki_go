package rootutils

import (
	"crypto/rsa"
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

func CreateJwt(privKey *rsa.PrivateKey, frontEndID string, publicKey *rsa.PublicKey) (string, PublicKeyInfo) {
	expiration := time.Now().Add(time.Hour * 1)
	myClaims := myJWKClaims{
		KeyType:   "RSA",
		Usage:     "sig",
		KeyID:     "test12345", // here maybe hash of the key idk how this works
		Algorithm: "RS256",
		Exponent:  strconv.Itoa(publicKey.E),
		Modulus:   publicKey.N.String(),
	}
	claims := jwt.MapClaims{
		"sub": frontEndID,
		"iss": "server",
		"kid": "serverkeyid",
		"exp": expiration.Unix(),
		"jwk": myClaims,
	}
	publicKeyData := PublicKeyInfo{
		E:   strconv.Itoa(publicKey.E),
		Kid: "test12345",
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
