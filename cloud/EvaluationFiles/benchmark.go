package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"

	"fmt"
	"time"
)

const oneMinute = 1 * time.Minute

func benchmarkSHA256() {
	data := []byte("Hello, World!")

	operations := 0
	startTime := time.Now()

	for time.Since(startTime) < oneMinute {
		_ = sha256.Sum256(data)
		operations++
	}

	fmt.Printf("SHA-256 Operations per Minute: %d\n", operations)
}

/*
func benchmarkSHA3() {
	data := []byte("Hello, World!")

	operations := 0
	startTime := time.Now()

	for time.Since(startTime) < oneMinute {
		_ = sha3.Sum256(data)
		operations++
	}

	fmt.Printf("SHA-3 Operations per Minute: %d\n", operations)
}*/

func benchmarkAES() {
	key := make([]byte, 32)
	data := []byte("Hello, World!")

	operations := 0
	startTime := time.Now()

	for time.Since(startTime) < oneMinute {
		block, _ := aes.NewCipher(key)
		gcm, _ := cipher.NewGCM(block)
		nonce := make([]byte, gcm.NonceSize())
		_ = gcm.Seal(nil, nonce, data, nil)
		operations++
	}

	fmt.Printf("AES Operations per Minute: %d\n", operations)
}

func benchmarkRSA() {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	data := []byte("Hello, World!")

	operations := 0
	startTime := time.Now()

	for time.Since(startTime) < oneMinute {
		_, _ = rsa.EncryptPKCS1v15(rand.Reader, &privKey.PublicKey, data)
		operations++
	}

	fmt.Printf("RSA Operations per Minute: %d\n", operations)
}

func benchmarkECDSA() {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	data := []byte("Hello, World!")

	operations := 0
	startTime := time.Now()

	for time.Since(startTime) < oneMinute {
		r, s, _ := ecdsa.Sign(rand.Reader, privKey, data)
		_ = append(r.Bytes(), s.Bytes()...)
		operations++
	}

	fmt.Printf("ECDSA Operations per Minute: %d\n", operations)
}

/*
func benchmarkPBKDF2() {
	password := []byte("MySecretPassword")
	salt := make([]byte, 16)

	operations := 0
	startTime := time.Now()

	for time.Since(startTime) < oneMinute {
		_ = pbkdf2.Key(password, salt, 100000, 32, sha256.New)
		operations++
	}

	fmt.Printf("PBKDF2 Operations per Minute: %d\n", operations)
}*/

func benchmarkRandomNumberGeneration() {
	operations := 0
	startTime := time.Now()

	for time.Since(startTime) < oneMinute {
		randomBytes := make([]byte, 16)
		_, err := rand.Read(randomBytes)
		if err != nil {
			fmt.Println("wrong")
		}
		operations++
	}

	fmt.Printf("Random Number Generation Operations per Minute: %d\n", operations)
}

func main() {
	fmt.Println("Benchmarking Cryptographic Operations in Go")

	fmt.Println("\nHash Functions:")
	benchmarkSHA256()
	//benchmarkSHA3()

	fmt.Println("\nSymmetric Encryption:")
	benchmarkAES()

	fmt.Println("\nAsymmetric Encryption:")
	benchmarkRSA()

	fmt.Println("\nDigital Signatures:")
	benchmarkECDSA()

	//fmt.Println("\nKey Derivation Functions:")
	//benchmarkPBKDF2()

	fmt.Println("\nRandom Number Generation:")
	benchmarkRandomNumberGeneration()
}
