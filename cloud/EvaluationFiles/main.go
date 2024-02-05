package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"time"
)

func main() {
	// Generate RSA key.
	counter := 0
	startTime := time.Now()
	bitSize := 2048
	duration := 1 * time.Minute
	var key *rsa.PrivateKey
	var err error

	for time.Since(startTime) < duration {
		key, err = rsa.GenerateKey(rand.Reader, bitSize)
		if err != nil {
			panic(err)
		}
		counter = counter + 1
	}
	fmt.Println(key)
	fmt.Printf("Number Keys created: %d\n", counter)
	fmt.Println(counter)
}
