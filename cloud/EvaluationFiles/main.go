package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net"
	"time"
)

func main() {
	// Generate RSA key.
	_ = testKeys()
	//go startServer()
	// _ = testNetwork()
	//_ = testFibonacci()
}

func testKeys() int {
	// Generate RSA key.
	counter := 0
	startTime := time.Now()
	bitSize := 2048
	duration := 1 * time.Minute
	var err error

	for time.Since(startTime) < duration {
		_, err = rsa.GenerateKey(rand.Reader, bitSize)
		if err != nil {
			panic(err)
		}
		counter = counter + 1
	}
	fmt.Printf("Number Keys created: %d\n", counter)
	return counter
}

func testNetwork() int {
	counter := 0
	startTime := time.Now()
	duration := 1 * time.Minute
	for time.Since(startTime) < duration {
		startClient()
		counter = counter + 1
	}
	fmt.Printf("Number Server interactions: %d\n", counter)
	return counter

}

func startServer() {
	// Listen for incoming connections on port 8080
	listener, err := net.Listen("tcp", ":8080")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer listener.Close()

	fmt.Println("Server listening on port 8080")

	for {
		// Accept a new connection
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("Error:", err)
			continue
		}

		// Handle the connection in a goroutine
		go handleConnection(conn)
	}
}

// handleConnection function to handle the communication with a single client
func handleConnection(conn net.Conn) {
	defer conn.Close()

	// Buffer to read data from the client
	buffer := make([]byte, 1024)

	// Read data from the client
	n, err := conn.Read(buffer)
	if err != nil {
		fmt.Println("Error reading:", err)
		return
	}

	// Print the received message
	// fmt.Printf("Received from client: %s", buffer[:n])

	// Echo the message back to the client
	_, err = conn.Write(buffer[:n])
	if err != nil {
		fmt.Println("Error writing:", err)
	}
}

// Client function that connects to the server and sends a message
func startClient() {
	// Connect to the server on localhost:8080
	conn, err := net.Dial("tcp", "localhost:8080")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer conn.Close()

	// Message to be sent to the server
	message := "Hello, server!"

	// Send the message to the server
	_, err = conn.Write([]byte(message))
	if err != nil {
		fmt.Println("Error writing:", err)
		return
	}

	// Buffer to read the echoed message from the server
	buffer := make([]byte, 1024)

	// Read the echoed message from the server
	_, err = conn.Read(buffer)
	if err != nil {
		fmt.Println("Error reading:", err)
		return
	}

	// Print the echoed message
	// fmt.Printf("Received from server: %s", buffer[:n])
}

func testFibonacci() int {
	counter := 0
	startTime := time.Now()
	duration := 1 * time.Minute
	var res int
	for time.Since(startTime) < duration {
		res = fibonacci(15)
		counter = counter + 1
	}
	fmt.Printf("fibonacci numbers calculated: %d\n", counter)
	fmt.Printf("Final fibb number: %d \n", res)
	return counter
}

func fibonacci2(n int) int {
	if n <= 1 {
		return n
	}

	a, b := 0, 1
	for i := 2; i <= n; i++ {
		a, b = b, a+b
	}

	return b
}

func fibonacci(n int) int {
	if n <= 1 {
		return n
	}
	return fibonacci(n-1) + fibonacci(n-2)
}
