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

	//go startServer()
	// _ = testNetwork()
	//for i := 0; i < 20; i++ {
	//_ = testFibonacci()
	_ = testKeys()
	//}
}

func testKeys() int {
	// Generate RSA key.
	start := time.Now() // Record the start time

	count := 0 // Initialize a counter for generated keys

	// Loop until one minute has passed
	for time.Since(start) < time.Minute {
		// Generate an RSA key
		_, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			fmt.Println("Error generating RSA key:", err)
			return 0
		}

		count++ // Increment the counter for each generated key
	}

	// Calculate keys per minute
	keysPerMinute := float64(count) / time.Since(start).Minutes()

	fmt.Printf("Generated %d RSA keys in one minute.\n", count)
	fmt.Printf("Average keys per minute: %.2f\n", keysPerMinute)
	return count
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
		res = fibonacci(30)
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
