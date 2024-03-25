package main

import (
	"fmt"
	"math/rand"
	"time"
)

func main() {
	// Generate 1GB of random numbers
	const gb = 1024 * 1024 * 1024
	const elementSize = 4 // int32 = 4 bytes
	const numElements = gb / elementSize

	data := make([]int, numElements)
	for i := range data {
		data[i] = rand.Int()
	}

	// Define a function to benchmark quicksort
	for i := 0; i < 20; i++ {
		start := time.Now() // Record the start time
		count := 0          // Initialize a counter for generated keys
		for time.Since(start) < time.Minute {
			_ = quicksort(data)
			count++
		}
		keysPerMinute := float64(count) / time.Since(start).Minutes()
		fmt.Printf("Sorted %d times.\n", count)
		fmt.Printf("Average keys per minute: %.2f\n", keysPerMinute)
	}

}

func quicksort(arr []int) []int {
	if len(arr) <= 1 {
		return arr
	}

	pivot := arr[len(arr)/2]
	var less, greater []int

	for _, num := range arr {
		if num < pivot {
			less = append(less, num)
		} else if num > pivot {
			greater = append(greater, num)
		}
	}

	less = quicksort(less)
	greater = quicksort(greater)
	return append(append(less, pivot), greater...)
}
