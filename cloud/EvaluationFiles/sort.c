#include <stdio.h>
#include <stdlib.h>
#include <time.h>

// Function prototypes
void quickSort(int data[], int low, int high);
int partition(int data[], int low, int high);

// Custom quicksort implementation
void quickSort(int data[], int low, int high) {
    if (low < high) {
        int pivot = partition(data, low, high);
        quickSort(data, low, pivot - 1);
        quickSort(data, pivot + 1, high);
    }
}

int partition(int data[], int low, int high) {
    int pivot = data[high];
    int i = low - 1;
    for (int j = low; j < high; j++) {
        if (data[j] < pivot) {
            i++;
            // Swap data[i] and data[j]
            int temp = data[i];
            data[i] = data[j];
            data[j] = temp;
        }
    }
    // Swap data[i+1] and data[high]
    int temp = data[i + 1];
    data[i + 1] = data[high];
    data[high] = temp;
    return i + 1;
}

int main() {
    const int gb = 1024 * 1024 * 128;
    const int elementSize = 4; // int = 4 bytes
    const int numElements = gb / elementSize;
    setbuf(stdout, NULL);

    // Generate random data
    srand(time(NULL));
    int* data = (int*)malloc(numElements * sizeof(int));
    for (int i = 0; i < numElements; i++) {
        data[i] = rand();
    }

    // Start time
    clock_t start = clock();

    // Perform quicksort for 1 minute
    clock_t duration = 20 * 60 * CLOCKS_PER_SEC; // 20 minutes in clock ticks
    clock_t end = start + duration;
    int count = 0;
    while (clock() < end) {
        // Create a copy of data to avoid modifying the original
        int* copyOfData = (int*)malloc(numElements * sizeof(int));
        for (int i = 0; i < numElements; i++) {
            copyOfData[i] = data[i];
        }

        // Perform quicksort
        quickSort(copyOfData, 0, numElements - 1);
        count++;
        printf("iteration %d: %f\n", count, (double)(clock() - start) / CLOCKS_PER_SEC);
        free(copyOfData);
    }

    // Calculate operations per second
    double opsPerSecond = (double)count / ((double)duration / CLOCKS_PER_SEC);

    printf("Sorted 128MB of data for %d iterations in 20 minutes.\n", count);
    printf("Operations per second: %.2f\n", opsPerSecond);

    free(data); // Free allocated memory
    return 0;
}