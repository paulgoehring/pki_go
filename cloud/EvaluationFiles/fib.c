#include <stdio.h>
#include <time.h>
//int main(void) {
  //  printf("Hello, world\n");
  //  return 0;
//}


int fibonacci(int n) {
    if (n <= 1) {
        return n;
    } else {
        return fibonacci(n - 1) + fibonacci(n - 2);
    }
}

int fibonacci2(int n) {
    if (n <= 1) {
        return n;
    }

    int a = 0, b = 1, temp;
    for (int i = 2; i <= n; i++) {
        temp = a + b;
        a = b;
        b = temp;
    }

    return b;
}

int main() {
    setbuf(stdout, NULL);
    for (int i=0; i<20; i++) {
    time_t startTime, currentTime;
    double elapsedTime = 0.0;
    int counter = 0;
    time(&startTime);  // Record the start time

    printf("Computing Fibonacci numbers for 1 minute...\n");
    unsigned long long result = 0;
    while (elapsedTime < 60.0) {
        // Calculate Fibonacci number (for demonstration purposes, using a relatively small index)
        result = fibonacci(30);

        // Print the result (you can modify the function or index as needed)
        //printf("Fibonacci(30): %llu\n", result);
        counter = counter + 1;
        // Check elapsed time
        time(&currentTime);
        elapsedTime = difftime(currentTime, startTime);
    }

    printf("Computation stopped after 1 minute.\n");
    printf("Numer of Fib numbers computed: %d\n", counter);
    printf("final number:%llu\n", result);
}
    return 0;
}