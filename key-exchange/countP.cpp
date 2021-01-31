#include <iostream>
#include <string>
#include <vector>
#include <stdio.h>
#include <math.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <pthread.h>

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

// Static strings for usage/errors
static std::string usage = "Usage: myCount [Num of Threads]";
static std::string threadError = "Error: threads must be between 1 and 256";

// Global variable to be protected by mutexes
int totalCount = 0;

// Glabal variable tracking how many numbers have been checked
int totalChecked = 0;

// Global list of numbers taken from input file
std::vector<int64_t> numbers;

/*
 * printMessage():
 *   Print a string for the purposes for informing the user of something
 * Input: string
 * Output: void
 */
void printMessage(std::string msg) {
    std::cout << msg << std::endl;
}

/*
 * checkArgs(int):
 *   Check the argument count of the program. Exit if not the correct amount
 * Input: int
 * Output: void
 */
void checkArgs(int args) {
    if (args != 2) {
        printMessage(usage);
        exit(-1);
    }
}

/*
 * fillArray():
 *   Read in the numbers from the input file
 * Input: void
 * Output: void
 */
void fillArray() {
    int count = 0;
    while (1) {
        int64_t num;
        if (1 != scanf("%ld", &num)) break;
        numbers.push_back(num);
        count++;
    }
}
void printArray() {
    for (int i = 0; i < numbers.size(); i++) {
        std::cout << "\tNumber: " << numbers.at(i) << std::endl;
    }
}

/*
 * checkThreadCount(int):
 *   Check if the threads are within an acceptable range (1 to 256)
 *   Exit if bad value.
 * Input: int
 * Output: void
 */
void checkThreadCount(int tcount) {
    if (tcount < 1 || tcount > 256) {
        printMessage(threadError);
        exit(-1);
    }
}

/*
 * isPrime(int64_t):
 *   Performs the primality test. Return true if n is prime, else return false
 * Input: int64_t
 * Output: bool
 */
/// primality test, if n is prime, return 1, else return 0
bool isPrime(int64_t n) {
    if( n <= 1) return false; // small numbers are not primes
    if( n <= 3) return true; // 2 and 3 are prime
    if( n % 2 == 0 || n % 3 == 0) return false; // multiples of 2 and 3
    int64_t i = 5;
    int64_t max = sqrt(n);
    while( i <= max) {
        if (n % i == 0 || n % (i+2) == 0) return false;
        i += 6;
    }
    return true;
}

void * checkNumber(void * arg) {
    int64_t number = (int64_t) arg;
    if (isPrime(number)) {
        pthread_mutex_lock(&mutex);
        totalCount++;
        pthread_mutex_unlock(&mutex);
    }
    totalChecked++;
    return NULL;
}
int main (int argc, char * argv[]) {
    checkArgs(argc);
    int inputThreads = atoi(argv[1]);
    checkThreadCount(inputThreads);
    fillArray();
    std::cout << "Counting primes with " << inputThreads << " threads." << std::endl;

    pthread_t thds[inputThreads];
    pthread_cond_t cvs[inputThreads];

    int currentNumber = 0;
    thds[currentNumber % inputThreads] = pthread_create(&thds[currentNumber % inputThreads], NULL, checkNumber, (void *)numbers[currentNumber]);
    currentNumber++;
    while (currentNumber < numbers.size()) {
        if (totalChecked < currentNumber) {
            thds[currentNumber % inputThreads] = pthread_create(&thds[currentNumber % inputThreads], NULL, checkNumber, (void *)numbers[currentNumber]);
            currentNumber++;
        }
    }

    for (int i = 0; i < inputThreads; i++) {
        int rc = pthread_join(thds[i], NULL);
        if (rc) {
            std::cout << "Unable to join thread " << rc << std::endl;
            exit(-1);
        }
    }
    std::cout << "Found " << totalCount << " primes." << std::endl;
    return 0;
}