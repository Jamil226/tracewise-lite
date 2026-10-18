/*
 * Vulnerable program: Integer Overflow
 * Demonstrates integer overflow leading to buffer overflow
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void* allocate_buffer(int size) {
    /* VULNERABILITY: Integer overflow in size calculation */
    int total_size = size * sizeof(int);

    printf("Allocating buffer: %d bytes\n", total_size);

    /* If size is large, total_size can overflow and become negative/small */
    void *buf = malloc(total_size);
    if (!buf) {
        perror("malloc");
        return NULL;
    }
    return buf;
}

void process_data(int *data, int count) {
    int i;
    /* If count was manipulated via integer overflow, this can cause issues */
    for (i = 0; i < count; i++) {
        data[i] = i * 10;
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <multiplier>\n", argv[0]);
        return 1;
    }

    int multiplier = atoi(argv[1]);
    printf("Multiplier: %d\n", multiplier);

    /* VULNERABILITY: Large multiplier causes integer overflow */
    int *buffer = allocate_buffer(multiplier);
    if (!buffer) {
        return 1;
    }

    /* This may write beyond allocated buffer due to overflow */
    process_data(buffer, multiplier);

    printf("Buffer processed successfully\n");

    free(buffer);
    return 0;
}