/*
 * Vulnerable program: Buffer Overflow
 * This program demonstrates a classic stack-based buffer overflow
 * vulnerability via unsafe strcpy usage.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void vulnerable_function(char *input) {
    char buffer[64];
    /* VULNERABILITY: No bounds checking - strcpy can overflow buffer */
    strcpy(buffer, input);
    printf("Input: %s\n", buffer);
}

void secret_function(void) {
    printf("SECRET: You have successfully exploited the buffer overflow!\n");
    exit(42);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <input>\n", argv[0]);
        printf("  Reads input from file if provided, otherwise stdin\n");
        return 1;
    }

    FILE *fp = fopen(argv[1], "rb");
    if (!fp) {
        perror("fopen");
        return 1;
    }

    char input[1024];
    size_t n = fread(input, 1, sizeof(input) - 1, fp);
    input[n] = '\0';
    fclose(fp);

    printf("Processing input (%zu bytes)...\n", n);
    vulnerable_function(input);

    printf("Program completed normally.\n");
    return 0;
}