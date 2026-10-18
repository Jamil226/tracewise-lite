#include <stdio.h>
#include <string.h>

void vulnerable_function(char *input) {
    char buffer[64];
    // CWE-121: Stack-based Buffer Overflow
    strcpy(buffer, input);
    printf("Processed input: %s\n", buffer);
}

int main() {
    char input[256];
    if (fgets(input, sizeof(input), stdin)) {
        vulnerable_function(input);
    }
    return 0;
}
