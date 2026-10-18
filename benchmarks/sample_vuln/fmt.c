#include <stdio.h>
#include <string.h>

/* CWE-134: Format String Vulnerability */
void vulnerable_function() {
    char input[256];
    if (fgets(input, sizeof(input), stdin)) {
        /* Directly passing user input as format string */
        printf(input);
    }
}

int main() {
    vulnerable_function();
    return 0;
}
