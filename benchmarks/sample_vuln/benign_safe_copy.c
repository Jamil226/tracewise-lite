#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* BENIGN: Safe strcpy with explicit bounds check - should NOT trigger CWE-121 */
void safe_copy(char *dst, size_t dst_size, const char *src) {
    if (strlen(src) + 1 > dst_size) {
        fprintf(stderr, "Input too large, truncating.\n");
        strncpy(dst, src, dst_size - 1);
        dst[dst_size - 1] = '\0';
    } else {
        strcpy(dst, src);
    }
}

int main() {
    char buffer[64];
    char input[256];
    if (fgets(input, sizeof(input), stdin)) {
        input[strcspn(input, "\n")] = '\0'; // strip newline
        safe_copy(buffer, sizeof(buffer), input);
        printf("Safely copied: %s\n", buffer);
    }
    return 0;
}
