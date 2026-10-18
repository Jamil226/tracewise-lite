#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* BENIGN: Safe malloc/free with proper use — should NOT trigger CWE-416 */
int main() {
    char input[256];
    if (!fgets(input, sizeof(input), stdin)) return 1;

    size_t len = strlen(input) + 1;
    char *buf = (char *)malloc(len);
    if (!buf) return 1;

    memcpy(buf, input, len);
    printf("Processed: %s\n", buf);
    free(buf);
    buf = NULL; /* Explicitly nulled — correct practice */
    return 0;
}
