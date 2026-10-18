#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* CWE-122: Heap-based Buffer Overflow */
void vulnerable_function() {
    char *heap_buf = (char *)malloc(32);
    if (!heap_buf) return;
    
    char input[256];
    if (fgets(input, sizeof(input), stdin)) {
        /* No bounds check - overflows heap buffer */
        strcpy(heap_buf, input);
        printf("Heap content: %s\n", heap_buf);
    }
    free(heap_buf);
}

int main() {
    vulnerable_function();
    return 0;
}
