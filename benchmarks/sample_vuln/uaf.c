#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* CWE-416: Use After Free */
void vulnerable_function() {
    char *buf = (char *)malloc(64);
    if (!buf) return;
    
    fgets(buf, 64, stdin);
    printf("Read: %s\n", buf);
    
    free(buf);
    
    /* Use after free - accessing freed memory */
    printf("Dangling: %s\n", buf);
}

int main() {
    vulnerable_function();
    return 0;
}
