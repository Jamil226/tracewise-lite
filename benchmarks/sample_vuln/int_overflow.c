#include <stdio.h>
#include <stdlib.h>

/* CWE-190: Integer Overflow leading to undersized allocation */
void vulnerable_function() {
    unsigned int size;
    scanf("%u", &size);
    
    /* Integer overflow: size + 1 wraps to 0 if size == UINT_MAX */
    char *buf = (char *)malloc(size + 1);
    if (!buf) return;
    
    /* Read more data than allocated */
    fread(buf, 1, 256, stdin);
    buf[size] = '\0';
    printf("Read: %s\n", buf);
    free(buf);
}

int main() {
    vulnerable_function();
    return 0;
}
