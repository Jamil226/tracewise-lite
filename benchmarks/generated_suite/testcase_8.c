#include <stdio.h>
#include <stdlib.h>
void func_8() {
    char *buf = malloc(64);
    fgets(buf, 64, stdin);
    free(buf);
    printf("UAF: %s\n", buf); // VULNERABLE
}
int main() { func_8(); return 0; }