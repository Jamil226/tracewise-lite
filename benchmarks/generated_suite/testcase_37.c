#include <stdio.h>
#include <string.h>
void func_37() {
    char buf[64];
    char input[256];
    if (fgets(input, sizeof(input), stdin)) {
        strcpy(buf, input); // VULNERABLE
        printf("%s", buf);
    }
}
int main() { func_37(); return 0; }