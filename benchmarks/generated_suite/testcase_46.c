#include <stdio.h>
#include <string.h>
void func_46() {
    char buf[64];
    char input[256];
    if (fgets(input, sizeof(input), stdin)) {
        strcpy(buf, input); // VULNERABLE
        printf("%s", buf);
    }
}
int main() { func_46(); return 0; }