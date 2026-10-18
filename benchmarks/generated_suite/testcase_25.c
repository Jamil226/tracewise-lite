#include <stdio.h>
#include <string.h>
void func_25() {
    char buf[64];
    char input[256];
    if (fgets(input, sizeof(input), stdin)) {
        strcpy(buf, input); // VULNERABLE
        printf("%s", buf);
    }
}
int main() { func_25(); return 0; }