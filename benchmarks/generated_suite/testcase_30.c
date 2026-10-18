#include <stdio.h>
#include <string.h>
void func_30() {
    char buf[256];
    if (fgets(buf, sizeof(buf), stdin)) {
        printf("%s", buf); // SAFE
    }
}
int main() { func_30(); return 0; }