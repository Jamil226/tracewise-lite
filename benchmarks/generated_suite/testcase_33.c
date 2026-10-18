#include <stdio.h>
#include <string.h>
void func_33() {
    char buf[256];
    if (fgets(buf, sizeof(buf), stdin)) {
        printf("%s", buf); // SAFE
    }
}
int main() { func_33(); return 0; }