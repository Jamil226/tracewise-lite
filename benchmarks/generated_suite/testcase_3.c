#include <stdio.h>
#include <string.h>
void func_3() {
    char buf[256];
    if (fgets(buf, sizeof(buf), stdin)) {
        printf("%s", buf); // SAFE
    }
}
int main() { func_3(); return 0; }