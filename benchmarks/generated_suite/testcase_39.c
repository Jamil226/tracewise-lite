#include <stdio.h>
#include <string.h>
void func_39() {
    char buf[256];
    if (fgets(buf, sizeof(buf), stdin)) {
        printf("%s", buf); // SAFE
    }
}
int main() { func_39(); return 0; }