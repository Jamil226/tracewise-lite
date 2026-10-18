#include <stdio.h>
#include <string.h>
void func_24() {
    char buf[256];
    if (fgets(buf, sizeof(buf), stdin)) {
        printf("%s", buf); // SAFE
    }
}
int main() { func_24(); return 0; }