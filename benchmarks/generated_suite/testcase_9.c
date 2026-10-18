#include <stdio.h>
#include <string.h>
void func_9() {
    char buf[256];
    if (fgets(buf, sizeof(buf), stdin)) {
        printf("%s", buf); // SAFE
    }
}
int main() { func_9(); return 0; }