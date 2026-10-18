/*
 * Vulnerable program: Use-After-Free
 * Demonstrates UAF vulnerability with heap-allocated objects
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    int id;
    char name[32];
    void (*process)(const char *);
} DataObject;

void process_data(const char *data) {
    printf("Processing: %s\n", data);
}

void vulnerable_function(void) {
    DataObject *obj = malloc(sizeof(DataObject));
    if (!obj) {
        perror("malloc");
        return;
    }

    obj->id = 1;
    strcpy(obj->name, "test_object");
    obj->process = process_data;

    printf("Object created at %p\n", (void*)obj);

    /* Free the object */
    free(obj);
    printf("Object freed\n");

    /* VULNERABILITY: Use after free - accessing freed memory */
    printf("Accessing freed object...\n");
    printf("Object ID: %d\n", obj->id);  /* UAF read */

    /* More dangerous: calling function pointer through UAF */
    if (obj->process) {
        obj->process("exploit_data");  /* UAF function call */
    }
}

int main(int argc, char *argv[]) {
    (void)argc; (void)argv;
    printf("=== Use-After-Free Demo ===\n");
    vulnerable_function();
    printf("Program survived UAF!\n");
    return 0;
}