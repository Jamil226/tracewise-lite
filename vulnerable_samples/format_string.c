/*
 * Vulnerable program: Format String Vulnerability
 * Demonstrates format string vulnerability via printf with user input
 */

#include <stdio.h>
#include <stdlib.h>

void vulnerable_function(char *user_input) {
    /* VULNERABILITY: User-controlled format string */
    printf(user_input);
    printf("\n");
}

void print_internal_data(void) {
    int secret_value = 0xdeadbeef;
    char secret_flag[] = "FLAG{format_string_exploited}";

    printf("Secret value at %p: %d\n", (void*)&secret_value, secret_value);
    printf("Secret flag at %p\n", (void*)secret_flag);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <input_file>\n", argv[0]);
        return 1;
    }

    FILE *fp = fopen(argv[1], "r");
    if (!fp) {
        perror("fopen");
        return 1;
    }

    char input[512];
    if (fgets(input, sizeof(input), fp) == NULL) {
        printf("No input provided\n");
        fclose(fp);
        return 1;
    }
    fclose(fp);

    /* Remove newline if present */
    size_t len = strlen(input);
    if (len > 0 && input[len-1] == '\n') {
        input[len-1] = '\0';
    }

    printf("=== Format String Vulnerability Demo ===\n");
    printf("Input received: ");
    vulnerable_function(input);

    print_internal_data();

    return 0;
}