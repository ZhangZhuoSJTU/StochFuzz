#include <stdio.h>
#include <string.h>

int main(int argc, const char **argv) {
    if (argc > 1 && !strcmp(argv[1], "mdzz")) {
        char *a = NULL;
        a[1] = 'z';
    }
}
