#include <string.h>
#include <unistd.h>

static void my_sleep() {
    sleep(5);
}

int main(int argc, const char **argv) {
    if (argc == 2 && !strcmp(argv[1], "mdzz")) {
        void (*p)() = my_sleep;
        (*p)();
    }
}
