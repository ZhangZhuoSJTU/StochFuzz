#!/bin/bash

echo "
#include <signal.h>
#include <stdio.h>

int main(int argc, char **argv) {
        int sz = SIGSTKSZ;
        if (sz < MINSIGSTKSZ) {
                sz = MINSIGSTKSZ;
        }
        printf(\"%#x\n\", sz * 2);
}" > /tmp/__sigstksz.c

clang /tmp/__sigstksz.c -o /tmp/__sigstksz
/tmp/__sigstksz
