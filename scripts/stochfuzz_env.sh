#!/bin/bash

stochfuzz_dir=$(realpath $(dirname "$(realpath $0)")/../)
libstochfuzzRT_path="$stochfuzz_dir/src/libstochfuzzRT.so"
libunwind_path="$stochfuzz_dir/libunwind/install/lib/libunwind.so"

if [ ! -f $libstochfuzzRT_path ]; then
    echo "libstochfuzzRT.so not found!"
    exit 1
fi

if [ ! -f $libunwind_path ]; then
    echo "libunwind.so not found!"
    exit 1
fi

# it seems that clang will inline ASAN functions into the target binary
if [ -x "$(command -v gcc)" ]; then
    libasan_gcc_path="$(gcc -print-file-name=libasan.so)"
else
    libasan_gcc_path=""
fi

export STOCHFUZZ_PRELOAD=$libasan_gcc_path:$libstochfuzzRT_path:$libunwind_path
echo $STOCHFUZZ_PRELOAD
