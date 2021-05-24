stochfuzz_dir=$(realpath $(dirname "$(realpath $0)")/../)
libstochfuzzRT_path="$stochfuzz_dir/src/libstochfuzzRT.so"
libunwind_path="$stochfuzz_dir/libunwind/install/lib/libunwind.so"

if [ ! -f $libstochfuzzRT_path ]; then
    echo "libstochfuzzRT.so not found!"
else
    echo "libstochfuzzRT.so: $libstochfuzzRT_path"
fi

if [ ! -f $libunwind_path ]; then
    echo "libunwind.so not found!"
else
    echo "libunwind.so: $libunwind_path"
fi

export STOCHFUZZ_PRELOAD=$libstochfuzzRT_path:$libunwind_path
