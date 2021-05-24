#!/bin/bash

readonly EXIT_FAILURE=1

tool=$1
options=$2
target=$3
phantom=$target.phantom
echo "phantom file: $phantom"

rm -rf $phantom
$tool $options -- $target 2>$target.daemon.log &
daemon_pid=$!

for i in {1..100}
do
    if [ -f $phantom ]; then
        echo "$target: daemon is up"
        if [ -v STOCHFUZZ_PRELOAD ]; then
            LD_PRELOAD=$STOCHFUZZ_PRELOAD ./$phantom ${@:4}
            code=$?
        else
            ./$phantom ${@:4}
            code=$?
        fi
        kill -0 $daemon_pid
        if [ "$?" -eq "0" ]; then
            wait $daemon_pid
        fi
        exit $code
    else
        echo "$target: daemon is not ready"
        sleep 5
    fi
done

echo "$target: timeout"
kill -9 $daemon_pid
exit 1
