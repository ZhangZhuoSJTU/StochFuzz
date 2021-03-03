#!/bin/bash

readonly EXIT_FAILURE=1

tool=$1
target=$2
phantom=$target.phantom
echo "phantom file: $phantom"

rm -rf $phantom
$tool start $target 2>/tmp/$target.daemon.log &
daemon_pid=$!

for i in {1..100}
do
    if [ -f $phantom ]; then
        echo "$target: daemon is up"
        ./$phantom ${@:3}
        wait $daemon_pid
        exit $?
    else
        echo "$target: daemon is not ready"
        sleep 5
    fi
done

echo "$target: timeout"
kill -9 0
