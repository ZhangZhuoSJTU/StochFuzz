#!/bin/bash

if [ -d capstone ]
then
    rm -rf capstone
fi

if [ -d keystone ]
then
    rm -rf keystone
fi

if [ -d glib ]
then
    rm -rf glib
fi

if [ -d libunwind ]
then
    rm -rf libunwind
fi

rm -rf *.zip

cd src && make clean
