#!/bin/bash

RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
BOLD="\033[1m"
OFF="\033[0m"

CAPSTONE_VERSION="4.0.2"
KEYSTONE_VERSION="0.9.2"
GLIB_VERSION="2.68.0"

#
# check necessary command
#

check_command () {
    for cmd in $@
    do
        if [ ! -x "$(command -v $cmd)" ]; then
            echo -e "${RED}Error${OFF}: $cmd is not installed." >&2
            exit 1
        fi
    done
}

check_command "wget" "unzip" "make" "cmake" "meson" "ninja" "pkg-config" "clang" "python3"

#
# check clang version (>= 6.0.0)
#

CLANG_VERSION=$(clang --version | head -n 1 | grep -o -E "[[:digit:]].[[:digit:]].[[:digit:]]" | uniq | sort)
CLANG_MAJOR_VERSION=$(echo $CLANG_VERSION | awk -F '.' '{ print $1 }')
if [[ $CLANG_VERSION < "6.0.0" && ${#CLANG_MAJOR_VERSION} = "1" ]]; then
    echo "clang-6.0 or a newer version is required"
    exit 1
fi


#
# build capstone
#

CAPSTONE_URL="https://github.com/aquynh/capstone/archive/$CAPSTONE_VERSION.zip"

if [ ! -d capstone ]
then
    if [ ! -f capstone.zip ]
    then
        echo -e "${GREEN}$0${OFF}: downloading capstone.zip..."
        wget -O capstone.zip $CAPSTONE_URL
    fi

    echo -e "${GREEN}$0${OFF}: extracting capstone.zip..."
    unzip capstone.zip
    mv capstone-$CAPSTONE_VERSION capstone

    echo -e "${GREEN}$0${OFF}: building capstone.zip..."
    cd capstone
    CAPSTONE_DIET=no CAPSTONE_X86_REDUCE=no CAPSTONE_ARCHS="x86" ./make.sh
    cd ..
fi


#
# build keystone
#

KEYSTONE_URL="https://github.com/keystone-engine/keystone/archive/$KEYSTONE_VERSION.zip"

if [ ! -d keystone ]
then
    if [ ! -f keystone.zip ]
    then
        echo -e "${GREEN}$0${OFF}: downloading keystone.zip..."
        wget -O keystone.zip $KEYSTONE_URL
    fi

    echo -e "${GREEN}$0${OFF}: extracting keystone.zip..."
    unzip keystone.zip
    mv keystone-$KEYSTONE_VERSION keystone

    echo -e "${GREEN}$0${OFF}: building keystone.zip..."
    cd keystone
    if [ -d build ]
    then
        rm -rf build
    fi
    mkdir build
    cd build
    cmake -DBUILD_LIBS_ONLY=1 -DLLVM_BUILD_32_BITS=0 -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DLLVM_TARGETS_TO_BUILD="AArch64;X86" -G "Unix Makefiles" ..
    make -j8
    cd ../..
fi


#
# build glib
#

GLIB_URL="https://github.com/GNOME/glib/archive/$GLIB_VERSION.zip"

if [ ! -d glib ]
then
    if [ ! -f glib.zip ]
    then
        echo -e "${GREEN}$0${OFF}: downloading glib.zip..."
        wget -O glib.zip $GLIB_URL
    fi

    echo -e "${GREEN}$0${OFF}: extracting glib.zip..."
    unzip glib.zip
    mv glib-$GLIB_VERSION glib

    echo -e "${GREEN}$0${OFF}: building glib.zip..."
    cd glib
    meson _build --buildtype=release --default-library=static --prefix=$(realpath .)
    ninja -C _build
    ninja -C _build install
    cd ..
fi


#
# build src
#

# cd src
# make release
