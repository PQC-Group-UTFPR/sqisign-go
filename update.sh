#!/bin/bash

function compile_sqisign() {
    if [ -d "the-sqisign" ] ; then return ; fi

    git clone https://github.com/SQISign/the-sqisign
    cd the-sqisign
    git reset --hard ff34a8c
    mkdir build; cd build
    cmake -DSQISIGN_BUILD_TYPE=ref -DENABLE_TESTS=OFF -DENABLE_GMP_BUILD=ON .. ||
    { echo "Failed to compile the-sqisign. Cmake. Exiting" ; exit 1 ;}
    time make || 
    { echo "Failed to compile the-sqisign. Make. Exiting" ; exit 1 ;}
    cd ..; cd ..
}

function copy_libs() {
    mkdir -p ./build

    basepath="./the-sqisign/build"

    while [ $# -gt 0 ] ; do
        list_files=$(ls "${basepath}/${1}" | grep '\.a$\|\.so$')

        echo "${list_files}" | while IFS= read -r file; do
            cp -v "${basepath}/${1}/${file}" "./build"
        done

        shift
    done
}

function copy_header() {
    cp -v "./the-sqisign/src/nistapi/lvl1/api.h" "./sqisign-api.h"
}

compile_sqisign
copy_libs "src" \
    "src/protocols/ref/lvl1" \
    "src/gf/ref/lvl1" \
    "src/id2iso/ref/lvl1" \
    "src/ec/ref/lvl1" \
    "src/klpt/ref/lvl1" \
    "src/precomp/ref/lvl1" \
    "src/intbig/ref/generic" \
    "src/common/generic" \
    "src/quaternion/ref/generic"
copy_header

rm -rf ./the-sqisign/
