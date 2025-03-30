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

function copy_to_lib() {
    sudo mkdir -p /usr/local/lib/sqisign 

    basepath="./the-sqisign/build"

    while [ $# -gt 0 ] ; do
        list_files=$(ls "${basepath}/${1}" | grep '\.a$\|\.so$')

        echo "${list_files}" | while IFS= read -r file; do
            sudo cp -v "${basepath}/${1}/${file}" "/usr/local/lib/sqisign"
        done

        shift
    done
}

function copy_to_include() {
    sudo mkdir -p /usr/local/include/sqisign/lvl1

    basepath="./the-sqisign/src/nistapi"
    
    sudo cp -v "${basepath}/lvl1/api.h" "/usr/local/include/sqisign/lvl1/api.h"
}

compile_sqisign
copy_to_lib "src" \
    "src/protocols/ref/lvl1" \
    "src/gf/ref/lvl1" \
    "src/id2iso/ref/lvl1" \
    "src/ec/ref/lvl1" \
    "src/klpt/ref/lvl1" \
    "src/precomp/ref/lvl1" \
    "src/intbig/ref/generic" \
    "src/common/generic" \
    "src/quaternion/ref/generic"
copy_to_include
