#!/bin/bash

if [ ! -d lib/pugixml -o ! -d lib/updfparser ] ; then
    echo "Some libraries are missing"
    echo "You must run this script at the top of libgourou working direcotry."
    echo "./lib/setup.sh must be called first (make all)"
    exit 1
fi

# Pugixml
pushd lib/pugixml
git pull origin latest
popd

# uPDFParser
pushd lib/updfparser
git pull origin master
make clean all BUILD_STATIC=1 BUILD_SHARED=0
