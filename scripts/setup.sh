#!/bin/bash

# Pugixml
if [ ! -d lib/pugixml ] ; then
    git clone https://github.com/zeux/pugixml.git lib/pugixml
    pushd lib/pugixml
    git checkout latest
    popd
fi

# uPDFParser
if [ ! -d lib/updfparser ] ; then
    git clone git://soutade.fr/updfparser.git lib/updfparser
    pushd lib/updfparser
    make BUILD_STATIC=1 BUILD_SHARED=0
    popd
fi
