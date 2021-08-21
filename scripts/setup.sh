#!/bin/bash

# Pugixml
if [ ! -d lib/pugixml ] ; then
    git clone https://github.com/zeux/pugixml.git lib/pugixml
    pushd lib/pugixml
    git checkout latest
    popd
fi

# Base64
if [ ! -d lib/base64 ] ; then
    git clone https://gist.github.com/f0fd86b6c73063283afe550bc5d77594.git lib/base64
fi

# uPDFParser
if [ ! -d lib/updfparser ] ; then
    git clone http://indefero.soutade.fr/p/updfparser lib/updfparser
    pushd lib/updfparser
    make STATIC=1 SHARED=0
    popd
fi
