#!/bin/bash

# Pugixml
git clone https://github.com/zeux/pugixml.git lib/pugixml
pushd lib/pugixml
git checkout latest
popd

# Base64
git clone https://gist.github.com/f0fd86b6c73063283afe550bc5d77594.git lib/base64
