#!/usr/bin/env bash

if [ ! -h public/zenroom.wasm ]
then
  pushd public
  ln -s ../node_modules/zenroom/dist/lib/zenroom.wasm .
  popd
fi

sed -i "s/var wasmBinaryFile = 'zenroom.wasm'/var wasmBinaryFile = '\/zenroom.wasm'/" node_modules/zenroom/dist/lib/zenroom.js
sed -i "s/wasmBinaryFile = locateFile(wasmBinaryFile);/\/\/ wasmBinaryFile = locateFile(wasmBinaryFile);/" node_modules/zenroom/dist/lib/zenroom.js
