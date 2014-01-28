#!/bin/sh
qmake RELEASE=1 USE_QRCODE=1
make -j 4
cd src
make STATIC=1 -j 4 -f makefile.unix
cd ..
mkdir cachecoin
cp cachecoin-qt cachecoin/
cp src/cachecoind cachecoin/
zip -r ~/cachecoin.zip cachecoin/
rm -rf cachecoin/
