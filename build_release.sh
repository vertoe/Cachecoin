#!/bin/sh
CPUNUM=`grep -c ^processor /proc/cpuinfo`
qmake RELEASE=1 USE_QRCODE=1
make -j $CPUNUM
cd src
make STATIC=1 -j $CPUNUM -f makefile.unix
cd ..
mkdir cachecoin
cp cachecoin-qt cachecoin/
cp src/cachecoind cachecoin/
zip -r ~/cachecoin.zip cachecoin/
rm -rf cachecoin/
