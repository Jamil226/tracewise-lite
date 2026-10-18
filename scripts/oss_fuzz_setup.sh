#!/bin/bash
set -e

mkdir -p ~/tracewise_cvs/oss_fuzz
cd ~/tracewise_cvs/oss_fuzz

echo "[*] Downloading and compiling libpng 1.6.36..."
wget -q https://download.sourceforge.net/libpng/libpng-1.6.36.tar.gz
tar xf libpng-1.6.36.tar.gz
cd libpng-1.6.36
./configure --prefix=/tmp/libpng_vuln > /dev/null
make -j4 > /dev/null
cd ..

echo "[*] Downloading and compiling libjpeg-turbo 2.0.3..."
wget -q https://github.com/libjpeg-turbo/libjpeg-turbo/archive/refs/tags/2.0.3.tar.gz
tar xf 2.0.3.tar.gz
cd libjpeg-turbo-2.0.3
cmake -G"Unix Makefiles" . > /dev/null
make -j4 > /dev/null
cd ..

echo "[*] Downloading and compiling expat 2.2.6..."
wget -q https://github.com/libexpat/libexpat/releases/download/R_2_2_6/expat-2.2.6.tar.bz2
tar xf expat-2.2.6.tar.bz2
cd expat-2.2.6
./configure > /dev/null
make -j4 > /dev/null
cd ..

echo "[*] Downloading and compiling libarchive 3.3.2..."
wget -q https://github.com/libarchive/libarchive/releases/download/v3.3.2/libarchive-3.3.2.tar.gz
tar xf libarchive-3.3.2.tar.gz
cd libarchive-3.3.2
./configure > /dev/null
make -j4 > /dev/null
cd ..

echo "[*] Downloading and compiling zlib 1.2.11..."
wget -q https://zlib.net/fossils/zlib-1.2.11.tar.gz
tar xf zlib-1.2.11.tar.gz
cd zlib-1.2.11
./configure > /dev/null
make -j4 > /dev/null
cd ..

echo "[*] Done compiling OSS-Fuzz target binaries."
