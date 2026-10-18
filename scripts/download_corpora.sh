#!/bin/bash
set -e

mkdir -p ~/tracewise_cvs/oss_fuzz_corpora
cd ~/tracewise_cvs/oss_fuzz_corpora

echo "Downloading libpng corpora..."
wget -q "https://storage.googleapis.com/oss-fuzz-corpora/libpng/libpng_read_fuzzer_latest.zip" -O libpng.zip
unzip -q libpng.zip -d libpng_corpus || true

echo "Downloading expat corpora..."
wget -q "https://storage.googleapis.com/oss-fuzz-corpora/expat/parse_fuzzer_latest.zip" -O expat.zip
unzip -q expat.zip -d expat_corpus || true

echo "Downloading libjpeg-turbo corpora..."
wget -q "https://storage.googleapis.com/oss-fuzz-corpora/libjpeg-turbo/libjpeg_turbo_fuzzer_latest.zip" -O libjpeg.zip
unzip -q libjpeg.zip -d libjpeg_corpus || true

echo "Downloading libarchive corpora..."
wget -q "https://storage.googleapis.com/oss-fuzz-corpora/libarchive/libarchive_fuzzer_latest.zip" -O libarchive.zip
unzip -q libarchive.zip -d libarchive_corpus || true

echo "Downloading zlib corpora..."
wget -q "https://storage.googleapis.com/oss-fuzz-corpora/zlib/zlib_uncompress_fuzzer_latest.zip" -O zlib.zip
unzip -q zlib.zip -d zlib_corpus || true

echo "Done downloading and extracting corpora."
