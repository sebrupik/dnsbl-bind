#!/usr/local/bin/bash
BLOCK_START="--- blockeddomains_begin ----"
BLOCK_END="---- blockeddomains_end ----"
NAMED_DIR="/usr/local/etc/namedb"
OUTPUT_DIR="$NAMED_DIR/blocked_zones"
AGG_FILE="aggregate_zones.conf"
SOURCE_URL="https://v.firebog.net/hosts/lists.php?type=tick"

wget -O ./input_list.txt $SOURCE_URL
mkdir -p ./input_files
rm -rf ./input_files/*
mkdir -p $OUTPUT_DIR
rm -rf $OUTPUT_DIR/*

cd ./input_files
wget -i ../input_list.txt
cd ..

rm -f $NAMED_DIR/$AGG_FILE
if [ ! -f $NAMED_DIR/$AGG_FILE ]; then
    touch $NAMED_DIR/$AGG_FILE
fi

python3.7 ./dnsbl-bind.py $NAMED_DIR $OUTPUT_DIR ./input_files rpz