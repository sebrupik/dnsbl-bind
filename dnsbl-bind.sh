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

python3.7 ./dnsbl-bind.py $NAMED_DIR $OUTPUT_DIR ./input_files

if [ ! -f $NAMED_DIR/$AGG_FILE ]; then
    touch $NAMED_DIR/$AGG_FILE
fi

echo "before some perl"
perl -i -pe 'BEGIN{undef $/;} s/$BLOCK_START.*$BLOCK_END/ /smg' $NAMED_DIR/$AGG_FILE
echo "$BLOCK_START" >> $NAMED_DIR/$AGG_FILE

echo "after some perl"

for ZONE_FILE_NAME in $OUTPUT_DIR/*
do
  echo "include \"$OUTPUT_DIR/$ZONE_FILE_NAME\";" >> $NAMED_DIR/$AGG_FILE
  echo $ZONE_FILE_NAME
done

echo "$BLOCK_END" >> $NAMED_DIR/$AGG_FILE