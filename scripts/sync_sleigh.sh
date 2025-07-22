#!/bin/sh

TEMP_DIR="ghidra_src"

echo "Sync sleigh c++ code to the latest release branch ..."
python3 fetch_ghidra.py -o $TEMP_DIR

echo "Prepare sleigh source and data ..."
python3 update_sleigh.py -g $TEMP_DIR/ghidra -o ../sleigh -p -b

echo "Clean up ..."
rm -rf $TEMP_DIR

echo "Done"
