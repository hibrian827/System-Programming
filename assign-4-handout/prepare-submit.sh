#!/bin/bash

ASSIGN_NUM=4
FILES=("tsh.c")

TAR=assign-${ASSIGN_NUM}-submit.tar.gz
echo "[*] Remove tar file..."
rm -f $TAR || echo ""

echo "[*] Compress files..."
tar cvzf $TAR ${FILES[@]} || echo ""

RESULT=$(tar -tf $TAR | tr " " "\n")
i=0
for FILE in $RESULT; do
    if [[ ! " ${FILES[@]} " =~ " ${FILE} " ]]; then
        echo "[*] Error: Your tar file seems to be broken. Please check."
    fi
    i+=1
done

if [ ${#FILES[@]} -ne $i ]; then
    echo "[*] Error: Your tar file seems to be broken. Please check."
fi

echo "[*] Successfully Compressed!"
echo "[*] Done! Please submit the file, $TAR"
