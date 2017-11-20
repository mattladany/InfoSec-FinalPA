#!/bin/bash
echo
echo "Script to run the Final PA"
echo "By: Matt Ladany"
echo

rm -f dispatcher amal/amal amal/logAmal.txt basim/basim basim/logBasim.txt basim/bunny.mp4 kdc/kdc

echo "=============================="
echo "Compiling all source"
    gcc genKey.c -o genKey -lcrypto
	gcc amal/amal.c    myCrypto.c   -o amal/amal    -lcrypto
	gcc basim/basim.c  myCrypto.c   -o basim/basim  -lcrypto
    gcc kdc/kdc.c      myCrypto.c   -o kdc/kdc      -lcrypto
	gcc wrappers.c     dispatcher.c -o dispatcher

echo
echo "=============================="
echo "Generating Master Keys"
    ./genKey

echo
echo "Amal's master key:"
hexdump -C amal_master_key.bin
echo "Basim's master key:"
hexdump -C basim_master_key.bin
echo
echo

echo "=============================="
echo "Starting the dispatcher"
./dispatcher

echo "=============================="
echo "Verifying File Transmission via the pipe"
echo
diff -s amal/bunny.mp4 basim/bunny.mp4

echo
echo "==========  KDC's  LOG  =========="
cat kdc/logKDC.txt

echo
echo "==========  Amal's  LOG  =========="
cat amal/logAmal.txt

echo
echo "==========  Basim's  LOG  =========="
cat basim/logBasim.txt
echo
echo

