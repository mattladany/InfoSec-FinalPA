#!/bin/bash
echo
echo "Script to run PA-03"
echo "By: Matt Ladany and Matt Bowles"
echo

rm -f dispatcher amal/amal amal/logAmal.txt basim/basim basim/logBasim.txt basim/bunny.mp4 

echo "=============================="
echo "Compiling all source"
	gcc amal/amal.c    myCrypto.c   -o amal/amal    -lcrypto
	gcc basim/basim.c  myCrypto.c   -o basim/basim  -lcrypto
	gcc wrappers.c     dispatcher.c -o dispatcher

echo "=============================="
echo "Starting the dispatcher"
./dispatcher

echo "=============================="
echo "Verifying File Transmission via the pipe"
echo
diff -s amal/bunny.mp4 basim/bunny.mp4

echo
echo "======  Amal's  LOG  ========="
cat amal/logAmal.txt

echo
echo "======  Basim's  LOG  ========="
cat basim/logBasim.txt
echo
echo

