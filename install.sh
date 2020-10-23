#!/bin/bash

if [ "$EUID" -ne 0 ]
	then echo "Please Run As Root!"
	exit
fi

echo "Installing ..."
apt update -qq
apt install -qq -y libsqlite3-dev libext2fs-dev
make -C kernel/
gcc -DSQLITE_OMIT_LOAD_EXTENSION user/fvaultd.c -lsqlite3 -lext2fs -o bin/fvaultd
gcc user/fvault.c -o bin/fvault

echo "Insert kernel module..."
if [ $(lsmod | grep fvault | wc -w) -ne 0 ]
then
	rmmod fvault
	echo "Remove old kernel successfully."
fi
insmod kernel/fvault.ko

echo "Startup daemon process..."
if [ $(ps -a | grep fvaultd | wc -w) -ne 0 ]
then 
	pkill -f fvaultd
	echo "Stop old daemon successfully."

fi
./bin/fvaultd &
ln ./bin/fvault /usr/bin/fvault
echo "DONE"
