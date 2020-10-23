#!/bin/bash

if [ "$EUID" -ne 0 ]
	then echo "Please Run As Root!"
	exit
fi

echo "Uninstalling ..."

echo "Stop daemon process..."
if [ $(ps -a | grep fvaultd | wc -w) -ne 0 ]
then 
	pkill -f fvaultd

fi

echo "Remove kernel module..."
if [ $(lsmod | grep fvault | wc -w) -ne 0 ]
then
	rmmod fvault
fi

if [ -e "/usr/bin/fvault" ]
then
	rm /usr/bin/fvault
fi

if [ -e "fvault.db" ]
then
	rm fvault.db
fi

rm /tmp/*.socket
make -C kernel clean
echo "DONE"