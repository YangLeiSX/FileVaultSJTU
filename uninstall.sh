#!/bin/bash

if [ "$EUID" -ne 0 ]
	then echo "Please Run As Root!"
	exit
fi

echo "Uninstalling ..."

echo -n "Stop daemon process..."
if [ $(ps -a | grep fvaultd | wc -w) -ne 0 ]
then 
	pkill fvaultd && echo "Stopped!"
fi

echo -n "Remove kernel module..."
if [ $(lsmod | grep fvault | wc -w) -ne 0 ]
then
	rmmod fvault && echo "Removed!"
fi

echo -n "Remove Runable Link..."
if [ -e "/usr/bin/fvault" ]
then
	rm /usr/bin/fvault && echo "Removed link!"
fi

echo -n "Clear databses..."
if [ -e "fvault.db" ]
then
	rm fvault.db && echo "Cleared!"
fi

echo -n "Clear socket file..."
rm /tmp/*.socket && echo "Cleared!"

echo -n "Clean build dir..."
make -C kernel clean && echo "Cleaned!"

echo "ALL DONE"
