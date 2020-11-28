#!/bin/bash

if [ "$EUID" -ne 0 ]
then
	echo "Please run as root!"
	exit
fi

if [ $(ps -a | grep fvaultd | wc -w) -ne 0 ]
then 
	echo "Daemon Process is Running!"
fi

if [ $(lsmod | grep fvault | wc -w) -ne 0 ]
then
	echo "Kernel Module is Running!"
fi

if [ -e "/usr/bin/fvault" ]
then
	echo "Client Exec is Ready!"
fi

echo "Check DONE."