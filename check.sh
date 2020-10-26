#!/bin/bash

if [ "$EUID" -ne 0 ]
then
	echo "Please run as root!"
	exit
fi

ps -a | grep fvaultd
lsmod | grep fvault
ls /usr/bin | grep fvault
