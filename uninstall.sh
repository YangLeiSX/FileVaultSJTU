#!/bin/bash

if [ "$EUID" -ne 0 ]
	then echo "Please Run As Root!"
	exit
fi

echo "Uninstalling ..." && \
rmmod safe
