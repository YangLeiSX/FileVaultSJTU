#!/bin/bash

if [ "$EUID" -ne 0 ]
	then echo "Please Run As Root!"
	exit
fi

echo "Installing ..." && \
apt update -qq && \
apt install -qq -y libsqlite3-dev libext2fs-dev && \
make -C kernel/ && \
gcc -DSQLITE_OMIT_LOAD_EXTENSION user/safed.c -lsqlite3 -lext2fs -o safed && \
gcc user/safe.c -o safe && \
insmod kernel/safe.ko && \
./safed
