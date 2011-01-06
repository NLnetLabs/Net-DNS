#!/bin/sh

#
# Somewhat simple script to set the local interfaces.
# Works for Mac OS X.
# Also works for FreeBSD.
# $Id$


SYSTEM=`uname -s`

ping -c  1   127.53.53.12
if   [ $? != 0 ] ; then

    if [ "$SYSTEM" = "Linux" ]; then
	INTERFACE=lo
	echo "Setting Interfaces"
	sudo ifconfig ${INTERFACE}:0 inet 127.53.53.1 \
	    netmask 255.255.255.255
	sudo ifconfig ${INTERFACE}:1 inet 127.53.53.2 \
	    netmask 255.255.255.255
	sudo ifconfig ${INTERFACE}:2 inet 127.53.53.3 \
	    netmask 255.255.255.255
	sudo ifconfig ${INTERFACE}:3 inet 127.53.53.4 \
	    netmask 255.255.255.255
	sudo ifconfig ${INTERFACE}:4 inet 127.53.53.5 \
	    netmask 255.255.255.255
	sudo ifconfig ${INTERFACE}:5 inet 127.53.53.6 \
	    netmask 255.255.255.255
	sudo ifconfig ${INTERFACE}:6 inet 127.53.53.7 \
	    netmask 255.255.255.255 
	sudo ifconfig ${INTERFACE}:7 inet 127.53.53.8 \
	    netmask 255.255.255.255 
	sudo ifconfig ${INTERFACE}:7 inet 127.53.53.9 \
	    netmask 255.255.255.255 
	sudo ifconfig ${INTERFACE}:7 inet 127.53.53.10 \
	    netmask 255.255.255.255 
	sudo ifconfig ${INTERFACE}:7 inet 127.53.53.11 \
	    netmask 255.255.255.255 
	sudo ifconfig ${INTERFACE}:7 inet 127.53.53.12 \
	    netmask 255.255.255.255 

    elif [ "$SYSTEM" = "Darwin" -o "$SYSTEM" = "FreeBSD" ]; then
	echo "Setting Interfaces"
	INTERFACE=lo0
	sudo ifconfig ${INTERFACE} inet 127.53.53.1 \
	    netmask 255.255.255.255 alias
	sudo ifconfig ${INTERFACE} inet 127.53.53.2 \
	    netmask 255.255.255.255 alias
	sudo ifconfig ${INTERFACE} inet 127.53.53.3 \
	    netmask 255.255.255.255 alias
	sudo ifconfig ${INTERFACE} inet 127.53.53.4 \
	    netmask 255.255.255.255 alias
	sudo ifconfig ${INTERFACE} inet 127.53.53.5 \
	    netmask 255.255.255.255 alias
	sudo ifconfig ${INTERFACE} inet 127.53.53.6 \
	    netmask 255.255.255.255 alias
	sudo ifconfig ${INTERFACE} inet 127.53.53.7 \
	    netmask 255.255.255.255 alias
	sudo ifconfig ${INTERFACE} inet 127.53.53.8 \
	    netmask 255.255.255.255 alias	
	sudo ifconfig ${INTERFACE} inet 127.53.53.9 \
	    netmask 255.255.255.255 alias	
	sudo ifconfig ${INTERFACE} inet 127.53.53.10 \
	    netmask 255.255.255.255 alias	
	sudo ifconfig ${INTERFACE} inet 127.53.53.11 \
	    netmask 255.255.255.255 alias	
	sudo ifconfig ${INTERFACE} inet 127.53.53.12 \
	    netmask 255.255.255.255 alias	
    else
	echo "FAILED"
    fi

else

    echo "Interfaces already configured"
fi
