#!/bin/sh

#
# Somewhat simple script to set the local interfaces.
# Works for Mac OS X.
# $Id$


SYSTEM=`uname -s`

ping -c  1   127.53.53.012
if   [ $? != 0 ] ; then

    if [ "$SYSTEM" = "Linux" ]; then
	INTERFACE=lo
	echo "Setting Interfaces"
	sudo ifconfig ${INTERFACE}:0 inet 127.53.53.001 \
	    netmask 255.255.255.255
	sudo ifconfig ${INTERFACE}:1 inet 127.53.53.002 \
	    netmask 255.255.255.255
	sudo ifconfig ${INTERFACE}:2 inet 127.53.53.003 \
	    netmask 255.255.255.255
	sudo ifconfig ${INTERFACE}:3 inet 127.53.53.004 \
	    netmask 255.255.255.255
	sudo ifconfig ${INTERFACE}:4 inet 127.53.53.005 \
	    netmask 255.255.255.255
	sudo ifconfig ${INTERFACE}:5 inet 127.53.53.006 \
	    netmask 255.255.255.255
	sudo ifconfig ${INTERFACE}:6 inet 127.53.53.007 \
	    netmask 255.255.255.255 
	sudo ifconfig ${INTERFACE}:7 inet 127.53.53.008 \
	    netmask 255.255.255.255 
	sudo ifconfig ${INTERFACE}:7 inet 127.53.53.009 \
	    netmask 255.255.255.255 
	sudo ifconfig ${INTERFACE}:7 inet 127.53.53.010 \
	    netmask 255.255.255.255 
	sudo ifconfig ${INTERFACE}:7 inet 127.53.53.011 \
	    netmask 255.255.255.255 
	sudo ifconfig ${INTERFACE}:7 inet 127.53.53.012 \
	    netmask 255.255.255.255 

    elif [ "$SYSTEM" = "Darwin" ]; then
	echo "Setting Interfaces"
	INTERFACE=lo0
	sudo ifconfig ${INTERFACE} inet 127.53.53.001 \
	    netmask 255.255.255.255 alias
	sudo ifconfig ${INTERFACE} inet 127.53.53.002 \
	    netmask 255.255.255.255 alias
	sudo ifconfig ${INTERFACE} inet 127.53.53.003 \
	    netmask 255.255.255.255 alias
	sudo ifconfig ${INTERFACE} inet 127.53.53.004 \
	    netmask 255.255.255.255 alias
	sudo ifconfig ${INTERFACE} inet 127.53.53.005 \
	    netmask 255.255.255.255 alias
	sudo ifconfig ${INTERFACE} inet 127.53.53.006 \
	    netmask 255.255.255.255 alias
	sudo ifconfig ${INTERFACE} inet 127.53.53.007 \
	    netmask 255.255.255.255 alias
	sudo ifconfig ${INTERFACE} inet 127.53.53.008 \
	    netmask 255.255.255.255 alias	
	sudo ifconfig ${INTERFACE} inet 127.53.53.009 \
	    netmask 255.255.255.255 alias	
	sudo ifconfig ${INTERFACE} inet 127.53.53.010 \
	    netmask 255.255.255.255 alias	
	sudo ifconfig ${INTERFACE} inet 127.53.53.011 \
	    netmask 255.255.255.255 alias	
	sudo ifconfig ${INTERFACE} inet 127.53.53.012 \
	    netmask 255.255.255.255 alias	
    else
	echo "FAILED"
    fi

else

    echo "Interfaces already configured"
fi