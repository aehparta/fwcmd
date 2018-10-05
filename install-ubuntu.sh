#!/bin/bash

if [[ $EUID -ne 0 ]]; then
	echo "This script must be run as root" 
	exit 1
fi

cp fwcmd /etc/init.d/fwcmd
chmod +x /etc/init.d/fwcmd
if [ ! -f /etc/fwcmd-rules.conf ]; then
	cp fwcmd-rules.conf /etc/fwcmd-rules.conf
fi
systemctl enable fwcmd
