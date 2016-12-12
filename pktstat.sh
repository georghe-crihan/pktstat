#!/bin/sh

PREFIX=/usr/local
PROG=pktstat

case "${1}" in
start)
	if [ -x ${PREFIX}/libexec/${PROG}.ko ]; then
	    echo -n " ${PROG}"
#	    kldload ${PREFIX}/libexec/${PROG}.ko
	fi
	;;
startt)
	if [ -x ${PREFIX}/libexec/${PROG}.ko ]; then
	    echo -n " ${PROG}"
	    kldload ${PREFIX}/libexec/${PROG}.ko
	fi
	;;
stop)
	kldunload ${PROG}.ko && echo -n " ${PROG}"
	;;
*)
	echo "Usage: `basename $0` {start|startt|stop}" >&2
	exit 64
	;;
esac
