PREFIX = /usr/local

all:
	make -f pktstatmod.mk all
	make -f pktstat.mk all

clean:
	make -f pktstatmod.mk clean
	make -f pktstat.mk clean

install: all
	cp pktstat $(PREFIX)/bin/
	cp pktstat.ko $(PREFIX)/libexec/
	cp pktstat.sh $(PREFIX)/etc/rc.d/
