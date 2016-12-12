#ifndef PKTSTAT_H
#define PKTSTAT_H

#define HZPERSEC 801820000

struct _pkt_stats {
	unsigned long hzusec;
	unsigned long miscmbuf;
	unsigned long giants;
	unsigned long type2;
	unsigned long chains;
	unsigned long maxsingle;
	unsigned long maxchainlen;
	unsigned long chainlen;
	unsigned long clocks;

#define CLP2P_EDK	0x00
#define CLP2P_DC	0x01
#define CLP2P_GNU	0x02
#define CLP2P_KAZAA	0x03
#define CLP2P_BIT	0x04
#define CLP2P_APPLE	0x05
#define CLP2P_SOU	0x06
#define CLP2P_WINMX	0x07
#define CLP2P_ARES	0x08

#define CLP2P_UKAZAA	0x10
#define CLP2P_UBIT	0x11
#define CLP2P_UGNU	0x12
#define CLP2P_UEDK	0x13
#define CLP2P_UDC	0x14
#define CL_MAX		0x15
	unsigned long clstats[CL_MAX];
	unsigned long ambigous;
	};

#define STAT_READ 0x00000001

extern struct _pkt_stats pktst;

#ifndef KERNEL
static char *clitab[] = {
	"eDonkey/eMule/Overnet",	/* 0x00 */
	"Direct Connect",		/* 0x01 */
	"Gnutella",			/* 0x02 */
	"KaZaA",			/* 0x03 */
	"BitTorrent",			/* 0x04 */
	"AppleJuice",			/* 0x05 */
	"SoulSeek",			/* 0x06 */
	"WinMX",			/* 0x07 */
	"Ares",				/* 0x08 */
	NULL,				/* 0x09 */
	NULL,				/* 0x0A */
	NULL,				/* 0x0B */
	NULL,				/* 0x0C */
	NULL,				/* 0x0D */
	NULL,				/* 0x0E */
	NULL,				/* 0x0F */
	"UDP KaZaA",			/* 0x10 */
	"UDP BitTorrent",		/* 0x11 */
	"UDP Gnutella",			/* 0x12 */
	"UDP eDonkey/eMule/Overnet",	/* 0x13 */
	"UDP Direct Connect",		/* 0x14 */
	NULL				/* 0x15 */
};
#endif /* !KERNEL */

#endif /* PKTSTAT_H */
