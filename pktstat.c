/*-
 * Copyright (c) 1999 Assar Westerlund
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include <stdio.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/module.h>
#include <unistd.h>

#include "ipt_ipp2p.h"
#include "pktstat.h"

static char tty_form[]=
"\f"
"Other types(1,3):                 %lu\n"
"Giant packets:                    %lu\n"
"Packet headers (Types 2,4):       %lu\n"
"    of which chained:             %lu\n"
"    maximum data length:          %lu\n"
"    maximum chain length:         %lu\n"
"    chain length:                 %lu\n"
"    total clocks:                 %lu\n"
"    clocks/packet:                %f\n"
"    usec/packet:                  %f\n"
"    clocks/sec:                   %lu\n"
"%s"
"    of them ambigous:             %lu\n"
"";

static char html_form[]=
                "Refresh: 10s\n"
                "Content-Type: text/html\n"
                "\n"
                "<html>"
                "<head>"
                "<title>Peer-to-Peer traffic scanner:</title>"
                "</head>"
                "<body>"
		"<table border=\"0\" cellspacing=\"5\">" 
"<tr><td colspan=\"2\">Other types(1,3):</td><td>%lu</td></tr>"
"<tr><td colspan=\"2\">Giant packets:</td><td>%lu</td></tr>"
"<tr><td colspan=\"2\">Packet headers (Types 2,4):</td><td>%lu</td></tr>"
"<tr><td>&nbsp;&nbsp;&nbsp;&nbsp;</td><td>of which chained:</td><td>%lu</td></td></tr>"
"<tr><td>&nbsp;</td><td>maximum data length:</td><td>%lu</td></tr>"
"<tr><td>&nbsp;</td><td>maximum chain length:</td><td>%lu</td></tr>"
"<tr><td>&nbsp;</td><td>chain length:</td><td>%lu</td></tr>"
"<tr><td>&nbsp;</td><td>total clocks:</td><td>%lu</td></tr>"
"<tr><td>&nbsp;</td><td>clocks/packet:</td><td>%f</td></tr>"
"<tr><td>&nbsp;</td><td>usec/packet:</td><td>%f</td></tr>"
"<tr><td>&nbsp;</td><td>clocks/sec:</td><td>%lu</td></tr>"
"%s"
"<tr><td>&nbsp;</td><td>of them ambigous:</td><td>%lu</td></tr>"
"</table>"
                "</body></html>";

static char gstat_string[512];
static char gstat_buf[16385];

static void usage (void);

static void
usage (void)
{
	fprintf (stderr, "pktstat [-v] [-w] [-l timeout]\n");
	exit (1);
}


static void fill_statbuf_tty(char *statbuf, struct _pkt_stats *ps)
{
int i;

		statbuf[0] = '\0';
		strcat(statbuf, "Clients:\n");
		for (i = 0; i < CL_MAX; i++)
		  if (clitab[i]!=NULL) {
		    sprintf(gstat_string, "%s\t\t\t%lu\n", clitab[i], ps->clstats[i]);
		    strcat(statbuf, gstat_string);
		  }
}

static void fill_statbuf_www(char *statbuf, struct _pkt_stats *ps)
{
int i;

		statbuf[0] = '\0';
		strcat(statbuf, "<tr><td colspan=\"3\">Clients:</td></tr>");
		for (i = 0; i < CL_MAX; i++)
		  if (clitab[i]!=NULL) {
		    sprintf(gstat_string, "<tr><td></td><td>%s</td><td>%lu</td></tr>", clitab[i], ps->clstats[i]);
		    strcat(statbuf, gstat_string);
		  }
}

int
main(int argc, char **argv)
{
static struct _pkt_stats pktst, *ps = &pktst;
int i;
char *cur_form = NULL;
int syscall_num, verbose=0, loop=0, www=0;
struct module_stat stat;

	while ((i = getopt(argc, argv, "l:vhw")) != -1)
		switch (i) {
		case 'l':
			loop=atoi(optarg);
			break;
		case 'v':
			verbose++;
			break;
		case 'w':
			www++;
			break;
		case 'h':
		default:
			usage();
		}
/*
	argc -= optind;
	argv += optind
*/
	stat.version = sizeof(stat);
	modstat(modfind("pktstat"), &stat);
	syscall_num = stat.data.intval;
	if (verbose)
	  printf("%d\n", syscall_num);
	do {
		syscall (syscall_num, STAT_READ, ps);
		if (www)
		  cur_form = tty_form, fill_statbuf_tty(gstat_buf, ps);
		else
		  cur_form = html_form, fill_statbuf_www(gstat_buf, ps);
  		printf(cur_form
, ps->miscmbuf, ps->giants, ps->type2, ps->chains
, ps->maxsingle, ps->maxchainlen, ps->chainlen
, ps->clocks, (double)ps->clocks/ps->type2
, (double)ps->clocks/ps->type2/HZPERSEC*1000000
, HZPERSEC, gstat_buf, ps->ambigous
		);


		if (loop)
		  sleep(loop);
	} while(loop);
	return 0;
}
