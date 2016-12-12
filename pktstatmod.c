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

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/socket.h>
#include <sys/proc.h>
#include <sys/module.h>
#include <sys/sysent.h>
#include <sys/kernel.h>
#include <sys/time.h>

#include <netinet/in.h>
#include <net/if.h>
#include <net/ethernet.h>

#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_fw.h>

#include "ipt_ipp2p.h"
#include "pktstat.h"

MALLOC_DECLARE(M_PKTSCAN);

MALLOC_DEFINE(M_PKTSCAN, "rawscanbufs", "Raw packet scanner buffers");

struct _pkt_stats pktst;
static struct _pkt_stats *ps = &pktst;

static ip_fw_chk_t *old_ip_fw_chk;

#define GET_TSC(var) {__asm__ volatile("rdtsc":"=A"(var)); }

extern int scan(unsigned char *buf, int len);

/* The procedure below is a real performance hog. We defeat the main
 * purpose of mbufs - minimal copying, since we need a linear packet
 * buffer to scan. Alas... Any good ideas?
 */
static int 
new_ip_fw_chk(struct ip_fw_args *args)
{
struct mbuf *t, *m = args->m;
int totl, cl = 0;
unsigned char *p, *rawbuf;
unsigned long f1=0, f2;


	if (m->m_flags & M_PKTHDR) {
	  pktst.type2++;
	  GET_TSC(f1);
	  totl = m->m_pkthdr.len;
	  if (totl > ETHER_MAX_LEN) {
            pktst.giants++;
            goto pass_ipfw;
          }
	  MALLOC(rawbuf, unsigned char *, ETHER_MAX_LEN, M_PKTSCAN, M_NOWAIT);
	  if (rawbuf==NULL)
	    goto pass_ipfw;
	  if (pktst.maxsingle < totl)
	    pktst.maxsingle = totl;
	  for (t=m, p=rawbuf; t!=NULL && totl > 0; t=t->m_next) {
            cl++;
	    totl -= t->m_len; 
	    bcopy(t->m_data, p, t->m_len);
	    p+=t->m_len;
	  }
	  if (cl > 0)
	    pktst.chains++;
	  if (pktst.maxchainlen < cl)
	    pktst.maxchainlen = cl;
	  pktst.chainlen = cl; 
          scan(rawbuf, m->m_pkthdr.len);
          FREE(rawbuf, M_PKTSCAN);
	} else pktst.miscmbuf++;
pass_ipfw:
	if (f1!=0) {
	  GET_TSC(f2);
	  pktst.clocks+=(f2-f1);
	}
	return (*old_ip_fw_chk)(args);
}

struct pktstat_args {
	int cmd;
	struct _pkt_stats * ps;
};

/*
 * The function for implementing the syscall.
 */

static int
pktstat_syscall (struct proc *p, void *u)
{
int rc = 0;
struct pktstat_args *uap = (struct pktstat_args *)u;

	if (uap->ps == NULL)
		return EINVAL;

	switch(uap->cmd) {
	case STAT_READ :
		rc = copyout(&pktst, uap->ps, sizeof(struct _pkt_stats));
		break;
	default :
		rc=EINVAL;
	}
	return rc;
}

/*
 * The `sysent' for the new syscall
 */

static struct sysent pktstat_sysent = {
	2,			/* sy_narg */
	pktstat_syscall		/* sy_call */
};

/*
 * The offset in sysent where the syscall is allocated.
 */

static int offset = NO_SYSCALL;

/*
 * The function called at load/unload.
 */

static int
load (struct module *module, int cmd, void *arg)
{
	int s, error = 0;
	struct timeval tv = {0, 1}; /* 1 microsecond */

	switch (cmd) {
	case MOD_LOAD :
		memset(ps, 0, sizeof(struct _pkt_stats));
		ps->hzusec=tvtohz(&tv);
		s = splnet();
		old_ip_fw_chk = ip_fw_chk_ptr;
		ip_fw_chk_ptr = new_ip_fw_chk;
		splx(s);
		break;
	case MOD_UNLOAD :
		s = splnet();
		ip_fw_chk_ptr = old_ip_fw_chk;
		splx(s);
/*		printf ("syscall unloaded from %d\n", offset);
*/
		break;
	default :
		error = EINVAL;
		break;
	}
	return error;
}

/* offset is the syscall slot # */
SYSCALL_MODULE(pktstat, &offset, &pktstat_sysent, load, NULL);
