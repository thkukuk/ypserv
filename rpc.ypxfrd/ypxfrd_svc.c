/* Copyright (c) 1996, 1997, 1998, 1999, 2001, 2004, 2012 Thorsten Kukuk
   Author: Thorsten Kukuk <kukuk@suse.de>

   The YP Server is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License
   version 2 as published by the Free Software Foundation.

   The YP Server is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public
   License along with the YP Server; see the file COPYING. If
   not, write to the Free Software Foundation, Inc., 51 Franklin Street,
   Suite 500, Boston, MA 02110-1335, USA. */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <rpc/rpc.h>
#include <rpc/pmap_clnt.h>
#include <string.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <memory.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <syslog.h>
#include <arpa/inet.h>
#include "ypxfrd.h"
#include "log_msg.h"

#define _RPCSVC_CLOSEDOWN 120

extern int _rpcpmstart;		/* Started by a port monitor ? */
extern int _rpcfdtype;		/* Whether Stream or Datagram ? */
extern int _rpcsvcdirty;	/* Still serving ? */

static
void _msgout(char* msg)
{
#ifdef RPC_SVC_FG
  if (_rpcpmstart)
    log_msg ("%s", msg);
  else
    fprintf (stderr, "%s\n", msg);
#else
  log_msg ("%s", msg);
#endif
}

void
ypxfrd_freebsd_prog_1 (struct svc_req *rqstp, SVCXPRT *transp)
{
  union {
    ypxfr_mapname ypxfrd_getmap_1_arg;
  } argument;
  char *result;
  xdrproc_t xdr_argument, xdr_result;
  char *(*local)(char *, struct svc_req *);

  _rpcsvcdirty = 1;
  switch (rqstp->rq_proc)
    {
    case NULLPROC:
      svc_sendreply(transp, (xdrproc_t) xdr_void, NULL);
      _rpcsvcdirty = 0;
      return;

    case YPXFRD_GETMAP:
      xdr_argument = (xdrproc_t) xdr_ypxfr_mapname;
      xdr_result = (xdrproc_t) xdr_xfr;
      local = (char *(*)(char *, struct svc_req *)) ypxfrd_getmap_1_svc;
      break;

    default:
      svcerr_noproc(transp);
      _rpcsvcdirty = 0;
      return;
    }
  memset(&argument, 0, sizeof (argument));
  if (!svc_getargs(transp, xdr_argument, (caddr_t) &argument))
    {
      const struct sockaddr_in *sin = svc_getcaller (rqstp->rq_xprt);

      log_msg ("cannot decode arguments for %d from %s",
              rqstp->rq_proc, inet_ntoa (sin->sin_addr));
      /* try to free already allocated memory during decoding */
      svc_freeargs (transp, xdr_argument, (caddr_t) &argument);

      svcerr_decode(transp);
      _rpcsvcdirty = 0;
      return;
    }
  result = (*local)((char *)&argument, rqstp);
  if (result != NULL && !svc_sendreply (transp, xdr_result, result))
    svcerr_systemerr (transp);

  if (!svc_freeargs (transp, xdr_argument, (caddr_t) &argument))
    {
      _msgout ("unable to free arguments");
      exit (1);
    }
  _rpcsvcdirty = 0;
  return;
}
