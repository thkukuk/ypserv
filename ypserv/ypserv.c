/* Copyright (c) 1996-2011, 2014 Thorsten Kukuk
   Author: Thorsten Kukuk <kukuk@thkukuk.de>

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

#if defined(HAVE_CONFIG_H)
#include "config.h"
#endif

#include <netdb.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <unistd.h>
#include <syslog.h>
#include <signal.h>
#include <getopt.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <rpc/rpc.h>
#include <rpc/rpc_com.h>
#include <rpc/nettype.h>

#include "yp.h"
#include "access.h"
#include "log_msg.h"
#include "ypserv_conf.h"
#include "pidfile.h"

#define _YPSERV_PIDFILE _PATH_VARRUN"ypserv.pid"

#ifndef YPOLDVERS
#define YPOLDVERS 1
#endif

static char *path_ypdb = YPMAPDIR;
static int foreground_flag = 0;

static void
ypprog_2 (struct svc_req *rqstp, register SVCXPRT * transp)
{
  union {
    domainname ypproc_domain_2_arg;
    domainname ypproc_domain_nonack_2_arg;
    ypreq_key ypproc_match_2_arg;
    ypreq_nokey ypproc_first_2_arg;
    ypreq_key ypproc_next_2_arg;
    ypreq_xfr ypproc_xfr_2_arg;
    ypreq_nokey ypproc_all_2_arg;
    ypreq_nokey ypproc_master_2_arg;
    ypreq_nokey ypproc_order_2_arg;
    domainname ypproc_maplist_2_arg;
  } argument;
  union {
    bool_t ypproc_domain_2_res;
    bool_t ypproc_domain_nonack_2_res;
    ypresp_val ypproc_match_2_res;
    ypresp_key_val ypproc_first_2_res;
    ypresp_key_val ypproc_next_2_res;
    ypresp_xfr ypproc_xfr_2_res;
    ypresp_all ypproc_all_2_res;
    ypresp_master ypproc_master_2_res;
    ypresp_order ypproc_order_2_res;
    ypresp_maplist ypproc_maplist_2_res;
  } result;
  bool_t retval;
  xdrproc_t _xdr_argument, _xdr_result;
  bool_t (*local) (char *, void *, struct svc_req *);

  switch (rqstp->rq_proc)
    {
    case YPPROC_NULL:
      _xdr_argument = (xdrproc_t) xdr_void;
      _xdr_result = (xdrproc_t) xdr_void;
      local =
	(bool_t (*)(char *, void *, struct svc_req *)) ypproc_null_2_svc;
      break;

    case YPPROC_DOMAIN:
      _xdr_argument = (xdrproc_t) xdr_domainname;
      _xdr_result = (xdrproc_t) xdr_bool;
      local =
	(bool_t (*)(char *, void *, struct svc_req *)) ypproc_domain_2_svc;
      break;

    case YPPROC_DOMAIN_NONACK:
      _xdr_argument = (xdrproc_t) xdr_domainname;
      _xdr_result = (xdrproc_t) xdr_bool;
      local =
	(bool_t (*)(char *, void *, struct svc_req *))
	ypproc_domain_nonack_2_svc;
      break;

    case YPPROC_MATCH:
      _xdr_argument = (xdrproc_t) xdr_ypreq_key;
      _xdr_result = (xdrproc_t) xdr_ypresp_val;
      local =
	(bool_t (*)(char *, void *, struct svc_req *)) ypproc_match_2_svc;
      break;

    case YPPROC_FIRST:
      _xdr_argument = (xdrproc_t) xdr_ypreq_nokey;
      _xdr_result = (xdrproc_t) xdr_ypresp_key_val;
      local =
	(bool_t (*)(char *, void *, struct svc_req *)) ypproc_first_2_svc;
      break;

    case YPPROC_NEXT:
      _xdr_argument = (xdrproc_t) xdr_ypreq_key;
      _xdr_result = (xdrproc_t) xdr_ypresp_key_val;
      local =
	(bool_t (*)(char *, void *, struct svc_req *)) ypproc_next_2_svc;
      break;

    case YPPROC_XFR:
      _xdr_argument = (xdrproc_t) xdr_ypreq_xfr;
      _xdr_result = (xdrproc_t) xdr_ypresp_xfr;
      local = (bool_t (*)(char *, void *, struct svc_req *)) ypproc_xfr_2_svc;
      break;

    case YPPROC_CLEAR:
      _xdr_argument = (xdrproc_t) xdr_void;
      _xdr_result = (xdrproc_t) xdr_void;
      local =
	(bool_t (*)(char *, void *, struct svc_req *)) ypproc_clear_2_svc;
      break;

    case YPPROC_ALL:
      _xdr_argument = (xdrproc_t) xdr_ypreq_nokey;
      _xdr_result = (xdrproc_t) xdr_ypresp_all;
      local = (bool_t (*)(char *, void *, struct svc_req *)) ypproc_all_2_svc;
      break;

    case YPPROC_MASTER:
      _xdr_argument = (xdrproc_t) xdr_ypreq_nokey;
      _xdr_result = (xdrproc_t) xdr_ypresp_master;
      local =
	(bool_t (*)(char *, void *, struct svc_req *)) ypproc_master_2_svc;
      break;

    case YPPROC_ORDER:
      _xdr_argument = (xdrproc_t) xdr_ypreq_nokey;
      _xdr_result = (xdrproc_t) xdr_ypresp_order;
      local =
	(bool_t (*)(char *, void *, struct svc_req *)) ypproc_order_2_svc;
      break;

    case YPPROC_MAPLIST:
      _xdr_argument = (xdrproc_t) xdr_domainname;
      _xdr_result = (xdrproc_t) xdr_ypresp_maplist;
      local =
	(bool_t (*)(char *, void *, struct svc_req *)) ypproc_maplist_2_svc;
      break;

    default:
      svcerr_noproc (transp);
      return;
    }

  memset ((char *) &argument, 0, sizeof (argument));
  if (!svc_getargs (transp, _xdr_argument, (caddr_t) &argument))
    {
           int error;
      char host[NI_MAXHOST];
      char serv[NI_MAXSERV];
      struct netbuf *rqhost = svc_getrpccaller(rqstp->rq_xprt);

      struct sockaddr *sap = (struct sockaddr *)(rqhost->buf);

      error = getnameinfo (sap, sizeof (struct sockaddr),
                           host, sizeof(host), serv, sizeof(serv),
                           NI_NUMERICHOST | NI_NUMERICSERV);
      if (error)
        {
          log_msg ("ypprog_2: getnameinfo(): %s",
                   gai_strerror(error));
        }
      else
        {
          log_msg ("ERROR: Cannot decode arguments for %d from %s:%s",
                   rqstp->rq_proc, host, serv);
	}

      /* try to free already allocated memory during decoding.
	 bnc#471924 */
      svc_freeargs (transp, _xdr_argument, (caddr_t) &argument);

      svcerr_decode (transp);
      return;
    }

  retval = (bool_t) (*local) ((char *) &argument, (void *) &result, rqstp);
  if (retval > 0 && !svc_sendreply (transp, _xdr_result, (char *) &result))
      svcerr_systemerr (transp);

  if (!svc_freeargs (transp, _xdr_argument, (caddr_t) &argument))
    {
      log_msg ("ERROR: Unable to free arguments");
      return; /* don't abort */
    }

  if (!ypprog_2_freeresult (transp, _xdr_result, (caddr_t) &result))
    log_msg ("ERROR: Unable to free results");

  return;
}

extern FILE *debug_output;
/* SIGUSR1: enable/disable debug output.  */
static void
sig_usr1 (int sig UNUSED)
{
  int save_errno = errno;

  if (debug_flag)
    {
      debug_flag = 0;
      if (debug_output != stderr)
	fclose (debug_output);
      debug_output = stderr;
    }
  else
    {
      debug_output = fopen ("/var/yp/ypserv.log", "a");
      if (debug_output != NULL)
	debug_flag = 1;
    }
  errno = save_errno;
}

/* Clean up if we quit the program. */
static void
sig_quit (int sig UNUSED)
{
  pmap_unset (YPPROG, YPVERS);
  pmap_unset (YPPROG, YPOLDVERS);
  unlink (_YPSERV_PIDFILE);

  exit (0);
}

/* Clean up after child processes signal their termination. */
static void
sig_child (int sig UNUSED)
{
  int save_errno = errno;

  while (wait3 (NULL, WNOHANG, NULL) > 0)
    ;
  errno = save_errno;
}

static void
Usage (int exitcode)
{
  fputs ("usage: ypserv [-d] [-p port] [-f|--foreground]\n", stderr);
  fputs ("       ypserv --version\n", stderr);

  exit (exitcode);
}

int
main (int argc, char **argv)
{
  struct netconfig *nconf;
  void *nc_handle;
  int connmaxrec = RPC_MAXDATASIZE;
  int my_port = -1;

  openlog ("ypserv", LOG_PID, LOG_DAEMON);

  while (1)
    {
      int c;
      int option_index = 0;
      static struct option long_options[] = {
	{"version", no_argument, NULL, 'v'},
	{"debug", no_argument, NULL, 'd'},
	{"port", required_argument, NULL, 'p'},
	{"usage", no_argument, NULL, 'u'},
	{"help", no_argument, NULL, 'h'},
	{"foreground", no_argument, NULL, 'f'},
	{NULL, 0, NULL, '\0'}
      };

      c = getopt_long (argc, argv, "vdp:fbuh", long_options, &option_index);
      if (c == -1)
	break;
      switch (c)
	{
	case 'v':
	  debug_flag = 1;
	  log_msg ("ypserv (%s) %s\n", PACKAGE, VERSION);
	  return 0;
	case 'd':
	  ++debug_flag;
	  break;
	case 'p':
	  my_port = atoi (optarg);
	  if (my_port <= 0 || my_port > 0xffff) {
	    /* Invalid port number */
	    fprintf (stdout, "Warning: ypserv: Invalid port %d (0x%x)\n",
			my_port, my_port);
	    my_port = -1;
	  }
	  if (debug_flag)
	    log_msg ("Using port %d\n", my_port);
	  break;
	case 'f':
	  foreground_flag = 1;
	  break;
	case 'u':
	case 'h':
	  Usage (0);
	  break;
	default:
	  Usage (1);
	  break;
	}
    }

  argc -= optind;
  argv += optind;

  if (debug_flag)
    log_msg ("[ypserv (%s) %s]\n", PACKAGE, VERSION);
  else if (! foreground_flag)
    {
      int i;

      if ((i = fork ()) > 0)
	exit (0);

      if (i < 0)
	{
	  log_msg ("Cannot fork: %s\n", strerror (errno));
	  exit (-1);
	}

      if (setsid () == -1)
	{
	  log_msg ("Cannot setsid: %s\n", strerror (errno));
	  exit (1);
	}

      if ((i = fork ()) > 0)
	exit (0);

      if (i < 0)
	{
	  log_msg ("Cannot fork: %s\n", strerror (errno));
	  exit (-1);
	}

      for (i = 0; i < getdtablesize (); ++i)
	close (i);
      errno = 0;

      umask (0);
      i = open ("/dev/null", O_RDWR);
      if (i == -1)
	{
	  log_msg ("opening /dev/null failed: %s\n", strerror (errno));
	  exit (1);
	}
      /* two dups: stdin, stdout, stderr */
      if (dup (i) == -1)
	{
	  log_msg ("dup failed: %s\n", strerror (errno));
	  exit (1);
	}
      if (dup (i) == -1)
	{
	  log_msg ("dup failed: %s\n", strerror (errno));
	  exit (1);
	}
    }

  if (argc > 0 && debug_flag)
    {
      path_ypdb = argv[0];
      log_msg ("Using database directory: %s\n", path_ypdb);
    }

  /* Change current directory to database location */
  if (chdir (path_ypdb) < 0)
    {
      log_msg ("ypserv: chdir: %s", strerror (errno));
      exit (1);
    }

  create_pidfile (_YPSERV_PIDFILE, "ypserv");

  load_securenets ();
  load_config ();

  /*
   * Ignore SIGPIPEs. They can hurt us if someone does a ypcat
   * and then hits CTRL-C before it terminates.
   */
  signal (SIGPIPE, SIG_IGN);
  /*
   * If program quits, give ports free.
   */
  signal (SIGTERM, sig_quit);
  signal (SIGINT, sig_quit);
  /*
   * Ignore SIGHUP, it's not safe and we cannot reload all variables
   */
  signal (SIGHUP, SIG_IGN);
  /*
   * If we get a SIGUSR1, enable/disable debuging.
   */
  signal (SIGUSR1, sig_usr1);
  /*
   * On SIGCHLD wait for the child process, so it can give free all
   * resources.
   */
  signal (SIGCHLD, sig_child);

  /* XXX my_port handling missing! */

#if 0 /* XXX */
  if (!__rpcbind_is_up())
    {
      log_msg ("terminating: rpcbind is not running");
      return 1;
    }
#endif

  /* Set non-blocking mode and maximum record size for
     connection oriented RPC transports. */
  if (!rpc_control(RPC_SVC_CONNMAXREC_SET, &connmaxrec))
    log_msg ("unable to set maximum RPC record size");

  rpcb_unset (YPPROG, YPVERS, NULL);
  rpcb_unset (YPPROG, YPOLDVERS, NULL);

  nc_handle = __rpc_setconf ("netpath");   /* open netconfig file */
  if (nc_handle == NULL)
    {
      log_msg("could not read /etc/netconfig, exiting..");
      return 1;
    }

  while ((nconf = __rpc_getconf (nc_handle)))
    {
      SVCXPRT *xprt;

      if (debug_flag)
	log_msg ("Call svc_tp_create for %s", nconf->nc_protofmly);

      if ((xprt = svc_tp_create (ypprog_2, YPPROG, YPVERS, nconf)) == NULL)
	{
	  log_msg ("terminating: cannot create rpcbind handle");
	  return 1;
	}

      /* support ypserv V1, but only on udp/tcp transports */
      if (strcmp(nconf->nc_protofmly, NC_INET) == 0)
	{
	  (void) rpcb_unset(YPPROG, YPOLDVERS, nconf);
	  if (!svc_reg(xprt, YPPROG, YPOLDVERS, ypprog_2, nconf))
	    {
	      log_msg ("unable to register (YPPROG, YPOLDVERS).");
	      continue;
              }

          }
    }

  __rpc_endconf (nc_handle);

  /* If we use systemd as an init system, we may want to give it
     a message, that this daemon is ready to accept connections.
     At this time, sockets for receiving connections are already
     created, so we can say we're ready now. It is a nop if we
     don't use systemd. */
  announce_ready();

  svc_run ();
  log_msg ("svc_run returned");
  unlink (_YPSERV_PIDFILE);
  exit (1);
  /* NOTREACHED */
}
