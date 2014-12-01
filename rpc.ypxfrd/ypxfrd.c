/* Copyright (c) 1996-1999, 2001-2003, 2005, 2006, 2010, 2014 Thorsten Kukuk
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

/* ypxfrd - ypxfrd main routines.  */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <unistd.h>
#include <syslog.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <rpc/rpc.h>
#include <rpc/pmap_clnt.h>
#include <rpc/nettype.h>
#include <getopt.h>
#include "ypxfrd.h"
#include "access.h"
#include "ypserv_conf.h"

#ifndef SA_RESTART
#define SA_RESTART 0
#endif

#include "log_msg.h"
#include "pidfile.h"

#define _YPXFRD_PIDFILE _PATH_VARRUN"ypxfrd.pid"

extern void ypxfrd_freebsd_prog_1 (struct svc_req *, SVCXPRT *);

int _rpcpmstart = 0;
int _rpcfdtype = 0;
int _rpcsvcdirty = 0;

#ifndef _RPCSVC_CLOSEDOWN
#define _RPCSVC_CLOSEDOWN       120
#endif

char *path_ypdb = YPMAPDIR;
char *progname;

static int foreground_flag = 0;

/*
** Needed, if we start rpc.ypxfrd from inetd
*/
static void
closedown (int sig)
{
  signal(sig, closedown);
  if (_rpcsvcdirty == 0)
    {
      static int size;
      int i, openfd;

      if (_rpcfdtype == SOCK_DGRAM)
	exit(0);
      if (size == 0)
	size = svc_maxfd+1;

      for (i = 0, openfd = 0; i < size && openfd < 2; ++i)
	if (FD_ISSET(i, &svc_fdset))
	  openfd++;
      if (openfd <= 1)
	exit(0);
    }
  alarm(_RPCSVC_CLOSEDOWN);
}

/* Clean up after child processes signal their termination.  */
static void
sig_child (int sig UNUSED)
{
  int save_errno = errno;

  while (wait3 (NULL, WNOHANG, NULL) > 0)
    ;
  errno = save_errno;
}

/* Clean up if we quit the program.  */
static void
sig_quit (int sig UNUSED)
{
  pmap_unset (YPXFRD_FREEBSD_PROG, YPXFRD_FREEBSD_VERS);
  unlink (_YPXFRD_PIDFILE);
  exit (0);
}

/*
** Reload securenets and config file
*/
static void
sig_hup (int sig UNUSED)
{
  load_securenets();
  load_config();
  /* we don't wish to cache the file handles.  */
  cached_filehandles = 0;
}

static void
usage (int exitcode)
{
  fputs ("usage: rpc.ypxfrd [--debug] [-d path] [-p port] [-f|--foreground]\n", stderr);
  fputs ("       rpc.ypxfrd --version\n", stderr);

  exit (exitcode);
}

int
main (int argc, char **argv)
{
  struct netconfig *nconf;
  void *nc_handle;
  int my_port = -1;
  struct sigaction sa;

  progname = strrchr (argv[0], '/');
  if (progname == (char *) NULL)
    progname = argv[0];
  else
    progname++;

  openlog(progname, LOG_PID, LOG_DAEMON);

  while(1)
    {
      int c;
      int option_index = 0;
      static struct option long_options[] =
      {
        {"version", no_argument, NULL, '\255'},
        {"debug", no_argument, NULL, '\254'},
        {"port", required_argument, NULL, 'p'},
	{"path", required_argument, NULL, 'd'},
	{"dir", required_argument, NULL, 'd'},
        {"foreground", no_argument, NULL, 'f'},
        {"usage", no_argument, NULL, 'u'},
	{"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, '\0'}
      };

      c=getopt_long(argc, argv, "p:d:fuh",long_options, &option_index);
      if (c==EOF) break;
      switch (c)
        {
	case '\255':
	  debug_flag = 1;
	  log_msg("rpc.ypxfrd (%s) %s\n", PACKAGE, VERSION);
	  exit(0);
	case '\254':
	  debug_flag++;
	  break;
	case 'd':
	  path_ypdb = optarg;
	  if (debug_flag)
	    log_msg("Using database directory: %s\n", path_ypdb);
	  break;
	case 'p':
	  my_port = atoi(optarg);
	  if (my_port <= 0 || my_port > 0xffff) {
	    /* Invalid port number */
	    fprintf (stdout, "Warning: rpc.ypxfrd: Invalid port %d (0x%x)\n",
			my_port, my_port);
	    my_port = -1;
	  }
	  if (debug_flag)
	    log_msg("Using port %d\n", my_port);
	  break;
	case 'f':
	  foreground_flag = 1;
	  break;
	case 'u':
        case 'h':
          usage(0);
          break;
        case '?':
          usage(1);
          break;
        }
    }

  argc-=optind;
  argv+=optind;

  if (debug_flag)
    log_msg("[Welcome to the rpc.ypxfrd Daemon, version %s]\n", VERSION);
  else
    if (!_rpcpmstart && !foreground_flag)
      {
	int i;

	if ((i = fork()) > 0)
	  exit(0);

	if (i < 0)
	  {
	    log_msg ("Cannot fork: %s\n", strerror (errno));
	    exit (-1);
	  }

	if (setsid() == -1)
	  {
	    log_msg ("Cannot setsid: %s\n", strerror (errno));
	    exit (-1);
	  }

	if ((i = fork()) > 0)
	  exit(0);

	if (i < 0)
	  {
	    log_msg ("Cannot fork: %s\n", strerror (errno));
	    exit (-1);
	  }

	for (i = 0; i < getdtablesize(); ++i)
	  close(i);
	errno = 0;

	umask(0);
	i = open("/dev/null", O_RDWR);
	if (dup(i) == -1)
	  {
	    int err = errno;
	    log_msg ("dup failed: %s\n", strerror (err));
	    exit (err);
	  }
	if (dup(i) == -1)
	  {
	    int err = errno;
	    log_msg ("dup failed: %s\n", strerror (err));
	    exit (err);
	  }
      }

  create_pidfile (_YPXFRD_PIDFILE, "rpc.ypxfrd");

  /* Change current directory to database location */
  if (chdir(path_ypdb) < 0)
    {
      log_msg("%s: chdir: %", argv[0], strerror(errno));
      exit(1);
    }

  load_securenets();
  load_config();
  /* we don't wish to cache the file handles.  */
  cached_filehandles = 0;

  /*
   * Ignore SIGPIPEs. They can hurt us if someone does a ypcat
   * and then hits CTRL-C before it terminates.
   */
  sigaction(SIGPIPE, NULL, &sa);
  sa.sa_handler = SIG_IGN;
#if !defined(sun) || (defined(sun) && defined(__svr4__))
  sa.sa_flags |= SA_RESTART;
  /*
   * The opposite to SA_ONESHOT, do  not  restore
   * the  signal  action.  This provides behavior
   * compatible with BSD signal semantics.
   */
#endif
  sigemptyset(&sa.sa_mask);
  sigaction(SIGPIPE, &sa, NULL);
  /*
   * Clear up if child exists
   */
  sigaction(SIGCHLD, NULL, &sa);
#if !defined(sun) || (defined(sun) && defined(__svr4__))
  sa.sa_flags |= SA_RESTART;
#endif
  sa.sa_handler = sig_child;
  sigemptyset(&sa.sa_mask);
  sigaction(SIGCHLD, &sa, NULL);
  /*
   * If program quits, give ports free.
   */
  sigaction(SIGTERM, NULL, &sa);
#if !defined(sun) || (defined(sun) && defined(__svr4__))
  sa.sa_flags |= SA_RESTART;
#endif
  sa.sa_handler = sig_quit;
  sigemptyset(&sa.sa_mask);
  sigaction(SIGTERM, &sa, NULL);

  sigaction(SIGINT, NULL, &sa);
#if !defined(sun) || (defined(sun) && defined(__svr4__))
  sa.sa_flags |= SA_RESTART;
#endif
  sa.sa_handler = sig_quit;
  sigemptyset(&sa.sa_mask);
  sigaction(SIGINT, &sa, NULL);

  /*
   * If we get a SIGHUP, reload the securenets and config file.
   */
  sigaction(SIGHUP, NULL, &sa);
#if !defined(sun) || (defined(sun) && defined(__svr4__))
  sa.sa_flags |= SA_RESTART;
#endif
  sa.sa_handler = sig_hup;
  sigemptyset(&sa.sa_mask);
  sigaction(SIGHUP, &sa, NULL);

  rpcb_unset(YPXFRD_FREEBSD_PROG, YPXFRD_FREEBSD_VERS, NULL);
  nc_handle = __rpc_setconf ("netpath");   /* open netconfig file */
  if (nc_handle == NULL)
    {
      log_msg ("could not read /etc/netconfig, exiting..");
      return 1;
    }

  while ((nconf = __rpc_getconf (nc_handle)))
    {
      SVCXPRT *xprt;
      struct sockaddr *sa;
      struct sockaddr_in sin;
      struct sockaddr_in6 sin6;
      int sock;
      sa_family_t family; /* AF_INET, AF_INET6 */
      int type; /* SOCK_DGRAM (udp), SOCK_STREAM (tcp) */
      int proto; /* IPPROTO_UDP, IPPROTO_TCP */

      if (debug_flag)
        log_msg ("Register ypserv for %s,%s",
                 nconf->nc_protofmly, nconf->nc_proto);

      if (strcmp (nconf->nc_protofmly, "inet6") == 0)
        family = AF_INET6;
      else if (strcmp (nconf->nc_protofmly, "inet") == 0)
        family = AF_INET;
      else
        continue; /* we don't support nconf->nc_protofmly */

      if (strcmp (nconf->nc_proto, "udp") == 0)
        {
          type = SOCK_DGRAM;
          proto = IPPROTO_UDP;
        }
      else if (strcmp (nconf->nc_proto, "tcp") == 0)
        {
          type = SOCK_STREAM;
          proto = IPPROTO_TCP;
        }
      else
        continue; /* We don't support nconf->nc_proto */

      if ((sock = socket (family, type, proto)) < 0)
        {
          log_msg ("Cannot create socket for %s,%s: %s",
                   nconf->nc_protofmly, nconf->nc_proto,
                   strerror (errno));
          continue;
        }

      if (family == AF_INET6)
        {
          /* Disallow v4-in-v6 to allow host-based access checks */

          int i;

          if (setsockopt (sock, IPPROTO_IPV6, IPV6_V6ONLY,
                          &i, sizeof(i)) == -1)
            {
              log_msg ("ERROR: cannot disable v4-in-v6 on %s6 socket",
                       nconf->nc_proto);
              return 1;
            }
        }

      switch (family)
        {
        case AF_INET:
          memset (&sin, 0, sizeof(sin));
          sin.sin_family = AF_INET;
          if (my_port > 0)
            sin.sin_port = htons (my_port);
          sa = (struct sockaddr *)(void *)&sin;
          break;
        case AF_INET6:
          memset (&sin6, 0, sizeof (sin6));
          sin6.sin6_family = AF_INET6;
          if (my_port > 0)
            sin6.sin6_port = htons (my_port);
          sa = (struct sockaddr *)(void *)&sin6;
          break;
        default:
          log_msg ("Unsupported address family %d", family);
          return -1;
        }

      if (bindresvport_sa (sock, sa) == -1)
        {
          if (my_port > 0)
            log_msg ("Cannot bind to reserved port %d (%s)",
                     my_port, strerror (errno));
          else
            log_msg ("bindresvport failed: %s",
                     strerror (errno));
          return 1;
        }

      if (type == SOCK_STREAM)
        {
          listen (sock, SOMAXCONN);
          xprt = svc_vc_create (sock, 0, 0);
        }
      else
        xprt = svc_dg_create (sock, 0, 0);

      if (xprt == NULL)
        {
          log_msg ("terminating: cannot create rpcbind handle");
          return 1;
        }

      rpcb_unset (YPXFRD_FREEBSD_PROG, YPXFRD_FREEBSD_VERS, nconf);
      if (!svc_reg (xprt, YPXFRD_FREEBSD_PROG, YPXFRD_FREEBSD_VERS,
		    ypxfrd_freebsd_prog_1, nconf))
	{
	  log_msg ("unable to register (YPXFRD_FREEBSD_PROG, YPXFRD_FREEBSD_VERS) for %s, %s.",
		   nconf->nc_protofmly, nconf->nc_proto);
	  return 1;
	}
    }
  __rpc_endconf (nc_handle);

  if (_rpcpmstart)
    {
      signal (SIGALRM, closedown);
      alarm (_RPCSVC_CLOSEDOWN);
    }

  /* If we use systemd as an init system, we may want to give it
     a message, that this daemon is ready to accept connections.
     At this time, sockets for receiving connections are already
     created, so we can say we're ready now. It is a nop if we
     don't use systemd. */
  announce_ready();

  svc_run();
  log_msg("svc_run returned");
  unlink (_YPXFRD_PIDFILE);
  exit(1);
  /* NOTREACHED */
}
