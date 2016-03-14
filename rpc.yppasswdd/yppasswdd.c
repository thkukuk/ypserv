/*
   Copyright (c) 1996-2006, 2010, 2011, 2012, 2014, 2015, 2016 Thorsten Kukuk, <kukuk@thkukuk.de>
   Copyright (c) 1994, 1995, 1996 Olaf Kirch, <okir@monad.swb.de>

   This file is part of the NYS YP Server.

   The YP Server is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License
   version 2 as published by the Free Software Foundation.

   The NYS YP Server is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public
   License along with the NYS YP Server; see the file COPYING.  If
   not, write to the Free Software Foundation, Inc., 51 Franklin Street,
   Suite 500, Boston, MA 02110-1335, USA. */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <termios.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <syslog.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <rpc/rpc.h>
#include <rpc/nettype.h>
#include <rpcsvc/yp_prot.h>
#include <rpcsvc/yppasswd.h>
#include <getopt.h>

#include "yppwd_local.h"
#include "log_msg.h"
#include "pidfile.h"
#include "access.h"

#define _YPPASSWDD_PIDFILE _PATH_VARRUN"yppasswdd.pid"

int use_shadow = 0;
int allow_chsh = 0;
int allow_chfn = 0;
int solaris_mode = -1;
int x_flag = -1;

static int foreground_flag = 0;

void yppasswdprog_1 (struct svc_req *rqstp, SVCXPRT * transp);
void reaper (int sig);

/*==============================================================*
 * RPC dispatch function
 *==============================================================*/
void
yppasswdprog_1 (struct svc_req *rqstp, SVCXPRT * transp)
{
  yppasswd argument;
  int *result;
  xdrproc_t xdr_argument, xdr_result;

  switch (rqstp->rq_proc)
    {
    case NULLPROC:
      svc_sendreply (transp, (xdrproc_t) xdr_void, (char *) NULL);
      return;

    case YPPASSWDPROC_UPDATE:
      xdr_argument = (xdrproc_t) xdr_yppasswd;
      xdr_result = (xdrproc_t) xdr_int;
      break;

    default:
      svcerr_noproc (transp);
      return;
    }
  memset ((char *) &argument, 0, sizeof (argument));
  if (!svc_getargs (transp, xdr_argument, (caddr_t) &argument))
    {
      char namebuf6[INET6_ADDRSTRLEN];
      struct netconfig *nconf;
      const struct netbuf *rqhost = svc_getrpccaller (rqstp->rq_xprt);

      nconf = getnetconfigent (rqstp->rq_xprt->xp_netid);

      log_msg ("cannot decode arguments for %d from %s",
	       rqstp->rq_proc, taddr2ipstr (nconf, rqhost,
					    namebuf6, sizeof (namebuf6)));
      /* try to free already allocated memory during decoding */
      svc_freeargs (transp, xdr_argument, (caddr_t) &argument);
      svcerr_decode (transp);
      freenetconfigent (nconf);

      return;
    }
  result = yppasswdproc_pwupdate_1 (&argument, rqstp);
  if (result != NULL
      && !svc_sendreply (transp, (xdrproc_t) xdr_result, (char *)result))
    {
      svcerr_systemerr (transp);
    }
  if (!svc_freeargs (transp, xdr_argument, (caddr_t) &argument))
    {
      log_msg ("unable to free arguments\n");
      exit (1);
    }
}

static void
usage (FILE * fp, int n)
{
  fputs ("Usage: rpc.yppasswdd [--debug] [-s shadowfile] [-p passwdfile] [-e chsh|chfn] [-f|--foreground]\n", fp);
  fputs ("       rpc.yppasswdd [--debug] [-D directory] [-e chsh|chfn] [-f|--foreground]\n", fp);
  fputs ("       rpc.yppasswdd [--debug] [-x program |-E program] [-e chsh|chfn] [-f|--foreground]\n", fp);
  fputs ("       rpc.yppasswdd --port number\n", fp);
  fputs ("       rpc.yppasswdd --version\n", fp);
  exit (n);
}

static void
sig_child (int sig UNUSED)
{
  int save_errno = errno;

  while (wait3 (NULL, WNOHANG, NULL) > 0)
    ;
  errno = save_errno;
}

/* Clean up if we quit the program. */
static void
sig_quit (int sig UNUSED)
{
  rpcb_unset (YPPASSWDPROG, YPPASSWDVERS, NULL);
  unlink (_YPPASSWDD_PIDFILE);
  exit (0);
}


static void
install_sighandler (void)
{
  struct sigaction sa;

  sigaction (SIGPIPE, NULL, &sa);
  sa.sa_handler = SIG_IGN;
#if !defined(sun) || (defined(sun) && defined(__svr4__))
  sa.sa_flags |= SA_RESTART;
  /* The opposite to SA_ONESHOT, do  not  restore
     the  signal  action.  This provides behavior
     compatible with BSD signal semantics. */
#endif
  sigemptyset (&sa.sa_mask);
  sigaction (SIGPIPE, &sa, NULL);
  /* Clear up if child exists */
  sigaction (SIGCHLD, NULL, &sa);
#if !defined(sun) || (defined(sun) && defined(__svr4__))
  sa.sa_flags |= SA_RESTART;
#endif
  sa.sa_handler = sig_child;
  sigemptyset (&sa.sa_mask);
  sigaction (SIGCHLD, &sa, NULL);
  /* If program quits, give ports free. */
  sigaction (SIGTERM, NULL, &sa);
#if !defined(sun) || (defined(sun) && defined(__svr4__))
  sa.sa_flags |= SA_RESTART;
#endif
  sa.sa_handler = sig_quit;
  sigemptyset (&sa.sa_mask);
  sigaction (SIGTERM, &sa, NULL);

  sigaction (SIGINT, NULL, &sa);
#if !defined(sun) || (defined(sun) && defined(__svr4__))
  sa.sa_flags |= SA_RESTART;
#endif
  sa.sa_handler = sig_quit;
  sigemptyset (&sa.sa_mask);
  sigaction (SIGINT, &sa, NULL);
}


int
main (int argc, char **argv)
{
  struct netconfig *nconf;
  int my_port = -1;
  void *nc_handle;
  int c;
  int could_register = 0;

  /* Initialize logging. */
  openlog ("rpc.yppasswdd", LOG_PID, LOG_AUTH);

  /* Parse the command line options and arguments. */
  while (1)
    {
      int option_index = 0;
      static struct option long_options[] =
      {
	{"version", no_argument, NULL, 'v'},
	{"usage", no_argument, NULL, 'h'},
	{"help", no_argument, NULL, 'h'},
	{"execute", required_argument, NULL, 'x'},
	{"foreground", no_argument, NULL, 'f'},
	{"debug", no_argument, NULL, '\254'},
	{"port", required_argument, NULL, '\253'},
	{NULL, 0, NULL, '\0'}
      };

      c=getopt_long (argc, argv, "e:p:s:fuhvD:E:x:m", long_options,
		     &option_index);
      if (c == EOF)
	break;
      switch (c)
	{
	case 'e':
	  if (!strcmp (optarg, "chsh"))
	    allow_chsh = 1;
	  else if (!strcmp (optarg, "chfn"))
	    allow_chfn = 1;
	  else
	    usage (stderr, 1);
	  break;
	case 'p':
	  if (solaris_mode == 1)
	    usage (stderr, 1);
	  solaris_mode = 0;
	  path_passwd = optarg;
	  break;
	case 'f':
	  foreground_flag = 1;
	  break;
	case 's':
	  if (solaris_mode == 1)
	    usage (stderr, 1);
	  solaris_mode = 0;
	  path_shadow = optarg;
	  break;
	case 'D':
	  if (solaris_mode == 0)
	    usage (stderr, 1);
	  solaris_mode = 1;
	  path_passwd = malloc (strlen (optarg) + 8);
	  sprintf (path_passwd, "%s/passwd", optarg);
	  path_shadow = malloc (strlen (optarg) + 8);
	  sprintf (path_shadow, "%s/shadow", optarg);
	  break;
	case 'E':
	  external_update_program = strdup(optarg);
	  x_flag = 0;
	  break;
	case 'x':
	  external_update_program = strdup(optarg);
	  x_flag = 1;
	  break;
	case 'm':
	  if (solaris_mode == 0)
	    usage (stderr, 1);
	  solaris_mode = 1;
	  /* do nothing for now. We always run make, and we uses the
	     fastest arguments */
	  break;
	case 'h':
	  usage (stdout, 0);
	  break;
	case '\253':
          my_port = atoi (optarg);
	  if (my_port <= 0 || my_port > 0xffff) {
		/* Invalid port number */
	    fprintf (stdout, "Warning: rpc.yppasswdd: Invalid port %d (0x%x)\n",
			my_port, my_port);
		my_port = -1;
	  }
          if (debug_flag)
            log_msg ("Using port %d\n", my_port);
          break;
	case 'v':
#if CHECKROOT
	  fprintf (stdout, "rpc.yppasswdd - YP server version %s (with CHECKROOT)\n",
		   VERSION);
#else /* NO CHECKROOT */
	  fprintf (stdout, "rpc.yppasswdd - YP server version %s\n",
		   VERSION);
#endif /* CHECKROOT */
	  exit (0);
	case '\254': /* --debug */
	  debug_flag = 1;
	  break;
	default:
	  usage (stderr, 1);
	}
    }

  /* No more arguments allowed. */
  if (optind != argc)
    usage (stderr, 1);

  /* Create tmp and .OLD file names for "passwd" */
  path_passwd_tmp = malloc (strlen (path_passwd) + 5);
  if (path_passwd_tmp == NULL)
    {
      log_msg ("rpc.yppasswdd: out of memory\n");
      exit (-1);
    }
  sprintf (path_passwd_tmp, "%s.tmp", path_passwd);
  path_passwd_old = malloc (strlen (path_passwd) + 5);
  if (path_passwd_old == NULL)
    {
      log_msg ("rpc.yppasswdd: out of memory\n");
      exit (-1);
    }
  sprintf (path_passwd_old, "%s.OLD", path_passwd);
  /* Create tmp and .OLD file names for "shadow" */
  path_shadow_tmp = malloc (strlen (path_shadow) + 5);
  if (path_shadow_tmp == NULL)
    {
      log_msg ("rpc.yppasswdd: out of memory\n");
      exit (-1);
    }
  sprintf (path_shadow_tmp, "%s.tmp", path_shadow);
  path_shadow_old = malloc (strlen (path_shadow) + 5);
  if (path_shadow_old == NULL)
    {
      log_msg ("rpc.yppasswdd: out of memory\n");
      exit (-1);
    }
  sprintf (path_shadow_old, "%s.OLD", path_shadow);

  if (debug_flag)
    {
#if CHECKROOT
      log_msg ("rpc.yppasswdd - NYS YP server version %s (with CHECKROOT)\n",
	      VERSION);
#else /* NO CHECKROOT */
      log_msg ("rpc.yppasswdd - NYS YP server version %s\n", VERSION);
#endif /* CHECKROOT */
    }
  else if (!foreground_flag)
    {
      int i;

      /* We first fork off a child. */
      if ((i = fork ()) > 0)
	exit (0);

      if (i < 0)
	{
	  log_msg ("rpc.yppasswdd: cannot fork: %s\n", strerror (errno));
	  exit (-1);
	}

      if (setsid() == -1)
	{
	  log_msg ("rpc.yppasswdd: cannot setsid: %s\n", strerror (errno));
	  exit (-1);
	}

      if ((i = fork ()) > 0)
	exit (0);

      if (i < 0)
	{
	  int err = errno;
	  log_msg ("rpc.yppasswdd: cannot fork: %s\n", strerror (err));
	  exit (err);
	}

      for (i = 0; i < getdtablesize (); ++i)
        close (i);
      errno = 0;

      if (chdir ("/") == -1)
	{
	  int err = errno;
	  log_msg ("rpc.yppasswdd: chdir failed: %s\n", strerror (err));
	  exit (err);
	}
      umask(0);
      i = open("/dev/null", O_RDWR);
      if (i == -1)
	{
	  int err = errno;
	  log_msg ("rpc.yppasswdd: open /dev/null failed: %s\n",
		   strerror (err));
	  exit (err);
	}

      /* two dups, we have stdin, stdout, stderr */
      if (dup(i) == -1)
	{
	  int err = errno;
	  log_msg ("rpc.yppasswdd: dup failed: %s\n", strerror (err));
	  exit (err);
	}

      if (dup(i) == -1)
	{
	  int err = errno;
	  log_msg ("rpc.yppasswdd: dup failed: %s\n", strerror (err));
	  exit (err);
	}
    }

  create_pidfile (_YPPASSWDD_PIDFILE, "rpc.yppasswdd");

  /* Register a signal handler to reap children after they terminated */
  install_sighandler ();

  /* Create the RPC server */
  rpcb_unset (YPPASSWDPROG, YPPASSWDVERS, NULL);

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

      rpcb_unset (YPPASSWDPROG, YPPASSWDVERS, nconf);
      if (!svc_reg (xprt, YPPASSWDPROG, YPPASSWDVERS, yppasswdprog_1, nconf))
        {
          log_msg ("unable to register (YPPASSWDPROG, 1) for %s, %s.",
                   nconf->nc_protofmly, nconf->nc_proto);
          continue;
        }
      else
	could_register = 1;
    }
  __rpc_endconf (nc_handle);

  if (!could_register)
    {
      log_msg ("terminating: rpcbind not running?");
      return 1;
    }

  /* If we use systemd as an init system, we may want to give it
     a message, that this daemon is ready to accept connections.
     At this time, sockets for receiving connections are already
     created, so we can say we're ready now. It is a nop if we
     don't use systemd. */
  announce_ready();

  /* Run the server */
  svc_run ();
  log_msg ("svc_run returned\n");
  unlink (_YPPASSWDD_PIDFILE);
  return 1;
}
