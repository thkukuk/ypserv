/* Copyright (c) 1996-2005, 2014, 2015, 2016 Thorsten Kukuk
   Author: Thorsten Kukuk <kukuk@suse.de>

   The YP Server is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License
   version 2 as published by the Free Software Foundation.

   The YP Server is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
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
#include <unistd.h>
#include <signal.h>
#include <rpc/rpc.h>
#include <time.h>
#include "yp.h"
#include <rpcsvc/ypclnt.h>
#include <rpc/svc.h>
#include <arpa/inet.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <ctype.h>
#include <netdb.h>
#include <errno.h>
#include <string.h>
#include <memory.h>
#if defined(HAVE_LIBGDBM)
#include <gdbm.h>
#elif defined(HAVE_LIBQDBM)
#include <hovel.h>
#elif defined(HAVE_NDBM)
#include <ndbm.h>
#include <fcntl.h>
#elif defined(HAVE_LIBTC)
#include <tcbdb.h>
#endif
#include <getopt.h>

#include "log_msg.h"

struct hostlist {
  char *hostname;
  struct hostlist *next;
};

struct hostlist *hostliste = NULL;

static char *DomainName = NULL;
int verbose_flag = 0;
static char local_hostname[MAXHOSTNAMELEN + 2];
static char *current_map;
static u_int CallbackProg = 0;
static u_int timeout = 90;
static u_int MapOrderNum;
static u_int maxchildren = 1;
static u_int children = 0;
static int my_port = -1;


static char *
yppush_err_string (enum yppush_status status)
{
  switch (status)
    {
    case YPPUSH_SUCC:
      return "Success";
    case YPPUSH_AGE:
      return "Master's version not newer";
    case YPPUSH_NOMAP:
      return "Can't find server for map";
    case YPPUSH_NODOM:
      return "Domain not supported";
    case YPPUSH_RSRC:
      return "Local resource alloc failure";
    case YPPUSH_RPC:
      return "RPC failure talking to server";
    case YPPUSH_MADDR:
      return "Can't get master address";
    case YPPUSH_YPERR:
      return "YP server/map db error";
    case YPPUSH_BADARGS:
      return "Request arguments bad";
    case YPPUSH_DBM:
      return "Local dbm operation failed";
    case YPPUSH_FILE:
      return "Local file I/O operation failed";
    case YPPUSH_SKEW:
      return "Map version skew during transfer";
    case YPPUSH_CLEAR:
      return "Can't send \"Clear\" req to local ypserv";
    case YPPUSH_FORCE:
      return "No local order number in map  use -f flag.";
    case YPPUSH_XFRERR:
      return "ypxfr error";
    case YPPUSH_REFUSED:
      return "Transfer request refused by ypserv";
    case YPPUSH_NOALIAS:
      return "Alias not found for map or domain";
    }
  return "YPPUSH: Unknown Error, this should not happen!";
}

bool_t
yppushproc_null_1_svc (void *req UNUSED,
		       void *resp UNUSED,
		       struct svc_req *rqstp UNUSED)
{
  resp = NULL;

  if (verbose_flag > 1)
    log_msg ("yppushproc_null_1_svc");

  return TRUE;
}


bool_t
yppushproc_xfrresp_1_svc (yppushresp_xfr *req,
			  void *resp UNUSED, struct svc_req *rqstp)
{
  char hostbuf[NI_MAXHOST];
  struct netconfig *nconf;
  struct netbuf *nbuf;

  if (verbose_flag > 1)
    log_msg ("yppushproc_xfrresp_1_svc");

  nbuf = svc_getrpccaller (rqstp->rq_xprt);
  nconf = getnetconfigent (rqstp->rq_xprt->xp_netid);

  if (verbose_flag)
    {
      log_msg ("Status received from ypxfr on %s",
	       taddr2host (nconf, nbuf, hostbuf, sizeof (hostbuf)));
      log_msg ("\tTransfer %sdone: %s",
	       req->status == YPPUSH_SUCC ? "" : "not ",
	       yppush_err_string (req->status));
    }
  else if (req->status != YPPUSH_SUCC)
    log_msg ("%s: %s", taddr2host (nconf, nbuf, hostbuf, sizeof (hostbuf)),
	     yppush_err_string (req->status));
  freenetconfigent (nconf);

  return TRUE;
}

static void
yppush_xfrrespprog_1(struct svc_req *rqstp, register SVCXPRT *transp)
{
  union {
    yppushresp_xfr yppushproc_xfrresp_1_arg;
  } argument;
  bool_t retval;
  xdrproc_t _xdr_argument, _xdr_result;
  bool_t (*local)(char *, void *, struct svc_req *);

  if (verbose_flag > 1)
    log_msg ("yppush_xfrrespprog_1");

  switch (rqstp->rq_proc) {
  case YPPUSHPROC_NULL:
    _xdr_argument = (xdrproc_t) xdr_void;
    _xdr_result = (xdrproc_t) xdr_void;
    local = (bool_t (*) (char *, void *,  struct svc_req *))yppushproc_null_1_svc;
    break;

  case YPPUSHPROC_XFRRESP:
    _xdr_argument = (xdrproc_t) xdr_yppushresp_xfr;
    _xdr_result = (xdrproc_t) xdr_void;
    local = (bool_t (*) (char *, void *,  struct svc_req *))yppushproc_xfrresp_1_svc;
    break;

  default:
    svcerr_noproc (transp);
    return;
  }
  memset ((char *)&argument, 0, sizeof (argument));
  if (!svc_getargs (transp, _xdr_argument, (caddr_t) &argument))
    {
      char hostbuf[NI_MAXHOST];
      struct netconfig *nconf;
      struct netbuf *nbuf = svc_getrpccaller (rqstp->rq_xprt);

      nconf = getnetconfigent (rqstp->rq_xprt->xp_netid);

      log_msg ("cannot decode arguments for %d from %s",
	       rqstp->rq_proc,
	       taddr2host (nconf, nbuf, hostbuf, sizeof (hostbuf)));
      /* try to free already allocated memory during decoding */
      svc_freeargs (transp, _xdr_argument, (caddr_t) &argument);
      freenetconfigent (nconf);
      svcerr_decode (transp);
      return;
    }
  retval = (bool_t) (*local)((char *)&argument, NULL, rqstp);
  if (retval > 0 && !svc_sendreply(transp, _xdr_result, NULL))
    {
      svcerr_systemerr (transp);
    }
  if (!svc_freeargs (transp, _xdr_argument, (caddr_t) &argument)) {
    log_msg ("unable to free arguments");
    exit (1);
  }

  if (rqstp->rq_proc != YPPUSHPROC_NULL)
    exit (0);

  return;
}

static void
yppush_svc_run (char *target)
{
  fd_set readfds;
  struct timeval tr, tb;

  tb.tv_sec = timeout;
  tb.tv_usec = 0;
  tr = tb;

  for (;;)
    {
      readfds = svc_fdset;

      switch (select (svc_maxfd+1, &readfds, (void *) 0, (void *) 0, &tr))
	{
	case -1:
	  if (errno == EINTR)
	    {
	      tr = tb;		/* Read the Linux select.2 manpage ! */
	      continue;
	    }
	  log_msg ("yppush_svc_run: - select failed (%s)", strerror (errno));
	  return;
	case 0:
	  log_msg ("%s->%s: Callback timed out", current_map, target);
	  exit (0);
	default:
	  svc_getreqset (&readfds);
	  break;
	}
    }
}

static char *
get_dbm_entry (char *key)
{
  static char mappath[MAXPATHLEN + 2];
  char *val;
  datum dkey, dval;
#if defined(HAVE_COMPAT_LIBGDBM)
  GDBM_FILE dbm;
#elif defined (HAVE_NDBM)
  DBM *dbm;
#elif defined (HAVE_LIBTC)
  TCBDB *dbm;
#endif

  if (strlen (YPMAPDIR) + strlen (DomainName) + strlen (current_map) + 3 < MAXPATHLEN)
    sprintf (mappath, "%s/%s/%s", YPMAPDIR, DomainName, current_map);
  else
    {
      log_msg ("YPPUSH ERROR: Path to long: %s/%s/%s", YPMAPDIR, DomainName, current_map);
      exit (1);
    }

#if defined(HAVE_COMPAT_LIBGDBM)
  dbm = gdbm_open (mappath, 0, GDBM_READER, 0600, NULL);
#elif defined(HAVE_NDBM)
  dbm = dbm_open (mappath, O_RDONLY, 0600);
#elif defined(HAVE_LIBTC)
  dbm = tcbdbnew();
  if (!tcbdbopen(dbm, mappath, BDBOREADER | BDBONOLCK))
    {
      tcbdbdel(dbm);
      dbm = NULL;
    }
#endif
  if (dbm == NULL)
    {
      log_msg ("YPPUSH: Cannot open %s", mappath);
      log_msg ("YPPUSH: consider rebuilding maps using ypinit");
      exit (1);
    }

  dkey.dptr = key;
  dkey.dsize = strlen (dkey.dptr);
#if defined(HAVE_COMPAT_LIBGDBM)
  dval = gdbm_fetch (dbm, dkey);
#elif defined(HAVE_NDBM)
  dval = dbm_fetch (dbm, dkey);
#elif defined(HAVE_LIBTC)
  dval.dptr = tcbdbget (dbm, dkey.dptr, dkey.dsize, &dval.dsize);
#endif
  if (dval.dptr == NULL)
    val = NULL;
  else
    {
      val = malloc (dval.dsize + 1);
      strncpy (val, dval.dptr, dval.dsize);
      val[dval.dsize] = 0;
    }
#if defined(HAVE_COMPAT_LIBGDBM)
  gdbm_close (dbm);
#elif defined(HAVE_NDBM)
  dbm_close (dbm);
#elif defined(HAVE_LIBTC)
  tcbdbclose (dbm);
  tcbdbdel (dbm);
#endif
  return val;
}

static u_int
getordernum (void)
{
  char *val;
  u_int i;

  val = get_dbm_entry ("YP_LAST_MODIFIED");

  if (val == NULL)
    {
      if (verbose_flag > 1)
	log_msg ("YPPUSH ERROR: Cannot determine order number for %s", current_map);
      free (val);
      return 0;
    }

  for (i = 0; i < strlen (val); ++i)
    {
      if (!isdigit (val[i]))
	{
	  log_msg ("YPPUSH ERROR: Order number '%s' in map %s is invalid!",
		   current_map, val);
	  free (val);
	  return 0;
	}
    }

  i = atoi (val);
  free (val);
  return i;
}

/* Create with the ypservers or slaves.hostname map a list with all
   slave servers we should send the new map */

/* NetBSD has a different prototype in struct ypall_callback */
#if defined(__NetBSD__)
static int
add_slave_server (u_long status, char *key, int keylen,
		  char *val, int vallen, void *data UNUSED)
#else
static int
add_slave_server (int status, char *key, int keylen,
		  char *val, int vallen, char *data UNUSED)
#endif
{
  char host[YPMAXPEER + 2];
  struct hostlist *tmp;

  if (verbose_flag > 1)
    log_msg ("add_slave_server: Key=%.*s, Val=%.*s, status=%d", keylen, key,
	     vallen, val, status);

  if (status != YP_TRUE)
    return status;

  if (vallen < YPMAXPEER)
    sprintf (host, "%.*s", vallen, val);
  else
    {
      log_msg ("YPPUSH ERROR: add_slave_server: %.*s to long", vallen, val);
      exit (1);
    }

  /* Do not add ourself! But don't put to much work into it. If
     the ypserver entry does not much the local name, we can also
     send the data to ourself. Better then to ignore a host only
     because it starts with the same name but is in a different
     domain.  */
  if (strcasecmp (local_hostname, host) == 0)
    {
      if (verbose_flag > 1)
	log_msg ("YPPUSH INFO: skipping %s", host);
      return 0;
    }

  if ((tmp = (struct hostlist *) malloc (sizeof (struct hostlist))) == NULL)
    {
      log_msg ("malloc() failed: %s", strerror (errno));
      return -1;
    }
  tmp->hostname = strdup (host);
  tmp->next = hostliste;
  hostliste = tmp;

  return 0;
}

static void
child_sig_int (int sig UNUSED)
{
  if (CallbackProg != 0)
    svc_unreg (CallbackProg, 1);
  exit (1);
}

static int
yppush_foreach (const char *host)
{
  SVCXPRT *CallbackXprt;
  CLIENT *PushClient;
  struct ypreq_newxfr newreq;
  struct timeval tv = {10, 0};
  u_int transid;
  char server[YPMAXPEER + 2];
  int i, sock;
  struct sigaction sig;
  struct netconfig *nconf;
  struct sockaddr *sa;
  struct sockaddr_in sin;
  struct sockaddr_in6 sin6;
  enum clnt_stat res;

  if (verbose_flag > 1)
    log_msg ("yppush_foreach: host=%s", host);

  sig.sa_handler = child_sig_int;
  sigemptyset (&sig.sa_mask);
  sig.sa_flags = SA_NOMASK;
  /* Do  not  prevent  the  signal   from   being
     received from within its own signal handler. */
  sigaction (SIGINT, &sig, NULL);

  if (strlen (host) < YPMAXPEER)
    sprintf (server, "%s", host);
  else
    {
      log_msg ("YPPUSH ERROR: yppush_foreach: %s to long", host);
      exit (1);
    }

  PushClient = clnt_create (server, YPPROG, YPVERS, "datagram_n");
  if (PushClient == NULL)
    {
      clnt_pcreateerror (server);
      return 1;
    }

  /* Register a socket for IPv4 and, if supported, for IPv6, too */
  if ((sock = socket (AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
    {
      log_msg ("Cannot create UDP socket for AF_INET: %s",
	       strerror (errno));
      return 1;
    }

  memset (&sin, 0, sizeof(sin));
  sin.sin_family = AF_INET;
  if (my_port > 0)
    sin.sin_port = htons (my_port);
  sa = (struct sockaddr *)(void *)&sin;

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

  if ((CallbackXprt = svc_dg_create (sock, 0, 0)) == NULL)
    {
      log_msg ("terminating: cannot create rpcbind handle");
      return 1;
    }

  nconf = getnetconfigent ("udp");
  if (nconf == NULL)
    {
      log_msg ("YPPUSH: getnetconfigent (\"udp\") failed.");
      exit (1);
    }
  for (CallbackProg = 0x40000000; CallbackProg < 0x5fffffff; CallbackProg++)
    {
      if (svc_reg (CallbackXprt, CallbackProg, 1,
		   yppush_xfrrespprog_1, nconf))
	break;
    }
  freenetconfigent (nconf);

  if (CallbackProg == 0x5FFFFFFF)
    {
      log_msg ("can't register yppush_xfrrespprog_1");
      exit (1);
    }
  else if (verbose_flag > 1)
    log_msg ("yppush_xfrrespprog_1 registered at %x", CallbackProg);

  /* And now do the same for IPv6 */
  if ((sock = socket (AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) >= 0)
    {
      /* Disallow v4-in-v6 to allow host-based access checks */
      if (setsockopt (sock, IPPROTO_IPV6, IPV6_V6ONLY,
		  &i, sizeof(i)) == -1)
	{
	  log_msg ("ERROR: cannot disable v4-in-v6 on %s6 socket",
	       nconf->nc_proto);
	  return 1;
	}
      memset (&sin6, 0, sizeof (sin6));
      sin6.sin6_family = AF_INET6;
      if (my_port > 0)
	sin6.sin6_port = htons (my_port);
      sa = (struct sockaddr *)(void *)&sin6;

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

      if ((CallbackXprt = svc_dg_create (sock, 0, 0)) == NULL)
	{
	  log_msg ("terminating: cannot create rpcbind handle");
	  return 1;
	}

      nconf = getnetconfigent ("udp6");
      if (nconf == NULL)
	{
	  log_msg ("YPPUSH: getnetconfigent (\"udp6\") failed.");
	  exit (1);
	}
      if (!svc_reg (CallbackXprt, CallbackProg, 1,
		   yppush_xfrrespprog_1, nconf))
	log_msg ("YPPUSH: couldn't register IPv6");
      freenetconfigent (nconf);
    }
  else if (errno != EAFNOSUPPORT)
    {
      log_msg ("Cannot create UDP socket for AF_INET6: %s",
	       strerror (errno));
      return 1;
    }

  switch (transid = fork ())
    {
    case -1:
      perror ("Cannot fork");
      exit (-1);
    case 0:
      yppush_svc_run (server);
      exit (0);
    default:
      newreq.map_parms.domain = (char *) DomainName;
      newreq.map_parms.map = (char *) current_map;
      /* local_hostname is correct since we have compared it
	 with YP_MASTER_NAME.  */
      newreq.map_parms.owner = local_hostname;
      newreq.map_parms.ordernum = MapOrderNum;
      newreq.transid = transid;
      newreq.proto = CallbackProg;
      // req.port = CallbackXprt->xp_port;
      newreq.name = server;

      if (verbose_flag)
	{
	  log_msg ("%s has been called.", server);
	  if (verbose_flag > 1)
	    {
	      log_msg ("\t->target: %s", server);
	      log_msg ("\t->domain: %s", newreq.map_parms.domain);
	      log_msg ("\t->map: %s", newreq.map_parms.map);
	      log_msg ("\t->tarnsid: %d", newreq.transid);
	      log_msg ("\t->proto: %d", newreq.proto);
	      log_msg ("\t->master: %s", newreq.map_parms.owner);
	      log_msg ("\t->ordernum: %d", newreq.map_parms.ordernum);
	      log_msg ("\t->name: %s", newreq.name);
	    }
	}


      res = clnt_call (PushClient, YPPROC_NEWXFR, (xdrproc_t) xdr_ypreq_newxfr,
		       (caddr_t) &newreq, (xdrproc_t) xdr_void, NULL, tv);

      if (res == RPC_PROCUNAVAIL)
	{
	  struct ypreq_xfr oldreq;

	  oldreq.map_parms.domain = (char *) DomainName;
	  oldreq.map_parms.map = (char *) current_map;
	  oldreq.map_parms.owner = local_hostname;
	  oldreq.map_parms.ordernum = MapOrderNum;
	  oldreq.transid = transid;
	  oldreq.proto = CallbackProg;
	  oldreq.port = 0; /* we don't really need that */

	  res = clnt_call (PushClient, YPPROC_XFR, (xdrproc_t) xdr_ypreq_xfr,
			   (caddr_t) &oldreq, (xdrproc_t) xdr_void, NULL, tv);
	}

      if (res != RPC_SUCCESS)
	{
	  log_msg ("YPPUSH: Cannot call YPPROC_XFR on host \"%s\"%s", server,
		   clnt_sperror (PushClient, ""));
	  kill (transid, SIGTERM);
	}

      waitpid (transid, &sock, 0);
      svc_unreg (CallbackProg, 1);
      CallbackProg = 0;
      if (PushClient != NULL)
	{
	  clnt_destroy (PushClient);
	  PushClient = NULL;
	}
    }

  return 0;
}

static char *
get_canonical_hostname (const char *hostname)
{
#if USE_FQDN
  struct addrinfo hints, *res0, *res1;
  int error;
  char *host = NULL;

  memset (&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
#if 0
  hints.ai_flags = AI_CANONNAME;  /* get the official name of the host */
#endif

  if ((error = getaddrinfo (hostname, NULL, &hints, &res0)))
    {
#if 0
      printf ("getaddrinfo: %s\n", gai_strerror (error));
#endif
      return strdup (hostname);
    }

  res1 = res0;

  while (res1)
    {
      char hostbuf[NI_MAXHOST];

      if ((error = getnameinfo (res1->ai_addr, res1->ai_addrlen,
                                (char *)&hostbuf, sizeof (hostbuf),
                                NULL, 0, NI_NAMEREQD)) == 0)
        {
          host = strdup (hostbuf);
          break;
        }
#if 0
      else
        printf ("getnameinfo: %s\n", gai_strerror (error));
#endif

      res1 = res1->ai_next;
    }

  if (host == NULL)
    host = strdup (res0->ai_canonname);

  freeaddrinfo (res0);

  return host;
#else
  return strdup (hostname);
#endif
}

static void
sig_child (int sig UNUSED)
{
  int status;
  int save_errno = errno;

  while (waitpid (-1, &status, WNOHANG) > 0)
    {
      if (verbose_flag > 1)
	log_msg ("Child %d exits", WEXITSTATUS (status));
      children--;
    }

  errno = save_errno;
}

static inline void
Usage (int exit_code)
{
  log_msg ("Usage:\n  yppush [-d domain] [-t timeout] [--parallel # | --port #] [-h host] [-v] mapname ...");
  log_msg ("  yppush --version");
  exit (exit_code);
}

int
main (int argc, char **argv)
{
  struct hostlist *tmp;
  enum ypstat y;
  struct sigaction sig;

  debug_flag = 1;

  sig.sa_handler = sig_child;
  sigemptyset (&sig.sa_mask);
#if defined(linux) || (defined(sun) && defined(__srv4__))
  sig.sa_flags = SA_NOMASK;
  /* Do  not  prevent  the  signal   from   being
     received from within its own signal handler. */
#endif
  sigaction (SIGCHLD, &sig, NULL);

  while (1)
    {
      int c;
      int option_index = 0;
      static struct option long_options[] =
      {
	{"version", no_argument, NULL, '\255'},
	{"verbose", no_argument, NULL, 'v'},
	{"host", required_argument, NULL, 'h'},
	{"help", no_argument, NULL, 'u'},
	{"usage", no_argument, NULL, 'u'},
	{"parallel", required_argument, NULL, 'p'},
	{"port", required_argument, NULL, '\254'},
	{"timeout", required_argument, NULL, 't'},
	{NULL, 0, NULL, '\0'}
      };

      c = getopt_long (argc, argv, "d:vh:ut:p:j:", long_options, &option_index);
      if (c == EOF)
	break;
      switch (c)
	{
	case 'd':
	  DomainName = optarg;
	  break;
	case 'v':
	  verbose_flag++;
	  break;
	case 't':
	  timeout = atoi (optarg);
	  break;
	case 'j':
	case 'p':
	  maxchildren = atoi (optarg);
	  if (my_port >= 0)
	    {
	      log_msg ("yppush cannot run in parallel with a fixed port");
	      return 1;
	    }
	  break;
	case 'h':
	  /* we can handle multiple hosts */
	  tmp = (struct hostlist *) malloc (sizeof (struct hostlist));
	  if (tmp == NULL)
	    {
	      log_msg ("malloc() failed: %s", strerror (errno));
	      return 1;
	    }
	  tmp->hostname = strdup (optarg);
	  tmp->next = hostliste;
	  hostliste = tmp;
	  break;
	case 'u':
	  Usage (0);
	  break;
	case '\255':
          log_msg ("yppush (%s) %s", PACKAGE, VERSION);
          return 0;
	case '\254':
	  my_port = atoi (optarg);
	  if (maxchildren > 1)
	    {
	      log_msg ("yppush cannot run in parallel with a fixed port");
	      return 1;
	    }
	  if (my_port <= 0 || my_port > 0xffff) {
	    /* Invalid port number */
	    fprintf (stdout, "Warning: yppush: Invalid port %d (0x%x)\n",
			my_port, my_port);
	    my_port = -1;
	  }
	  break;
	default:
	  Usage (1);
	}
    }

  argc -= optind;
  argv += optind;

  if (argc < 1)
    Usage (1);

  if (DomainName == NULL)
    {
      if (yp_get_default_domain (&DomainName) != 0)
	{
	  log_msg ("YPPUSH: Cannot get default domain");
	  return 1;
	}
      if (strlen(DomainName) == 0)
	{
	  log_msg ("YPPUSH: Domainname not set");
	  return 1;
	}
    }

  if (gethostname (local_hostname, MAXHOSTNAMELEN) != 0)
    {
      perror ("YPPUSH: gethostname");
      log_msg ("YPPUSH: Cannot determine local hostname");
      return 1;
    }
  else
    {
      char *cp;

      cp = get_canonical_hostname (local_hostname);
      strncpy (local_hostname, cp, sizeof (local_hostname) -1);
    }


  if (hostliste == NULL)
    {
      struct ypall_callback f;

      memset (&f, 0, sizeof f);
      f.foreach = add_slave_server;
      y = yp_all (DomainName, "ypservers", &f);
      if (y && y != YP_NOMORE)
	{
	  log_msg ("Could not read ypservers map: %d %s", y, yperr_string (y));
	}
    }

  while (*argv)
    {
      char *val;

      current_map = *argv++;
      val = get_dbm_entry ("YP_MASTER_NAME");
      if (val && strcasecmp (val, local_hostname) != 0)
	{
	  log_msg ("YPPUSH: %s is not the master for %s, try it from %s.",
		  local_hostname, current_map, val);
	  free (val);
	  continue;
	}
      else if (val)
	free (val);

      MapOrderNum = getordernum ();
#if 0
      if (MapOrderNum == 0xffffffff)
	continue;
#endif
      tmp = hostliste;
      while (tmp != NULL)
	{
	  while (children >= maxchildren)
	    sleep (1);
	  children++;
	  switch (fork ())
	    {
	    case -1:
	      perror ("YPPUSH: Cannot fork");
	      exit (1);
	    case 0:
	      yppush_foreach (tmp->hostname);
	      exit (children);
	    default:
	      if (verbose_flag > 1)
		log_msg ("Start new child (%d)", children);
	      break;
	    }
	  tmp = tmp->next;
	}
      while (children != 0)
	{
	  sleep (10);
	  if (verbose_flag > 1)
	    log_msg ("Running Children: %d", children);
	}
    }

  if (verbose_flag > 1)
    log_msg ("all done (%d running childs)", children);

  return 0;
}
