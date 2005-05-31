/* Copyright (C) 1997, 1998, 1999, 2000, 2002, 2003 Thorsten Kukuk
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
   not, write to the Free Software Foundation, Inc., 675 Mass Ave,
   Cambridge, MA 02139, USA. */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <netdb.h>
#include <syslog.h>
#ifndef LOG_DAEMON
#include <sys/syslog.h>
#endif
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "log_msg.h"
#include "ypserv_conf.h"
#include "access.h"
#include "yp_db.h"
#include "yp.h"
#include "compat.h"

static conffile_t *conf = NULL;

void
load_config (void)
{
  conffile_t *tmp;

  if (conf != NULL)
    {
      log_msg ("Reloading %s/ypserv.conf", CONFDIR);
      while (conf)
	{
	  tmp = conf;
	  conf = conf->next;

	  free (tmp->map);
	  free (tmp);
	}
    }

  conf = load_ypserv_conf (CONFDIR);
}

/* Give a string with the DEFINE description back */
static char *
ypproc_name (int proc)
{
  switch (proc)
    {
    case YPPROC_NULL:
      return "ypproc_null";
    case YPPROC_DOMAIN:
      return "ypproc_domain";
    case YPPROC_DOMAIN_NONACK:
      return "ypproc_domain_nonack";
    case YPPROC_MATCH:
      return "ypproc_match";
    case YPPROC_FIRST:
      return "ypproc_first";
    case YPPROC_NEXT:
      return "ypproc_next";
    case YPPROC_XFR:
      return "ypproc_xfr";
    case YPPROC_CLEAR:
      return "ypproc_clear";
    case YPPROC_ALL:
      return "ypproc_all";
    case YPPROC_MASTER:
      return "ypproc_master";
    case YPPROC_ORDER:
      return "ypproc_order";
    case YPPROC_MAPLIST:
      return "ypproc_maplist";
    default:
      return "unknown ?";
    }
}

/* The is_valid_domain function checks the domain specified bye the
   caller to make sure it's actually served by this server.

   Return 1 if the name is a valid domain name served by us, else 0. */
int
is_valid_domain (const char *domain)
{
  struct stat sbuf;

  if (domain == NULL || domain[0] == '\0' ||
      strcmp (domain, "binding") == 0 ||
      strcmp (domain, "..") == 0 ||
      strcmp (domain, ".") == 0 ||
      strchr (domain, '/'))
    return 0;

  if (stat (domain, &sbuf) < 0 || !S_ISDIR (sbuf.st_mode))
    return 0;

  return 1;
}

/* By default, we use the securenet list, to check if the client
   is secure.

   return  1, if request comes from an authorized host
   return  0, if securenets does not allow access from this host
   return -1, if request comes from an unauthorized host
   return -2, if the map name is not valid
   return -3, if the domain is not valid */

int
is_valid (struct svc_req *rqstp, const char *map, const char *domain)
{
  const struct sockaddr_in *sin;
  int status;
  static unsigned long int oldaddr = 0;		/* so we dont log multiple times */
  static int oldstatus = -1;

  if (domain && is_valid_domain (domain) == 0)
    return -3;

  if (map && (map[0] == '\0' || strchr (map ,'/')))
    return -2;

  sin = svc_getcaller (rqstp->rq_xprt);

  status = securenet_host (sin->sin_addr);

  if ((map != NULL) && status)
    {
      conffile_t *work;

      work = conf;
      while (work)
	{
	  if ((sin->sin_addr.s_addr & work->netmask.s_addr) == work->network.s_addr)
	    if (strcmp (work->domain, domain) == 0 ||
		strcmp (work->domain, "*") == 0)
	      if (strcmp (work->map, map) == 0 || strcmp (work->map, "*") == 0)
		break;
	  work = work->next;
	}

      if (work != NULL)
	switch (work->security)
	  {
	  case SEC_NONE:
	    break;
	  case SEC_DENY:
	    status = -1;
	    break;
	  case SEC_PORT:
	    if (ntohs (sin->sin_port) >= IPPORT_RESERVED)
	      status = -1;
	    break;
	  }
      else if (domain != NULL)
	{
	  /* The map is not in the access list, maybe it
	     has a YP_SECURE key ? */
	  DB_FILE dbp = ypdb_open (domain, map);
	  if (dbp != NULL)
	    {
	      datum key;

	      key.dsize = sizeof ("YP_SECURE") - 1;
	      key.dptr = "YP_SECURE";
	      if (ypdb_exists (dbp, key))
		if (ntohs (sin->sin_port) >= IPPORT_RESERVED)
		  status = -1;
	      ypdb_close (dbp);
	    }
	}
    }

  if (debug_flag)
    {
      log_msg ("%sconnect from %s", status ? "" : "refused ",
	       inet_ntoa (sin->sin_addr));
    }
  else
    {
      if (status < 1 && ((sin->sin_addr.s_addr != oldaddr)
			 || (status != oldstatus)))
	syslog (LOG_WARNING,
		"refused connect from %s:%d to procedure %s (%s,%s;%d)\n",
		inet_ntoa (sin->sin_addr), ntohs (sin->sin_port),
		ypproc_name (rqstp->rq_proc),
		domain ? domain : "", map ? map : "", status);
    }
  oldaddr = sin->sin_addr.s_addr;
  oldstatus = status;

  return status;
}
