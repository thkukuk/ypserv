/* Copyright (c) 1999, 2001, 2002, 2011, 2013, 2014 Thorsten Kukuk
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

#if defined(HAVE_CONFIG_H)
#include "config.h"
#endif

#include <sys/types.h>
#include <grp.h>
#include <pwd.h>
#include <netdb.h>
#include <rpc/types.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <ctype.h>
#include <alloca.h>
#include <stdlib.h>
#include <getopt.h>
#if defined(HAVE_LIBGDBM)
#include <gdbm.h>
#elif defined(HAVE_LIBQDBM)
#include <hovel.h>
#elif defined(HAVE_NDBM)
#include <ndbm.h>
#elif defined(HAVE_LIBTC)
#include <tcbdb.h>
#endif
#include "yp.h"
#include <rpcsvc/ypclnt.h>
#include <arpa/nameser.h>
#include <shadow.h>

struct __sgrp {
  char *sg_name;       /* group name */
  char *sg_passwd;     /* group password */
};


#ifndef YPERR_SUCCESS
#define YPERR_SUCCESS   0
#endif

static struct timeval UDPTIMEOUT = {5, 0};

static int
_yp_maplist (const char *server, char *indomain,
	     struct ypmaplist **outmaplist)
{
  CLIENT *clnt;
  struct ypresp_maplist resp;
  enum clnt_stat result;

  if (indomain == NULL || indomain[0] == '\0')
    return YPERR_BADARGS;

  memset (&resp, '\0', sizeof (resp));
  clnt = clnt_create (server, YPPROG, YPVERS, "udp");
  if (clnt == NULL)
    exit (1);

  result = clnt_call (clnt, YPPROC_MAPLIST, (xdrproc_t) xdr_domainname,
		      (caddr_t) & indomain, (xdrproc_t) xdr_ypresp_maplist,
		      (caddr_t) & resp, UDPTIMEOUT);

  if (result != YPERR_SUCCESS)
    return result;
  if (resp.status != YP_TRUE)
    return ypprot_err (resp.status);

  *outmaplist = resp.list;
  /* We give the list not free, this will be done by ypserv
     xdr_free((xdrproc_t)xdr_ypresp_maplist, (char *)&resp); */

  return YPERR_SUCCESS;
}

static int
_yp_master (const char *server, char *indomain, char *inmap, char **outname)
{
  CLIENT *clnt;
  ypreq_nokey req;
  ypresp_master resp;
  enum clnt_stat result;

  if (indomain == NULL || indomain[0] == '\0' ||
      inmap == NULL || inmap[0] == '\0')
    return YPERR_BADARGS;

  req.domain = indomain;
  req.map = inmap;

  memset (&resp, '\0', sizeof (resp));
  clnt = clnt_create (server, YPPROG, YPVERS, "udp");
  if (clnt == NULL)
    exit (1);
  result = clnt_call (clnt, YPPROC_MASTER, (xdrproc_t) xdr_ypreq_nokey,
		      (caddr_t) & req, (xdrproc_t) xdr_ypresp_master,
		      (caddr_t) & resp, UDPTIMEOUT);

  if (result != YPERR_SUCCESS)
    return result;
  if (resp.status != YP_TRUE)
    return ypprot_err (resp.status);

  *outname = strdup (resp.master);
  xdr_free ((xdrproc_t) xdr_ypresp_master, (char *) &resp);

  return *outname == NULL ? YPERR_YPERR : YPERR_SUCCESS;
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

/* print theofficial name of the host as returned by DNS */
static void
print_hostname (char *param)
{
  char hostname[MAXHOSTNAMELEN + 1];

  if (param == NULL)
    gethostname (hostname, sizeof (hostname));
  else
    {
      strncpy (hostname, param, sizeof (hostname));
      hostname[sizeof (hostname) - 1] = '\0';
    }

  printf ("%s\n", get_canonical_hostname (hostname));

  exit (0);
}

/* Show the master for all maps */
static void
print_maps (char *server, char *domain)
{
  char *master = NULL, *domainname;
  struct ypmaplist *ypmap = NULL, *y, *old;
  int ret;

  if (domain != NULL)
    domainname = domain;
  else
    if ((ret = yp_get_default_domain (&domainname)) != 0)
      {
	fprintf (stderr, "can't get local yp domain: %s\n",
		 yperr_string (ret));
	exit (1);
      }

  server = get_canonical_hostname (server);

  ret = _yp_maplist (server, domainname, &ypmap);
  switch (ret)
    {
    case YPERR_SUCCESS:
      for (y = ypmap; y;)
	{
	  ret = _yp_master (server, domainname, y->map, &master);
	  if (ret == YPERR_SUCCESS)
	    {
	      if (strcasecmp (server, master) == 0)
		printf ("%s\n", y->map);

	      free (master);
	    }
	  old = y;
	  y = y->next;
	  free (old);
	}
      break;
    default:
#if 0
      printf ("_yp_maplist %s\n", yperr_string (ret));
#endif
      exit (1);
    }

  free (server);
  exit (0);
}

static void
merge_passwd (char *passwd, char *shadow)
{
  FILE *p_input, *s_input;
  struct passwd *pwd;
  struct spwd *spd;

  p_input = fopen (passwd, "r");
  if (p_input == NULL)
    {
      fprintf (stderr, "yphelper: Cannot open %s\n", passwd);
      exit (1);
    }

  s_input = fopen (shadow, "r");
  if (s_input == NULL)
    {
      fclose (p_input);
      fprintf (stderr, "yphelper: Cannot open %s\n", shadow);
      exit (1);
    }

  while ((pwd = fgetpwent (p_input)) != NULL)
    {
      char *pass;

      if (pwd->pw_name[0] == '-' || pwd->pw_name[0] == '+' ||
	  pwd->pw_name == NULL || pwd->pw_name[0] == '\0')
	continue;

      /* If we found an passwd entry which could have a shadow
	 password, we try the following:
	 At first, try the next entry in the shadow file. If we
	 have luck, the shadow file is sorted in the same order
	 then as the passwd file is. If not, try the whole shadow
	 file. */

      /* Some systems and old programs uses '*' as marker for shadow! */
      if (pwd->pw_passwd[1] == '\0' &&
	  (pwd->pw_passwd[0] == 'x' || pwd->pw_passwd[0] == '*'))
	{
	  pass = NULL;
	  spd = fgetspent (s_input);
	  if (spd != NULL)
	    {
	      if (strcmp (pwd->pw_name, spd->sp_namp) == 0)
		pass = spd->sp_pwdp;
	    }
	  if (pass == NULL)
	    {
	      rewind (s_input);
	      while ((spd = fgetspent (s_input)) != NULL)
		{
		  if (strcmp (pwd->pw_name, spd->sp_namp) == 0)
		    {
		      pass = spd->sp_pwdp;
		      break;
		    }
		}
	    }
	  if (pass == NULL)
	    pass = pwd->pw_passwd;
	}
      else
	pass = pwd->pw_passwd;

      fprintf (stdout, "%s:%s:%d:%d:%s:%s:%s\n",
	       pwd->pw_name, pass, pwd->pw_uid,
	       pwd->pw_gid, pwd->pw_gecos, pwd->pw_dir,
	       pwd->pw_shell);
    }
  fclose (p_input);
  fclose (s_input);

  exit (0);
}

static struct __sgrp *
fgetsgent (FILE *fp)
{
  static struct __sgrp sgroup;
  static char sgrbuf[BUFSIZ*4];
  char *cp;

  if (! fp)
    return 0;

  if (fgets (sgrbuf, sizeof (sgrbuf), fp) != (char *) 0)
    {
      if ((cp = strchr (sgrbuf, '\n')))
	*cp = '\0';

      sgroup.sg_name = sgrbuf;
      if ((cp = strchr (sgrbuf, ':')))
	*cp++ = '\0';

      if (cp == NULL)
	return 0;

      sgroup.sg_passwd = cp;
      if ((cp = strchr (cp, ':')))
	*cp++ = '\0';

      return &sgroup;
    }
  return 0;
}

static void
merge_group (char *group, char *gshadow)
{
  FILE *g_input, *s_input;
  struct group *grp;
  struct __sgrp *spd;
  int i;

  g_input = fopen (group, "r");
  if (g_input == NULL)
    {
      fprintf (stderr, "yphelper: Cannot open %s\n", group);
      exit (1);
    }

  s_input = fopen (gshadow, "r");
  if (s_input == NULL)
    {
      fclose (g_input);
      fprintf (stderr, "yphelper: Cannot open %s\n", gshadow);
      exit (1);
    }

  while ((grp = fgetgrent (g_input)) != NULL)
    {
      char *pass;

      if (grp->gr_name[0] == '-' || grp->gr_name[0] == '+' ||
	  grp->gr_name == NULL || grp->gr_name[0] == '\0')
	continue;

      /* If we found an group entry which could have a shadow
	 password, we try the following:
	 At first, try the next entry in the gshadow file. If we
	 have luck, the gshadow file is sorted in the same order
	 then as the group file is. If not, try the whole gshadow
	 file. */
      /* Some systems and old programs uses '*' as marker for shadow! */
      if (grp->gr_passwd[1] == '\0' &&
	  (grp->gr_passwd[0] == 'x' || grp->gr_passwd[0] == '*'))
	{
	  pass = NULL;

	  spd = fgetsgent (s_input);
	  if (spd != NULL)
	    {
	      if (strcmp (grp->gr_name, spd->sg_name) == 0)
		pass = spd->sg_passwd;
	    }
	  if (pass == NULL)
	    {
	      rewind (s_input);
	      while ((spd = fgetsgent (s_input)) != NULL)
		{
		  if (strcmp (grp->gr_name, spd->sg_name) == 0)
		    {
		      pass = spd->sg_passwd;
		      break;
		    }
		}
	    }

	  if (pass == NULL)
	    pass = grp->gr_passwd;
	}
      else
	pass = grp->gr_passwd;

      fprintf (stdout, "%s:%s:%d:", grp->gr_name, pass, grp->gr_gid);
      i =  0;
      while (grp->gr_mem[i] != NULL)
        {
          if (i != 0)
            fprintf (stdout, ",");
          fprintf (stdout, "%s", grp->gr_mem[i]);
          ++i;
        }
      printf ("\n");
    }
  fclose (g_input);
  fclose (s_input);

  exit (0);
}

static char *
get_dbm_entry (char *key, char *map, char *domainname)
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

  if (strlen (YPMAPDIR) + strlen (domainname) + strlen (map) + 3 < MAXPATHLEN)
    sprintf (mappath, "%s/%s/%s", YPMAPDIR, domainname, map);
  else
    {
      fprintf (stderr, "yphelper: path to long: %s/%s/%s\n", YPMAPDIR, domainname, map);
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
      fprintf (stderr, "yphelper: cannot open %s\n", mappath);
      fprintf (stderr, "yphelper: consider rebuilding maps using ypinit\n");
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

/* Show the master for all maps */
static void
is_master (char *map, char *domainname, char *host)
{
  char h_tmp[MAXHOSTNAMELEN+1];
  char *hostname, *val;
  int ret;

  if (host)
    hostname = host;
  else
    {
      if (gethostname (h_tmp, sizeof (h_tmp)) != 0)
	{
	  perror ("gethostname");
	  exit (1);
	}
      hostname = h_tmp;
    }

  hostname = get_canonical_hostname (hostname);

  if (strcasecmp (hostname,
		  (val = get_dbm_entry ("YP_MASTER_NAME", map, domainname)))
      == 0)
    ret = 0;
  else
    ret = 1;

  free(hostname);
  exit (ret);
}

static void
Warning (void)
{
  fprintf (stderr, "yphelper: This program is for internal use from some\n");
  fprintf (stderr, "          ypserv scripts and should never be called\n");
  fprintf (stderr, "          from a terminal\n");
  exit (1);
}

int
main (int argc, char *argv[])
{
  int hostname = 0;
  char *master = NULL;
  char *domainname = NULL;
  char *map = NULL;
  int merge_pwd = 0;
  int merge_grp = 0;

  while (1)
    {
      int c;
      int option_index = 0;
      static struct option long_options[] =
	{
	  {"hostname", no_argument, NULL, 'h'},
	  {"version", no_argument, NULL, 'v'},
	  {"maps", required_argument, NULL, 'm'},
	  {"merge_passwd", no_argument, NULL, 'p'},
	  {"merge-passwd", no_argument, NULL, 'p'},
	  {"merge_group", no_argument, NULL, 'g'},
	  {"merge-group", no_argument, NULL, 'g'},
	  {"domainname", required_argument, NULL, 'd'},
	  {"is_master", required_argument, NULL, 'i'},
	  {"is-master", required_argument, NULL, 'i'},
	  {NULL, 0, NULL, '\0'}
	};

      c = getopt_long (argc, argv, "d:hvm:pgi:", long_options, &option_index);
      if (c == EOF)
        break;
      switch (c)
	{
	case 'd':
	  domainname = optarg;
	  break;
	case 'h':
	  ++hostname;
	  break;
	case 'm':
	  master = optarg;
	  break;
	case 'p':
	  merge_pwd = 1;
	  break;
	case 'g':
	  merge_grp = 1;
	  break;
	case 'v':
	  printf ("yphelper (%s) %s", PACKAGE, VERSION);
	  exit (0);
	case 'i':
	  map = optarg;
	  break;
	default:
	  Warning ();
	  return 1;
	}
    }

  argc -= optind;
  argv += optind;

  if (hostname)
    {
      if (argc == 0)
	print_hostname (NULL);
      else
	print_hostname (argv[0]);
    }

  if (merge_pwd && argc == 2)
    merge_passwd (argv[0], argv[1]);

  if (merge_grp && argc == 2)
    merge_group (argv[0], argv[1]);

  if (domainname == NULL)
    {
      int ret;

      if ((ret = yp_get_default_domain (&domainname)) != 0)
	{
	  fprintf (stderr, "can't get local yp domain: %s\n",
		   yperr_string (ret));
	  exit (1);
	}
    }

  if (master != NULL)
    print_maps (master, domainname);

  if (map)
    is_master (map, domainname, NULL);

  Warning ();
  return 1;
}
