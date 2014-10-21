/* Copyright (c) 1996, 1999, 2001, 2002, 2009, 2012 Thorsten Kukuk
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

/* mknetid - generate netid.byname map.  */

#if defined(HAVE_CONFIG_H)
#include "config.h"
#endif

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <rpc/types.h>
#include <rpcsvc/ypclnt.h>
#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif

#include "mknetid.h"
#include "compat.h"

static int quiet_flag = 0;

char *
xstrtok (char *cp, int delim)
{
  static char *str = NULL;

  if (cp)
    str = cp;

  if (*str == '\0')
    return NULL;

  cp = str;

  if (delim == ' ')
    while (*str && (!isspace (*str)))
      str++;
  else
    while (*str && *str != delim)
      str++;

  if (*str)
    *str++ = '\0';

  return cp;
}

static void
Usage (int exitcode)
{
  fputs ("Usage: mknetid [-q] [-h hosts] [-p passwd] [-g group] [-d domain] [-n netid]\n",
	 stderr);
  fputs ("Usage: mknetid --version\n", stderr);
  exit (exitcode);
}

int
main (int argc, char *argv[])
{
  char *line = NULL;
  size_t length = 0;
  char *pwname = "/etc/passwd";
  char *grpname = "/etc/group";
  char *hostname = "/etc/hosts";
  char *netidname = "/etc/netid";
  char *domain = NULL;
  FILE *file;

  while (1)
    {
      int c;
      int option_index = 0;
      static struct option long_options[] =
      {
	{"version", no_argument, NULL, 'v'},
	{"host", required_argument, NULL, 'h'},
	{"group", required_argument, NULL, 'g'},
	{"passwd", required_argument, NULL, 'p'},
	{"netid", required_argument, NULL, 'n'},
	{"domain", required_argument, NULL, 'd'},
	{"quiet", no_argument, NULL, 'q'},
	{"help", no_argument, NULL, 'u'},
	{"usage", no_argument, NULL, 'u'},
	{NULL, 0, NULL, '\0'}
      };

      c = getopt_long (argc, argv, "uvqh:g:p:d:n:", long_options, &option_index);
      if (c == EOF)
	break;
      switch (c)
	{
	case 'q':
	  quiet_flag = 1;
	  break;
	case 'h':
	  hostname = optarg;
	  break;
	case 'g':
	  grpname = optarg;
	  break;
	case 'p':
	  pwname = optarg;
	  break;
	case 'n':
	  netidname = optarg;
	  break;
	case 'd':
	  domain = optarg;
	  break;
	case 'u':
	  Usage (0);
	  break;
	case 'v':
	  fprintf (stderr, "mknetid (%s) %s\n", PACKAGE, VERSION);
	  exit (0);
	default:
	  Usage (1);
	}
    }
  argc -= optind;
  argv += optind;

  if (argc != 0)
    Usage (1);

  if (domain == NULL)
    {
      if (yp_get_default_domain (&domain) != 0)
	{
	  fprintf (stderr, "YPPUSH: Cannot get default domain\n");
	  return 1;
	}
    }

  if ((file = fopen (pwname, "r")) == NULL)
    {
      fprintf (stderr, "ERROR: Can't open %s\n", pwname);
      exit (1);
    }

  while (!feof (file))
    {
#if HAVE_GETDELIM
      ssize_t n = getdelim (&line, &length, '\n', file);
#else
      ssize_t n = getline (&line, &length, file);
#endif
      if (n < 1)
	break;

      if (line[0] != '+' && line[0] != '-')
	{

	  char *ptr, *key, *uid, *gid;
	  char *err_line = strdup (line);

	  key = xstrtok (line, ':');
	  ptr = xstrtok (NULL, ':');
	  uid = xstrtok (NULL, ':');
	  gid = xstrtok (NULL, ':');

	  if (key == NULL || ptr == NULL ||
	      uid == NULL || gid == NULL)
	    {
	      int n = strlen (err_line);

	      if (err_line[n - 1] == '\n')
		err_line[n - 1] = '\0';

	      if (strlen (err_line) > 0)
		fprintf (stderr, "WARNING: bad netid entry: '%s'\n",
			 err_line);
	      free (err_line);
	      continue;
	    }

	  free (err_line);

	  if (insert_user (key, domain, uid, gid) < 0)
	    if (!quiet_flag)
	      fprintf (stderr,
		       "WARNING: unix.%s@%s multiply defined, ignore new one\n",
		       uid, domain);
	}
    }
  fclose (file);

  if ((file = fopen (grpname, "r")) == NULL)
    {
      fprintf (stderr, "ERROR: Can't open %s\n", grpname);
      exit (1);
    }

  while (!feof (file))
    {
#if HAVE_GETDELIM
      ssize_t n = getdelim (&line, &length, '\n', file);
#else
      ssize_t n = getline (&line, &length, file);
#endif
      if (n < 1)
	break;

      if (line[n - 1] == '\n')
        {
          if(n < 2)
            continue; /* empty line */
	  line[n - 1] = '\0';
        }

      if (line[0] != '+' && line[0] != '-')
	{
	  char *grpname, *ptr, *gid, *user;

	  grpname = xstrtok (line, ':');
	  ptr = xstrtok (NULL, ':');
	  gid = xstrtok (NULL, ':');
	  if(grpname && ptr && gid)
	    length -= gid - line;
	  else
	    {
	      fprintf (stderr, "ERROR: bad format of group \"%s\".\n",
		       grpname);
	      exit (1);
	    }
	  user = xstrtok (NULL, ',');
	  while (user != NULL) {
	    length = length - strlen(user) - 1;
	    if (add_group (user, gid) < 0)
	      if (!quiet_flag)
		fprintf (stderr, "WARNING: unknown user \"%s\" in group \"%s\".\n",
			 user, grpname);
	    if (length > 0)
	      user = xstrtok (user + strlen(user) + 1, ',');
	    else
	      user = NULL;
	  }
	}
    }
  fclose (file);

  if ((file = fopen (hostname, "r")) == NULL)
    {
      fprintf (stderr, "ERROR: Can't open %s\n", hostname);
      exit (1);
    }

  while (!feof (file))
    {
#if HAVE_GETDELIM
      ssize_t n = getdelim (&line, &length, '\n', file);
#else
      ssize_t n = getline (&line, &length, file);
#endif
      if (n < 1)
	break;

      if (line[0] != '#')
	{
	  char *ptr, *host;

	  ptr = xstrtok (line, ' ');
	  host = xstrtok (NULL, ' ');
	  while (host != NULL && strlen (host) == 0)
	    host = xstrtok (NULL, ' ');

	  if (host != NULL)
	    if (insert_host (host, domain) < 0)
	      if (!quiet_flag)
		fprintf (stderr, "WARNING: unix.%s@%s multiply defined, ignore new one\n",
			 host, domain);
	}
    }

  fclose (file);

  print_table ();

  /*
  ** If /etc/netid does not exist, ignore it
  */
  if ((file = fopen (netidname, "r")) != NULL)
    {
      while (!feof (file))
	{
#if HAVE_GETDELIM
	  ssize_t n = getdelim (&line, &length, '\n', file);
#else
	  ssize_t n = getline (&line, &length, file);
#endif
	  if (n < 1)
	    break;

	  if (line[0] != '#')
	    {
	      int n = strlen (line);

	      if (line[n - 1] == '\n')
		line[n - 1] = '\0';
	      if (strpbrk (line, " \t") == NULL)
		{
		  if (strlen (line) > 0)
		    fprintf (stderr,
			     "WARNING: bad netid entry: '%s'\n",
			     line);
		}
	      else
		printf ("%s\n", line);
	    }
	}
      fclose (file);
    }

  free (line);
  return 0;
}
