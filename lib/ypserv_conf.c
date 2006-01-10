/* Copyright (c) 1996, 1997, 1998, 1999, 2000, 2001, 2003, 2004, 2006 Thorsten Kukuk
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

#define _GNU_SOURCE

#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#ifdef HAVE_ALLOCA_H
#include <alloca.h>
#endif /* HAVE_ALLOCA_H */
#include <unistd.h>

#include "log_msg.h"
#include "ypserv_conf.h"
#include "compat.h"

int dns_flag = 0;
#if USE_SLP
int slp_flag = 0;
unsigned long int slp_timeout = 3600;
#endif
int xfr_check_port = 0;
char *trusted_master = NULL;
/* cached_filehandles (how many databases will be cached):
   big -> slow list searching, we go 3 times through the list.
   little -> have to close/open very often.
   We now uses 30, because searching 3 times in the list is faster
   then reopening the database.
   You can open max. 255 file handles.
*/
int cached_filehandles = 30;


static int
getipnr (char *n, char *network, char *netmask)
{
  char *m;
  size_t i;
  int pw, pm;
  char buf[20];

  pw = pm = 0;

  m = strtok (n, "/");

  sscanf (m, "%s", buf);

  for (i = 0; i < strlen (buf); i++)
    if ((buf[i] < '0' || buf[i] > '9') && buf[i] != '.')
      return 1;
    else if (buf[i] == '.')
      ++pw;

  strcpy (network, buf);
  switch (pw)
    {
    case 0:
      strcat (network, ".0.0.0");
      ++pw;
      break;
    case 1:
      if (network[strlen (network) - 1] == '.')
	strcat (network, "0.0.0");
      else
	{
	  strcat (network, ".0.0");
	  pw++;
	}
      break;
    case 2:
      if (network[strlen (network) - 1] == '.')
	strcat (network, "0.0");
      else
	{
	  strcat (network, ".0");
	  pw++;
	}
      break;
    case 3:
      if (network[strlen (network) - 1] == '.')
	strcat (network, "0");
      else
	pw++;
      break;
    default:
      return 1;
      break;
    }

  m = strtok (NULL, "/");

  if ((m != NULL) && (strlen (m) != 0))
    {
      sscanf (m, "%s", buf);

      for (i = 0; i < strlen (buf); i++)
	if ((buf[i] < '0' || buf[i] > '9') && buf[i] != '.')
	  return 1;
	else if (buf[i] == '.')
	  pm++;

      strcpy (netmask, buf);
      switch (pm)
	{
	case 0:
	  strcat (netmask, ".0.0.0");
	  break;
	case 1:
	  if (netmask[strlen (netmask) - 1] == '.')
	    strcat (netmask, "0.0.0");
	  else
	    strcat (netmask, ".0.0");
	  break;
	case 2:
	  if (netmask[strlen (netmask) - 1] == '.')
	    strcat (netmask, "0.0");
	  else
	    strcat (netmask, ".0");
	  break;
	case 3:
	  if (netmask[strlen (netmask) - 1] == '.')
	    strcat (netmask, "0");
	  break;
	default:
	  return 1;
	}
    }
  else
    switch (pw)
      {
      case 1:
	strcpy (netmask, "255.0.0.0");
	break;
      case 2:
	strcpy (netmask, "255.255.0.0");
	break;
      case 3:
	strcpy (netmask, "255.255.255.0");
	break;
      case 4:
	strcpy (netmask, "255.255.255.255");
	break;
      default:
	return 1;
      }
  return 0;
}

conffile_t *
load_ypserv_conf (const char *path)
{
  FILE *in;
  char c, *cp;
  char buf1[1025], buf2[1025], buf3[1025];
  long line = 0;
  conffile_t *ptr = NULL, *work = NULL;
  char *filename = alloca (strlen (path) + sizeof ("/ypserv.conf") + 1);

  cp = stpcpy (filename, path);
  strcpy (cp, "/ypserv.conf");
  if ((in = fopen (filename, "r")) == NULL)
    {
      if (debug_flag)
	log_msg ("WARNING: %s not found!", filename);
      return NULL;
    }

  while ((c = fgetc (in)) != (char) EOF)
    {				/*while */
      line++;
      switch (tolower (c))
	{
	case 'F':
	case 'f':
	  {
	    size_t i, j;
	    unsigned long files = 30;

	    if (fgets (buf1, sizeof (buf1) - 1, in) == NULL)
	      {
		log_msg ("Read error in line %d => Ignore line", line);
		break;
	      }

	    i = 0;
	    buf1[sizeof (buf1) - 1] = '\0';
	    while (c != ':' && i <= strlen (buf1))
	      {
		if ((c == ' ') || (c == '\t'))
		  break;
		buf2[i] = c;
		buf2[i + 1] = '\0';
		c = buf1[i];
		++i;
	      }

	    while ((buf1[i - 1] != ':') && (i <= strlen (buf1)))
	      ++i;

	    if ((buf1[i - 1] == ':') && (strcasecmp (buf2, "files") == 0))
	      {
		while (((buf1[i] == ' ') || (buf1[i] == '\t')) &&
		       (i <= strlen (buf1)))
		  ++i;
		j = 0;
		while ((buf1[i] != '\0') && (buf1[i] != '\n'))
		  buf3[j++] = buf1[i++];
		buf3[j] = 0;

		sscanf (buf3, "%lu", &files);
	      }
	    else
	      log_msg ("Parse error in line %d: => Ignore line", line);

	    cached_filehandles = files;

	    if (cached_filehandles > 255)
              cached_filehandles = 255;

	    if (debug_flag)
	      log_msg ("ypserv.conf: files: %lu", files);
	    break;
	  }
	case 'D':
	case 'd':
	  {
	    size_t i, j;

	    if (fgets (buf1, sizeof (buf1) - 1, in) == NULL)
	      {
		log_msg ("Read error in line %d => Ignore line", line);
		break;
	      }

	    i = 0;
	    while (c != ':' && i <= strlen (buf1))
	      {
		if ((c == ' ') || (c == '\t'))
		  break;
		buf2[i] = c;
		buf2[i + 1] = '\0';
		c = buf1[i];
		i++;
	      }

	    while ((buf1[i - 1] != ':') && (i <= strlen (buf1)))
	      i++;

	    if ((buf1[i - 1] == ':') && (strcasecmp (buf2, "dns") == 0))
	      {
		if (!dns_flag)	/* Do not overwrite parameter */
		  {
		    while (((buf1[i] == ' ') || (buf1[i] == '\t')) &&
			   (i <= strlen (buf1)))
		      i++;
		    j = 0;
		    while ((buf1[i] != '\0') && (buf1[i] != '\n'))
		      buf3[j++] = buf1[i++];
		    buf3[j] = 0;

		    sscanf (buf3, "%s", buf2);
		    if (strcasecmp (buf2, "yes") == 0)
		      dns_flag = 1;
		    else if (strcasecmp (buf2, "no") == 0)
		      dns_flag = 0;
		    else
		      log_msg ("Unknown dns option in line %d: => Ignore line",
			      line);
		  }
	      }
	    else
	      log_msg ("Parse error in line %d: => Ignore line", line);

	    if (debug_flag)
	      log_msg ("ypserv.conf: dns: %d", dns_flag);
	    break;
	  }
	case 'S':
	case 's':
	  {			/* sunos_kludge / slp */
	    size_t i;

	    if (fgets (buf1, sizeof (buf1) - 1, in) == NULL)
	      {
		log_msg ("Read error in line %d => Ignore line", line);
		break;
	      }

	    i = 0;
	    while (c != ':' && i <= strlen (buf1))
	      {
		if ((c == ' ') || (c == '\t'))
		  break;
		buf2[i] = c;
		buf2[i + 1] = '\0';
		c = buf1[i];
		i++;
	      }

	    while ((buf1[i - 1] != ':') && (i <= strlen (buf1)))
	      i++;

	    if ((buf1[i - 1] == ':') && (strcasecmp (buf2, "sunos_kludge") == 0))
	      {
		log_msg ("sunos_kludge (line %d) is not longer supported.",
			line);
	      }

	    if ((buf1[i - 1] == ':') && (strcasecmp (buf2, "slp") == 0))
	      {
#if USE_SLP
		size_t j;

		while (((buf1[i] == ' ') || (buf1[i] == '\t')) &&
		       (i <= strlen (buf1)))
		  i++;
		j = 0;
		while ((buf1[i] != '\0') && (buf1[i] != '\n'))
		  buf3[j++] = buf1[i++];
		buf3[j] = 0;

		sscanf (buf3, "%s", buf2);
		if (strcasecmp (buf2, "yes") == 0)
		  slp_flag = 1;
		else if (strcasecmp (buf2, "domain") == 0)
		  slp_flag = 2;
		else if (strcasecmp (buf2, "no") == 0)
		  slp_flag = 0;
		else
		  log_msg ("Unknown slp option in line %d: => Ignore line",
			   line);

		if (debug_flag)
		  log_msg ("ypserv.conf: slp: %d", slp_flag);
#else
		log_msg ("Support for SLP (line %d) is not compiled in.",
			 line);
#endif
	      }
	    else if ((buf1[i - 1] == ':') &&
		     (strcasecmp (buf2, "slp_timeout") == 0))
	      {
#if USE_SLP
		size_t j;

		while (((buf1[i] == ' ') || (buf1[i] == '\t')) &&
		       (i <= strlen (buf1)))
		  i++;
		j = 0;
		while ((buf1[i] != '\0') && (buf1[i] != '\n'))
		  buf3[j++] = buf1[i++];
		buf3[j] = 0;

		sscanf (buf3, "%lu", &slp_timeout);

		if (debug_flag)
		  log_msg ("ypserv.conf: slp_timeout: %lu", slp_timeout);

#else
		log_msg ("Support for SLP (line %d) is not compiled in.",
			 line);
#endif
	      }
	    else
	      log_msg ("Parse error in line %d: => Ignore line", line);

	    break;
	  }
	case 'T':
	case 't':
	  {			/* tryresolve / trusted_master */
	    size_t i, j;

	    if (fgets (buf1, sizeof (buf1) - 1, in) == NULL)
	      {
		log_msg ("Read error in line %d => Ignore line", line);
		break;
	      }

	    i = 0;
	    while (c != ':' && i <= strlen (buf1))
	      {
		if ((c == ' ') || (c == '\t'))
		  break;
		buf2[i] = c;
		buf2[i + 1] = '\0';
		c = buf1[i];
		i++;
	      }

	    while ((buf1[i - 1] != ':') && (i <= strlen (buf1)))
	      i++;

	    if ((buf1[i - 1] == ':') && (strcasecmp (buf2, "tryresolve") == 0))
	      {
		log_msg ("tryresolve (line %d) is not longer supported.",
			 line);
		break;
	      }

	    if ((buf1[i - 1] == ':') && (strcasecmp (buf2, "trusted_master") == 0))
	      {
		while (((buf1[i] == ' ') || (buf1[i] == '\t')) &&
		       (i <= strlen (buf1)))
		  i++;
		j = 0;
		while ((buf1[i] != '\0') && (buf1[i] != '\n'))
		  buf3[j++] = buf1[i++];
		buf3[j] = 0;

		sscanf (buf3, "%s", buf2);
		trusted_master = strdup (buf2);
	      }
	    else
	      log_msg ("Parse error in line %d: => Ignore line", line);

	    if (debug_flag)
	      log_msg ("ypserv.conf: trusted_master: %s", trusted_master);
	    break;
	  }
	case 'X':
	case 'x':
	  {			/* xfr_check_port */
	    size_t i, j;

	    if (fgets (buf1, sizeof (buf1) - 1, in) == NULL)
	      {
		log_msg ("Read error in line %d => Ignore line", line);
		break;
	      }

	    i = 0;
	    while (c != ':' && i <= strlen (buf1))
	      {
		if ((c == ' ') || (c == '\t'))
		  break;
		buf2[i] = c;
		buf2[i + 1] = '\0';
		c = buf1[i];
		i++;
	      }

	    while ((buf1[i - 1] != ':') && (i <= strlen (buf1)))
	      i++;

	    if ((buf1[i - 1] == ':') && (strcasecmp (buf2, "xfr_check_port") == 0))
	      {
		while (((buf1[i] == ' ') || (buf1[i] == '\t')) &&
		       (i <= strlen (buf1)))
		  i++;
		j = 0;
		while ((buf1[i] != '\0') && (buf1[i] != '\n'))
		  buf3[j++] = buf1[i++];
		buf3[j] = 0;

		sscanf (buf3, "%s", buf2);
		if (strcasecmp (buf2, "yes") == 0)
		  xfr_check_port = 1;
		else if (strcasecmp (buf2, "no") == 0)
		  xfr_check_port = 0;
		else
		  log_msg ("Unknown xfr_check_port option in line %d: => Ignore line",
			  line);
	      }
	    else
	      log_msg ("Parse error in line %d: => Ignore line", line);

	    if (debug_flag)
	      log_msg ("ypserv.conf: xfr_check_port: %d", xfr_check_port);
	    break;
	  }
	case '1': case '2': case '3':
	case '4': case '5': case '6':
	case '7': case '8': case '9':
	case '*':
	  {
	    char *n, *d, *m, *s, *p, *f;
	    conffile_t *tmp;

	    buf1[0] = c;
	    if (fgets (&buf1[1], sizeof (buf1) - 2, in) == NULL)
	      {
		log_msg ("Read error in line %d => Ignore line", line);
		break;
	      }

	    n = strtok (buf1, ":");
	    if (n == NULL)
	      {
		log_msg ("Parse error in line %d => Ignore line", line);
		break;
	      }
	    d = strtok (NULL, ":");
	    if (d == NULL)
	      {
		log_msg ("No domain given in line %d => Ignore line", line);
		break;
	      }
	    m = strtok (NULL, ":");
	    if (m == NULL)
	      {
		log_msg ("No map given in line %d => Ignore line", line);
		break;
	      }

	    s = strtok (NULL, ":");
	    if (s == NULL)
	      {
		log_msg ("No security entry in line %d => Ignore line", line);
		break;
	      }
	    p = strtok (NULL, ":");
	    if (p != NULL && strlen (p) != 0)
	      f = strtok (NULL, ":");
	    else
	      f = NULL;

	    if ((tmp = malloc (sizeof (conffile_t))) == NULL)
	      {
		log_msg ("ERROR: could not allocate enough memory! [%s|%d]", __FILE__, __LINE__);
		exit (1);
	      }
	    tmp->next = NULL;

	    if (c == '*')
	      {
#if defined(HAVE_INET_ATON)
		inet_aton ("0.0.0.0", &tmp->network);
		inet_aton ("0.0.0.0", &tmp->netmask);
#else
		tmp->network.s_addr = inet_addr ("0.0.0.0");
		tmp->netmask.s_addr = inet_addr ("0.0.0.0");
#endif
	      }
	    else
	      {
		if (getipnr (n, buf2, buf3) != 0)
		  {
		    log_msg ("Malformed network/netmask entry in line %d", line);
		    free (tmp->map);
		    free (tmp);
		    break;
		  }
#if defined(HAVE_INET_ATON)
		inet_aton (buf2, &tmp->network);
		inet_aton (buf3, &tmp->netmask);
#else
		tmp->network.s_addr = inet_addr (buf2);
		tmp->netmask.s_addr = inet_addr (buf3);
#endif
	      }
	    sscanf (d, "%s", buf2);
	    tmp->domain = strdup (buf2);
	    sscanf (m, "%s", buf2);
	    tmp->map = strdup (buf2);

	    sscanf (s, "%s", buf2);

	    if (strcasecmp (buf2, "none") == 0)
	      tmp->security = SEC_NONE;
	    else if (strcasecmp (buf2, "deny") == 0)
	      tmp->security = SEC_DENY;
	    else if (strcasecmp (buf2, "port") == 0)
	      tmp->security = SEC_PORT;
	    else
	      {
		log_msg ("Unknown security option \"%s\" in line %d => Ignore line",
			buf2, line);
		free (tmp->map);
		free (tmp);
		break;
	      }

	    if (f != NULL)
	      {
		log_msg ("Bogus data \"%s\" in line %d => Ignore line", f,
			 line);
		free (tmp->map);
		free (tmp);
	      }
	    if (debug_flag)
	      {
		log_msg ("ypserv.conf: %s/%s:%s:%s:%d",
			 inet_ntoa (tmp->network), inet_ntoa (tmp->netmask),
			 tmp->domain, tmp->map, tmp->security);
	      }

	    if (work == NULL)
	      {
		work = tmp;
		ptr = work;
	      }
	    else
	      {
		work->next = tmp;
		work = work->next;
	      }
	    break;
	  }
	case ' ':
	case '\t':
	  line--;		/* Ignore Character, no new line */
	  break;
	case '\n':
	  break;		/* Ignore newline */
	case '#':
	  if (fgets (buf1, sizeof (buf1) - 1, in) == NULL)
	    log_msg ("Read error in line %d => Ignore line", line);
	  break;
	default:
	  if (fgets (buf1, sizeof (buf1) - 1, in) == NULL) {};
	  log_msg ("Parse error in line %d: %c%s", line, c, buf1);
	  break;
	}
    }
  fclose (in);

  return ptr;
}

#if 0

int debug_flag = 1;
int dns_flag = 0;

void
main ()
{
  conffile_t *ptr;

  ptr = load_ypserv_conf (".");

  log_msg ("Output:");

  while (ptr != NULL)
    {
      log_msg ("%s/%s:%s:%d:%d",
	       inet_ntoa (ptr->network), inet_ntoa (ptr->netmask), ptr->map,
	       ptr->security, ptr->mangle);
      ptr = ptr->next;
    }

}

#endif
