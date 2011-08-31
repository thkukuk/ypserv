/* Copyright (c) 1996, 1997, 1998, 1999, 2000, 2003, 2005, 2006 Thorsten Kukuk
   Author: Thorsten Kukuk <kukuk@suse.de>

   The YP Server is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

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

#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "access.h"
#include "log_msg.h"

#ifndef SECURENETS
#define SECURENETS "securenets"
#endif

typedef struct securenet
{
  struct in_addr netmask;
  struct in_addr network;
  struct securenet *next;
}
securenet_t;

static securenet_t *securenets = NULL;

void
load_securenets (void)
{
  char buf1[128], buf2[128], buf3[128];
  FILE *in;
  securenet_t *work, *tmp;
  int line = 0;

  /* If securenets isn't NULL, we should reload the securents file. */
  if (securenets != NULL)
    {
      log_msg ("Reloading securenets file\n");
      while (securenets != NULL)
	{
	  work = securenets;
	  securenets = securenets->next;
	  free (work);
	}
    }
  securenets = NULL;
  work = NULL;
  tmp = NULL;

  if ((in = fopen (SECURENETS, "r")) == NULL)
    {
      log_msg ("WARNING: no %s file found!\n", SECURENETS);
      return;
    }

  while (!feof (in))
    {
      int host = 0;

      memset (buf1, 0, sizeof (buf1));
      memset (buf2, 0, sizeof (buf2));
      memset (buf3, 0, sizeof (buf3));
      if (fgets (buf3, 128, in) == NULL)
	continue;
      line++;

      if (buf3[0] == '\0' || buf3[0] == '#' || buf3[0] == '\n')
	continue;

      if (sscanf (buf3, "%s %s", buf1, buf2) != 2)
	{
	  log_msg ("securenets(%d): malformed line, ignore it\n", line);
	  continue;
	}

      if ((tmp = malloc (sizeof (securenet_t))) == NULL)
	{
	  log_msg ("ERROR: could not allocate enough memory! [%s|%d]\n",
		   __FILE__, __LINE__);
	  exit (1);
	}

      tmp->next = NULL;

      if (strcmp (buf1, "host") == 0)
	{
	  strcpy (buf1, "255.255.255.255");
	  host = 1;
	}
      else if (strcmp (buf1, "255.255.255.255") == 0)
	host = 1;

#if defined(HAVE_INET_ATON)
      if (!inet_aton (buf1, &tmp->netmask) && !host)
#else
      if ((tmp->netmask.s_addr = inet_addr (buf1)) == (-1) && !host)
#endif
	{
	  log_msg ("securenets(%d): %s is not a correct netmask!\n", line,
		   buf1);
	  free (tmp);
	  continue;
	}

#if defined(HAVE_INET_ATON)
      if (!inet_aton (buf2, &tmp->network))
#else
      if ((tmp->network.s_addr = inet_addr (buf2)) == (-1))
#endif
	{
	  log_msg ("securenets(%d): %s is not a correct network address!\n",
		   line, buf2);
	  free (tmp);
	  continue;
	}

      if (work == NULL)
	{
	  work = tmp;
	  securenets = work;
	}
      else
	{
	  work->next = tmp;
	  work = work->next;
	}
    }
  fclose (in);

  if (debug_flag)
    {
      tmp = securenets;
      while (tmp)
	{
	  char *p1 = strdup (inet_ntoa (tmp->netmask));
	  char *p2 = strdup (inet_ntoa (tmp->network));

	  if (p1 != NULL && p2 != NULL)
	    {
	      log_msg ("Find securenet: %s %s", p1, p2);
	      free (p1);
	      free (p2);
	    }

	  tmp = tmp->next;
	}
    }
}

int
securenet_host (const struct in_addr sin_addr)
{
  securenet_t *ptr;

  ptr = securenets;

  if (ptr == NULL)
    return 1;
  else
    while (ptr != NULL)
      {
	if ((ptr->netmask.s_addr & sin_addr.s_addr) == ptr->network.s_addr)
	  return 1;
	ptr = ptr->next;
      }
  return 0;
}
