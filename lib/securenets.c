/* Copyright (c) 1996-2014, 2016 Thorsten Kukuk
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
#define SECURENETS YPMAPDIR "/securenets"
#endif

typedef struct securenet
{
  sa_family_t family;
  struct sockaddr_storage network;
  struct sockaddr_storage netmask;
  struct securenet *next;
}
securenet_t;

static securenet_t *securenets = NULL;


void
dump_securenets (void)
{
  struct securenet *sn;
  int i = 0;

  log_msg ("--- securenets start ---");
  sn = securenets;
  while (sn)
    {
      char host[INET6_ADDRSTRLEN];
      char mask[INET6_ADDRSTRLEN];

      i++;

      switch (sn->family)
	{
	case AF_INET:
	  {
	    struct sockaddr_in *network =
	      (struct sockaddr_in *)&(sn->network);
	    struct sockaddr_in *netmask =
	      (struct sockaddr_in *)&(sn->netmask);

	    log_msg ("entry %d: %s %s", i,
		     inet_ntop (AF_INET, &network->sin_addr,
				host, sizeof (host)),
		     inet_ntop (AF_INET, &netmask->sin_addr,
				mask, sizeof (mask)));
	  }
	  break;
	case AF_INET6:
	  {
	    struct sockaddr_in6 *network =
	      (struct sockaddr_in6 *)&(sn->network);
	    struct sockaddr_in6 *netmask =
	      (struct sockaddr_in6 *)&(sn->netmask);

	    log_msg ("entry %d: %s %s", i,
		     inet_ntop (AF_INET6, &network->sin6_addr,
				host, sizeof (host)),
		     inet_ntop (AF_INET6, &netmask->sin6_addr,
				mask, sizeof (mask)));
	  }
	  break;
	default:
	  log_msg ("ERROR: Unknown family: %i", sn->family);
	  break;
	}
      sn = sn->next;
    }
  log_msg ("--- securenets end ---");
}

void
load_securenets (void)
{
  char buf[2 * NI_MAXHOST + 2];
  char col_mask[NI_MAXHOST + 1], col_host[NI_MAXHOST + 1];
  struct addrinfo hints, *res0;
  FILE *in;
  securenet_t *work, *tmp;
  int error, line = 0;


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
      int nr_entries;

      memset (col_mask, 0, sizeof (col_mask));
      memset (col_host, 0, sizeof (col_host));
      memset (buf, 0, sizeof (buf));
      if (fgets (buf, sizeof (buf) -1, in) == NULL)
	continue;
      line++;

      if (buf[0] == '\0' || buf[0] == '#' || buf[0] == '\n')
	continue;

      nr_entries = sscanf (buf, "%s %s", col_mask, col_host);

      if (nr_entries == 2)
	{
	  memset(&hints, 0, sizeof(hints));
	  hints.ai_family = PF_UNSPEC;
	  hints.ai_socktype = SOCK_STREAM;
	  hints.ai_flags = AI_NUMERICHOST;
	  if ((error = getaddrinfo (col_host, NULL, &hints, &res0)))
	    {
	      log_msg ("securenets (%d) badly formated: %s",
		       line, gai_strerror (error));
	      continue;
	    }

	  if ((tmp = malloc (sizeof (securenet_t))) == NULL)
	    {
	      log_msg ("ERROR: could not allocate enough memory! [%s|%d]\n",
		       __FILE__, __LINE__);
	      exit (1);
	    }

	  tmp->next = NULL;
	  memcpy (&tmp->network, res0->ai_addr, res0->ai_addrlen);
	  tmp->family = res0->ai_addr->sa_family;
	  freeaddrinfo(res0);

	  if (strcmp (col_mask, "host") == 0)
	    {
	      if (tmp->family == AF_INET)
		strcpy (col_mask, "255.255.255.255");
	      else if (tmp->family == AF_INET6)
		strcpy (col_mask, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
	      else
		{
		  log_msg ("securenets(%d): unsupported address family: %i", line, tmp->family);
		  free (tmp);
		  continue;
		}
	    }
	  memset (&hints, 0, sizeof(hints));
	  hints.ai_family = PF_UNSPEC;
	  hints.ai_socktype = SOCK_STREAM;
	  hints.ai_flags = AI_NUMERICHOST;
	  if ((error = getaddrinfo (col_mask, NULL, &hints, &res0)))
	    {
	      log_msg ("securenets (%d) badly formated: %s",
		       line, gai_strerror (error));
	      free (tmp);
	      continue;
	    }
	  memcpy (&tmp->netmask, res0->ai_addr, res0->ai_addrlen);
	  freeaddrinfo(res0);
	}
      else if (nr_entries == 1)
	{
	  /* 127.0.0.1/8, 2001:0db8:85a3::8a2e:0370:7334/64 */
	  int netmask_len = 0;
	  char *p;

	  if ((p = strrchr (buf, '/')))
	    {
	      *p = ' ';
	      nr_entries = sscanf(buf, "%s %i", col_host, &netmask_len);
	      if (nr_entries != 2)
		goto malformed;

	      memset (&hints, 0, sizeof(hints));
	      hints.ai_family = PF_UNSPEC;
	      hints.ai_socktype = SOCK_STREAM;
	      hints.ai_flags = AI_NUMERICHOST;
	      if ((error = getaddrinfo (col_host, NULL, &hints, &res0)))
		{
		  log_msg ("securenets (%d) badly formated: %s",
			   line, gai_strerror (error));
		  continue;
		}
	    }
	  else
	    goto malformed;

	  if ((tmp = malloc (sizeof (securenet_t))) == NULL)
	    {
	      log_msg ("ERROR: could not allocate enough memory! [%s|%d]\n",
		       __FILE__, __LINE__);
	      exit (1);
	    }

	  tmp->next = NULL;
	  memcpy (&tmp->network, res0->ai_addr, res0->ai_addrlen);
	  tmp->family = res0->ai_addr->sa_family;
	  switch (tmp->family) /* prefixlen -> netmask */
	    {
	    case AF_INET:
	      {
		struct sockaddr_in sin;

		memcpy (&sin, res0->ai_addr, res0->ai_addrlen);
		sin.sin_addr.s_addr = (0xFFFFFFFFu >> (32 - netmask_len));
		memcpy (&tmp->netmask, &sin, sizeof (struct sockaddr_in));
	      }
	      break;
	    case AF_INET6:
	      {
		struct sockaddr_in6 sin6;
		int i, j;

		memcpy (&sin6, res0->ai_addr, res0->ai_addrlen);
		for (i = netmask_len, j = 0; i > 0; i -= 8, ++j)
		  sin6.sin6_addr.s6_addr[ j ] = i >= 8 ? 0xff
		    : (unsigned long)(( 0xffU << ( 8 - i ) ) & 0xffU );
		memcpy (&tmp->netmask, &sin6, sizeof (struct sockaddr_in6));
	      }
	      break;
	    default:
	      log_msg ("securenets(%d): unsupported address family: %i",
		       line, tmp->family);
	      free (tmp);
	      continue;
	      break;
	    }
	  freeaddrinfo (res0);
 	}
      else
	{
	malformed:
	  log_msg ("securenets(%d): malformed line, ignore it\n", line);
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
    dump_securenets ();
}

int
securenet_host (struct netconfig *nconf, struct netbuf *nbuf)
{
  securenet_t *ptr;
  struct __rpc_sockinfo si;

  if (nconf == NULL || nbuf == NULL || nbuf->len <= 0)
    return 0;

  if (!__rpc_nconf2sockinfo(nconf, &si))
    return 0;

  ptr = securenets;

  if (ptr == NULL) /* this means no securenets file, grant access */
    return 1;
  else
    while (ptr != NULL)
      {
	if (si.si_af == ptr->family)
	  switch (ptr->family)
	    {
	    case AF_INET:
	      {
		struct sockaddr_in *sin1 = nbuf->buf;
		struct sockaddr_in *sin2 = (struct sockaddr_in *)&(ptr->netmask);
		struct sockaddr_in *sin3 = (struct sockaddr_in *)&(ptr->network);

		if ((sin1->sin_addr.s_addr & sin2->sin_addr.s_addr) ==
		    sin3->sin_addr.s_addr)
		  return 1;
	      }
	      break;
	    case AF_INET6:
	      {
		int i;
		struct sockaddr_in6 *sin1 = nbuf->buf;
		struct sockaddr_in6 *sin2 =
		  (struct sockaddr_in6 *)&(ptr->netmask);
		struct sockaddr_in6 *sin3 =
		  (struct sockaddr_in6 *)&(ptr->network);

		for (i = 0; i < 16; i++)
		  if ((sin1->sin6_addr.s6_addr[i] & sin2->sin6_addr.s6_addr[i])
		      != sin3->sin6_addr.s6_addr[i])
		    goto next;
		return 1;
	      }
	      break;
	    default:
	      goto next; /* Something is wrong here, should not happen. */
	    }
      next:
	ptr = ptr->next;
      }
  return 0;
}
