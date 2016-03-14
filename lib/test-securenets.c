/* Copyright (c) 2014, 2016  Thorsten Kukuk
   Author: Thorsten Kukuk <kukuk@suse.de>

   The YP Server is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License
   version 2 as published by the Free Software Foundation.

   The YP Server is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>. */

#include <rpc/rpc.h>
#include <rpc/rpc_com.h>

#include "access.h"

extern int debug_flag;
extern const char *securenetsfile;

static int
check_entry (int af, char *ip)
{
  struct __rpc_sockinfo si;
  struct netconfig *nconf = NULL;
  struct netbuf *nbuf;
  const char *netid;
  char uaddr[100];

  snprintf (uaddr, 100, "%s.0.0", ip);

  nbuf = __rpc_uaddr2taddr_af (af, uaddr);
  if (nbuf == NULL)
    {
      fprintf (stderr, "uaddr2taddr (\"%s\") failed\n", ip);
      return 1;
    }

  si.si_af = af;
  si.si_proto = IPPROTO_UDP;
  if (!__rpc_sockinfo2netid (&si, &netid))
    {
      fprintf (stderr, "__rpc_sockinfo2netid() failed\n");
      return 1;
    }
  nconf = getnetconfigent (netid);
  if (nconf == NULL)
    {
      fprintf (stderr, "getnetconfigent (%s) failed\n", netid);
      return 1;
    }
  if (securenet_host (nconf, nbuf) != 1)
    return 1;


  return 0;
}

int
main (void)
{
  debug_flag = 1;
  securenetsfile = "securenets.test";

  if (load_securenets () != 0)
    return 1;
  /* dump_securenets (); */

  /* success */
  if (check_entry (AF_INET, "127.0.0.1") != 0)
    return 1;
  /* success */
  if (check_entry (AF_INET6, "::1") != 0)
    return 1;
  /* success */
  if (check_entry (AF_INET6, "fe80::202:b3ff:ad:245") != 0)
    return 1;
  /* fail */
  if (check_entry (AF_INET, "10.10.0.87") != 1)
    return 1;
  /* fail */
  if (check_entry (AF_INET6, "fe80::202:b3fe:ff:ff") != 1)
    return 1;

  return 0;
}
