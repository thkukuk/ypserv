/* Copyright (c) 2003, 2004 Thorsten Kukuk
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

#define _GNU_SOURCE

#if defined(HAVE_CONFIG_H)
#include "config.h"
#endif

#if USE_SLP

#include <netdb.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <slp.h>

#include "reg_slp.h"
#include "log_msg.h"

static void
ypservSLPRegReport (SLPHandle hslp UNUSED, SLPError errcode, void* cookie)
{
  /* return the error code in the cookie */
  *(SLPError*)cookie = errcode;
}

/* the URL we use to register.  */

static char *url = NULL;

int
register_slp ()
{
  SLPError err;
  SLPError callbackerr;
  SLPHandle hslp;
  char hostname[1024];
  char *hname;
#if USE_FQDN
  struct hostent *hp = NULL;
#endif

  if (url != NULL)
    {
      log_msg ("URL already registerd!\n");
      return -1;
    }

  gethostname (hostname, sizeof (hostname));
#if !USE_FQDN
  hname = hostname;
#else
  if (isdigit (hostname[0]))
    {
      char addr[INADDRSZ];
      if (inet_pton (AF_INET, hostname, &addr))
        hp = gethostbyaddr (addr, sizeof (addr), AF_INET);
    }
  else
    hp = gethostbyname (hostname);
  hname = hp->h_name;
#endif

  if (asprintf (&url, "service:ypserv://%s/", hname) < 0)
    {
      log_msg ("Out of memory\n");
      return -1;
    }

  err = SLPOpen ("en", SLP_FALSE, &hslp);
  if(err != SLP_OK)
    {
      log_msg ("Error opening slp handle %i\n", err);
      return -1;
    }

    /* Register a service with SLP */
  err = SLPReg (hslp, url, SLP_LIFETIME_MAXIMUM, 0,
		"",
		SLP_TRUE,
		ypservSLPRegReport,
		&callbackerr);

  /* err may contain an error code that occurred as the slp library    */
  /* _prepared_ to make the call.                                     */
  if ((err != SLP_OK) || (callbackerr != SLP_OK))
    {
      log_msg ("Error registering service with slp %i\n", err);
      return -1;
    }

  /* callbackerr may contain an error code (that was assigned through */
  /* the callback cookie) that occurred as slp packets were sent on    */
  /* the wire */
  if( callbackerr != SLP_OK)
    {
      log_msg ("Error registering service with slp %i\n",
	       callbackerr);
      return callbackerr;
    }

  /* Now that we're done using slp, close the slp handle */
  SLPClose (hslp);

  return 0;
}

int
deregister_slp ()
{
  SLPError err;
  SLPError callbackerr;
  SLPHandle hslp;

  if (url == NULL)
    {
      log_msg ("URL not registerd!\n");
      return -1;
    }

  err = SLPOpen ("en", SLP_FALSE, &hslp);
  if(err != SLP_OK)
    {
      log_msg ("Error opening slp handle %i\n", err);
      return -1;
    }

    /* DeRegister a service with SLP */
  err = SLPDereg (hslp, url, ypservSLPRegReport, &callbackerr);

  free (url);
  url = NULL;

  /* err may contain an error code that occurred as the slp library    */
  /* _prepared_ to make the call.                                     */
  if ((err != SLP_OK) || (callbackerr != SLP_OK))
    {
      log_msg ("Error registering service with slp %i\n", err);
      return -1;
    }

  /* callbackerr may contain an error code (that was assigned through */
  /* the callback cookie) that occurred as slp packets were sent on    */
  /* the wire */
  if( callbackerr != SLP_OK)
    {
      log_msg ("Error registering service with slp %i\n",
	       callbackerr);
      return callbackerr;
    }

  /* Now that we're done using slp, close the slp handle */
  SLPClose (hslp);

  return 0;
}

#endif
