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
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <slp.h>

#include "reg_slp.h"
#include "log_msg.h"

#include "ypserv_conf.h"

/*  This is the minimum we'll use, irrespective of config setting.
    definately don't set to less than about 30 seconds.  */
#define SLP_MIN_TIMEOUT 120

static void
ypservSLPRegReport (SLPHandle hslp UNUSED, SLPError errcode, void* cookie)
{
  /* return the error code in the cookie */
  *(SLPError*)cookie = errcode;
}

static void
do_refresh (int sig UNUSED)
{
  if (debug_flag)
    log_msg ("Service registration almost expired, refreshing it");
  register_slp ();
}


/* the URL we use to register.  */
static char *url = NULL;

static char hostname[1024];
#if USE_FQDN
static struct hostent *hp = NULL;
#endif
static char *hname;

int
register_slp ()
{
  SLPError err;
  SLPError callbackerr;
  SLPHandle hslp;
  int timeout;

  if (url != NULL)
    {
      free (url);
      url = NULL;
    }
  else
    {
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
    }

  if (slp_timeout == 0)
    timeout = SLP_LIFETIME_MAXIMUM; /* don't expire, ever */
  else if (SLP_MIN_TIMEOUT > slp_timeout)
    timeout = SLP_MIN_TIMEOUT; /* use a reasonable minimum */
  else if (SLP_LIFETIME_MAXIMUM <= slp_timeout)
    timeout = (SLP_LIFETIME_MAXIMUM - 1); /* as long as possible */
  else
    timeout = slp_timeout;

  if (asprintf (&url, "service:ypserv://%s/", hname) < 0)
    {
      log_msg ("Out of memory");
      return -1;
    }

  err = SLPOpen ("en", SLP_FALSE, &hslp);
  if(err != SLP_OK)
    {
      log_msg ("Error opening slp handle %i", err);
      return -1;
    }

  /* Register a service with SLP */
  err = SLPReg (hslp, url, timeout, 0,
		"",
		SLP_TRUE,
		ypservSLPRegReport,
		&callbackerr);

  /* err may contain an error code that occurred as the slp library    */
  /* _prepared_ to make the call.                                     */
  if ((err != SLP_OK) || (callbackerr != SLP_OK))
    {
      log_msg ("Error registering service with slp %i", err);
      return -1;
    }

  /* callbackerr may contain an error code (that was assigned through */
  /* the callback cookie) that occurred as slp packets were sent on    */
  /* the wire */
  if( callbackerr != SLP_OK)
    {
      log_msg ("Error registering service with slp %i",
	       callbackerr);
      return callbackerr;
    }

  /* Now that we're done using slp, close the slp handle */
  SLPClose (hslp);

  /* Set up a timer to refresh the service records */
  if (timeout != SLP_LIFETIME_MAXIMUM)
    {
      struct sigaction act;

      act.sa_handler = do_refresh;
      if (sigaction (SIGALRM, &act, NULL) != 0)
	log_msg ("SLP: error establishing signal handler\n");

      alarm (timeout - 15);
    }

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
      log_msg ("URL not registerd!");
      return -1;
    }

  err = SLPOpen ("en", SLP_FALSE, &hslp);
  if(err != SLP_OK)
    {
      log_msg ("Error opening slp handle %i", err);
      return -1;
    }

  /* Disable possibel alarm call.  */
  alarm (0);

    /* DeRegister a service with SLP */
  err = SLPDereg (hslp, url, ypservSLPRegReport, &callbackerr);

  free (url);
  url = NULL;

  /* err may contain an error code that occurred as the slp library    */
  /* _prepared_ to make the call.                                     */
  if ((err != SLP_OK) || (callbackerr != SLP_OK))
    {
      log_msg ("Error registering service with slp %i", err);
      return -1;
    }

  /* callbackerr may contain an error code (that was assigned through */
  /* the callback cookie) that occurred as slp packets were sent on    */
  /* the wire */
  if( callbackerr != SLP_OK)
    {
      log_msg ("Error registering service with slp %i",
	       callbackerr);
      return callbackerr;
    }

  /* Now that we're done using slp, close the slp handle */
  SLPClose (hslp);

  return 0;
}

#endif
