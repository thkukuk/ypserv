/* Copyright (c) 2003, 2004, 2006 Thorsten Kukuk
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

#if USE_SLP

#include <netdb.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <dirent.h>
#include <sys/stat.h>
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

static
char *create_domain_attr (void)
{
  DIR *dp;
  struct dirent *dep;
  char *str = NULL;

  dp = opendir (YPMAPDIR);
  if (dp == NULL)
    return NULL;

  while ((dep = readdir (dp)) != NULL)
    {
      struct stat st;

      /* ignore files starting with . */
      if (dep->d_name[0] == '.')
	continue;

      /* Ignore all files which are not a directory.  */
      if (stat (dep->d_name, &st) < 0)
	continue; /* Don't add something we cannot stat. */

      if (!S_ISDIR (st.st_mode))
	continue;

      /* We also don't wish to see ypbind data as domain name.  */
      if (strcmp (dep->d_name, "binding") == 0)
	continue;

      if (str == NULL)
	{
#if defined(HAVE_ASPRINTF)
	  if (asprintf (&str, "(domain=%s", dep->d_name) < 0)
	    {
	      log_msg ("Out of memory");
	      return NULL;
	    }
#else
	  str = malloc (9 + strlen (dep->d_name));
	  if (str == NULL)
	    {
	      log_msg ("Out of memory");
	      return NULL;
	    }
	  sprintf (str, "(domain=%s", dep->d_name);
#endif
	}
      else
	{
	  char *cp;

#if defined(HAVE_ASPRINTF)
	  if (asprintf (&cp, "%s,%s", str, dep->d_name) < 0)
	    {
	      log_msg ("Out of memory");
	      return NULL;
	    }
#else
	  cp = malloc (strlen (str) + strlen (dep->d_name) + 2);
	  if (cp == NULL)
	    {
	      log_msg ("Out of memory");
	      return NULL;
	    }
	  sprintf (cp, "%s,%s", str, dep->d_name);
#endif
	  free (str);
	  str = cp;
	}
    }
  closedir (dp);
  if (str)
    {
      char *cp;

#if defined(HAVE_ASPRINTF)
      if (asprintf (&cp, "%s)", str) < 0)
	{
	  log_msg ("Out of memory");
	  return NULL;
	}
#else
      cp = malloc (strlen (str) + 2);
      if (cp == NULL)
	{
	  log_msg ("Out of memory");
	  return NULL;
	}
      sprintf (cp, "%s)", str);
#endif
      free (str);
      return cp;
    }
  return NULL;
}

int
register_slp ()
{
  SLPError err;
  SLPError callbackerr;
  SLPHandle hslp;
  int timeout;
  char *attr = NULL;

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
      if (hp == NULL)
	{
	  log_msg ("Broken setup: cannot resolve %s, please fix",
		   hostname);
	  hname = hostname;
	}
      else
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

#if defined(HAVE_ASPRINTF)
  if (asprintf (&url, "service:ypserv://%s/", hname) < 0)
    {
      log_msg ("Out of memory");
      return -1;
    }
#else
  url = malloc(strlen(hname) + 19);
  if (!url)
    {
      log_msg ("Out of memory");
      return -1;
    }
  sprintf (url, "service:ypserv://%s/", hname) < 0;
#endif

  err = SLPOpen ("en", SLP_FALSE, &hslp);
  if(err != SLP_OK)
    {
      log_msg ("Error opening slp handle %i", err);
      return -1;
    }

  if (slp_flag == 2)
    attr = create_domain_attr ();

  if (attr == NULL) /* can also be NULL if create_domain_attr fails.  */
    attr = strdup ("");

  /* Register a service with SLP */
  err = SLPReg (hslp, url, timeout, 0,
		attr,
		SLP_TRUE,
		ypservSLPRegReport,
		&callbackerr);

  free (attr);

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
      if (signal (SIGALRM, do_refresh) == SIG_ERR)
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
