/* Copyright (c)  2000, 2001, 2002, 2003, 2004 Thorsten Kukuk
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

#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>

#include "ypserv_conf.h"
#include "log_msg.h"
#include "yp_db.h"
#include "yp.h"

#if defined(HAVE_LIBGDBM)
#include <gdbm.h>
#elif defined(HAVE_NDBM)
#include <ndbm.h>
#endif

#if defined(HAVE_LIBGDBM)

/* Open a GDBM database */
static GDBM_FILE
_db_open (const char *domain, const char *map)
{
  GDBM_FILE dbp;
  char buf[MAXPATHLEN + 2];
  int gdbm_cache_value = -1;

  if (strlen (domain) + strlen (map) < MAXPATHLEN)
    {
      sprintf (buf, "%s/%s", domain, map);

      dbp = gdbm_open (buf, 0, GDBM_READER, 0, NULL);

      if (dbp && gdbm_cache_value >= 0)
	gdbm_setopt(dbp, GDBM_CACHESIZE, &gdbm_cache_value, sizeof(int));

      if (debug_flag && dbp == NULL)
	log_msg ("gdbm_open: GDBM Error Code #%d", gdbm_errno);
      else if (debug_flag)
	log_msg ("\t\t->Returning OK!");
    }
  else
    {
      dbp = NULL;
      log_msg ("Path to long: %s/%s", domain, map);
    }

  return dbp;
}

static inline int
_db_close (GDBM_FILE file)
{
  gdbm_close (file);
  return 0;
}

#elif defined(HAVE_NDBM)

/*****************************************************
  The following stuff is for NDBM suport !
******************************************************/

/* Open a NDBM database */
static DB_FILE
_db_open (const char *domain, const char *map)
{
  DB_FILE dbp;
  char buf[MAXPATHLEN + 2];

  if (strlen (domain) + strlen (map) < MAXPATHLEN)
    {
      sprintf (buf, "%s/%s", domain, map);

      dbp = dbm_open (buf, O_RDONLY, 0600);

      if (debug_flag && dbp == NULL)
	log_msg ("dbm_open: NDBM Error Code #%d", errno);
      else if (debug_flag)
	log_msg ("\t\t->Returning OK!");
    }
  else
    {
      dbp = NULL;
      log_msg ("Path to long: %s/%s", domain, map);
    }

  return dbp;
}

static inline int
_db_close (DB_FILE file)
{
  dbm_close (file);
  return 0;
}

int
ypdb_exists (DB_FILE dbp, datum key)
{
  datum tmp = dbm_fetch (dbp, key);

  if (tmp.dptr != NULL)
    return 1;
  else
    return 0;
}

datum
ypdb_nextkey (DB_FILE file, datum key)
{
  datum tkey;

  tkey = dbm_firstkey (file);
  while ((key.dsize != tkey.dsize) ||
	   (strncmp (key.dptr, tkey.dptr, tkey.dsize) != 0))
    {
      tkey = dbm_nextkey (file);
      if (tkey.dptr == NULL)
	return tkey;
    }
  tkey = dbm_nextkey (file);

  return tkey;
}

#else

#error "No database found or selected!"

#endif

typedef struct _fopen
{
  char *domain;
  char *map;
  DB_FILE dbp;
  int flag;
}
Fopen, *FopenP;

#define F_OPEN_FLAG 1
#define F_MUST_CLOSE 2

static int fast_open_init = -1;
static Fopen fast_open_files[255];

int
ypdb_close_all (void)
{
  int i;

  if (debug_flag)
    log_msg ("ypdb_close_all() called");

  if (fast_open_init == -1)
    return 0;

  for (i = 0; i < cached_filehandles; i++)
    {
      if (fast_open_files[i].dbp != NULL)
	{
	  if (fast_open_files[i].flag & F_OPEN_FLAG)
	    {
	      if (debug_flag)
		log_msg ("ypdb_close_all (%s/%s|%d) MARKED_TO_BE_CLOSE",
			 fast_open_files[i].domain,
			 fast_open_files[i].map, i);
	      fast_open_files[i].flag |= F_MUST_CLOSE;
	    }
	  else
	    {
	      if (debug_flag)
		log_msg ("ypdb_close_all (%s/%s|%d)",
			 fast_open_files[i].domain,
			 fast_open_files[i].map, i);
	      free (fast_open_files[i].domain);
	      free (fast_open_files[i].map);
	      _db_close (fast_open_files[i].dbp);
	      fast_open_files[i].dbp = NULL;
	      fast_open_files[i].flag = 0;
	    }
	}
    }

  return 0;
}

int
ypdb_close (DB_FILE file)
{
  if (debug_flag)
    log_msg ("ypdb_close() called");

  if (cached_filehandles > 0)
    {
      if (fast_open_init != -1)
	{
	  int i;

	  for (i = 0; i < cached_filehandles; ++i)
	    {
	      if (fast_open_files[i].dbp == file)
		{
		  if (fast_open_files[i].flag & F_MUST_CLOSE)
		    {
		      if (debug_flag)
			log_msg ("ypdb_MUST_close (%s/%s|%d)",
				 fast_open_files[i].domain,
				 fast_open_files[i].map, i);
		      free (fast_open_files[i].domain);
		      free (fast_open_files[i].map);
		      _db_close (fast_open_files[i].dbp);
		      fast_open_files[i].dbp = NULL;
		      fast_open_files[i].flag = 0;
		    }
		  else
		    {
		      fast_open_files[i].flag &= ~F_OPEN_FLAG;
		    }
		  return 0;
		}
	    }
	}
      log_msg ("ERROR: Could not close file!");
      return 1;
    }
  else
    {
      _db_close (file);
      return 0;
    }
}

DB_FILE
ypdb_open (const char *domain, const char *map)
{
  int i;

  if (debug_flag)
    log_msg ("\typdb_open(\"%s\", \"%s\")", domain, map);

  if (map[0] == '.' || strchr (map, '/'))
    {
      if (debug_flag)
	log_msg ("\t\t->Returning 0");
      return NULL;
    }

  if (cached_filehandles > 0)
    {
      /* First call, initialize the fast_open_init struct */
      if (fast_open_init == -1)
	{
	  fast_open_init = 0;
	  for (i = 0; i < cached_filehandles; i++)
	    {
	      fast_open_files[i].domain =
		fast_open_files[i].map = NULL;
	      fast_open_files[i].dbp = (DB_FILE) NULL;
	      fast_open_files[i].flag = 0;
	    }
	}

      /* Search if we have already open the domain/map file */
      for (i = 0; i < cached_filehandles; i++)
	{
	  if (fast_open_files[i].dbp != NULL)
	    {
	      if ((strcmp (domain, fast_open_files[i].domain) == 0) &&
		  (strcmp (map, fast_open_files[i].map) == 0))
		{
		  /* The file is open and we know the file handle */
		  if (debug_flag)
		    log_msg ("Found: %s/%s (%d)", fast_open_files[i].domain,
			     fast_open_files[i].map, i);

		  if (fast_open_files[i].flag & F_OPEN_FLAG)
		    {
		      /* The file is already in use, don't open it twice.
			 I think this could never happen. */
		      log_msg ("\t%s/%s already open.", domain, map);
		      return NULL;
		    }
		  else
		    {
		      /* Mark the file as open */
		      fast_open_files[i].flag |= F_OPEN_FLAG;
		      return fast_open_files[i].dbp;
		    }
		}
	    }
	}

      /* Search for free entry. If we do not found one, close the LRU */
      for (i = 0; i < cached_filehandles; i++)
	{
#if 0
	  /* Bad Idea. If one of them is NULL, we will get a seg.fault
	     I think it will only work with Linux libc 5.x */
	  log_msg ("Opening: %s/%s (%d) %x",
		   fast_open_files[i].domain,
		   fast_open_files[i].map,
		   i, fast_open_files[i].dbp);
#endif
	  if (fast_open_files[i].dbp == NULL)
	    {
	      /* Good, we have a free entry and don't need to close a map */
	      int j;
	      Fopen tmp;

	      if ((fast_open_files[i].dbp = _db_open (domain, map)) == NULL)
		return NULL;
	      fast_open_files[i].domain = strdup (domain);
	      fast_open_files[i].map = strdup (map);
	      fast_open_files[i].flag |= F_OPEN_FLAG;

	      if (debug_flag)
		log_msg ("Opening: %s/%s (%d) %x", domain, map, i,
			 fast_open_files[i].dbp);

	      /* LRU: put this entry at the first position, move all the other
		 one back */
	      tmp = fast_open_files[i];
	      for (j = i; j >= 1; --j)
		fast_open_files[j] = fast_open_files[j-1];

	      fast_open_files[0] = tmp;
	      return fast_open_files[0].dbp;
	    }
	}

      /* The badest thing, which could happen: no free cache entrys.
	 Search the last entry, which isn't in use. */
      for (i = (cached_filehandles - 1); i > 0; --i)
	if ((fast_open_files[i].flag & F_OPEN_FLAG) != F_OPEN_FLAG)
	  {
	    int j;
	    Fopen tmp;
	    DB_FILE dbp;

	    /* Check, if we can open the file. Else there is no reason
	       to close a cached handle.  */
	    if ((dbp = _db_open (domain, map)) == NULL)
	      return NULL;

	    if (debug_flag)
	      {
		log_msg ("Closing %s/%s (%d)",
			 fast_open_files[i].domain,
			 fast_open_files[i].map, i);
		log_msg ("Opening: %s/%s (%d)", domain, map, i);
	      }
	    free (fast_open_files[i].domain);
	    free (fast_open_files[i].map);
	    _db_close (fast_open_files[i].dbp);

	    fast_open_files[i].domain = strdup (domain);
	    fast_open_files[i].map = strdup (map);
	    fast_open_files[i].flag = F_OPEN_FLAG;
	    fast_open_files[i].dbp = dbp;

	    /* LRU: Move the new entry to the first positon */
	    tmp = fast_open_files[i];
	    for (j = i; j >= 1; --j)
	      fast_open_files[j] = fast_open_files[j-1];

	    fast_open_files[j] = tmp;
	    return fast_open_files[j].dbp;
	  }

      log_msg ("ERROR: Couldn't find a free cache entry!");

      for (i = 0; i < cached_filehandles; i++)
	{
	  log_msg ("Open files: %s/%s (%d) %x (%x)",
		   fast_open_files[i].domain,
		   fast_open_files[i].map,
		   i, fast_open_files[i].dbp,
		   fast_open_files[i].flag);
	}
      return NULL;
    }
  else
    return _db_open (domain, map);
}
