/* Copyright (c) 1996-2006, 2011, 2014, 2024 Thorsten Kukuk
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

#include <alloca.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <fcntl.h>
#include <ctype.h>
#include <netdb.h>
#include <rpc/rpc.h>
#include <rpcsvc/yp_prot.h>

#if defined (__NetBSD__) || (defined(__GLIBC__) && (__GLIBC__ == 2 && __GLIBC_MINOR__ == 0))
/* <rpc/rpc.h> is missing the prototype */
int callrpc (char *host, u_long prognum, u_long versnum, u_long procnum,
             xdrproc_t inproc, char *in, xdrproc_t outproc, char *out);
#endif
#include <sys/param.h>
#include <sys/time.h>
#include <sys/stat.h>

#if defined(HAVE_COMPAT_LIBGDBM)

#if defined(HAVE_LIBGDBM)
#include <gdbm.h>
#elif defined(HAVE_LIBQDBM)
#include <hovel.h>
#endif

#define ypdb_store gdbm_store
#define YPDB_REPLACE GDBM_REPLACE
#define ypdb_close gdbm_close
static GDBM_FILE dbm;

#elif defined (HAVE_NDBM)

#include <ndbm.h>

#define ypdb_store dbm_store
#define YPDB_REPLACE DBM_REPLACE
#define ypdb_close dbm_close
static DBM *dbm;

#elif defined (HAVE_LIBTC)

#include <tcbdb.h>

#define YPDB_REPLACE 1

static TCBDB *dbm;

static inline int
ypdb_store(TCBDB *dbm, datum key, datum data, int mode)
{
  if (mode != YPDB_REPLACE)
    return 1;

  return !tcbdbput(dbm, key.dptr, key.dsize, data.dptr, data.dsize);
}

static inline void
ypdb_close (TCBDB *dbm)
{
  tcbdbclose (dbm);
  tcbdbdel (dbm);
}

#else

#error "No database found or selected!"

#endif

static int lower = 0;

static inline void
write_data (datum key, datum data)
{
  if (ypdb_store (dbm, key, data, YPDB_REPLACE) != 0)
    {
      perror ("makedbm: dbm_store");
      ypdb_close (dbm);
      exit (1);
    }
}

#ifdef HAVE_NDBM
static char *
strapp (const char *str1, const char *str2)
{
  char *buffer = alloca(strlen (str1) + strlen (str2) + 1);

  strcpy (buffer, str1);
  strcat (buffer, str2);

  return strdup (buffer);
}
#endif

static void
create_file (char *fileName, char *dbmName, char *masterName,
	     char *domainName, char *inputName,
	     char *outputName, int aliases, int shortlines,
	     int b_flag, int s_flag, int remove_comments,
	     int check_limit)
{
  datum kdat, vdat;
  char *key = NULL;
  size_t keylen = 0;
  char *filename = NULL;
  FILE *input;
  char orderNum[12];
  struct timeval tv;
  struct timezone tz;

  input = strcmp (fileName, "-") ? fopen (fileName, "r") : stdin;
  if (input == NULL)
    {
      fprintf (stderr, "makedbm: Cannot open %s\n", fileName);
      exit (1);
    }

  filename = calloc (1, strlen (dbmName) + 3);
  sprintf (filename, "%s~", dbmName);
#if defined(HAVE_COMPAT_LIBGDBM)
  dbm = gdbm_open (filename, 0, GDBM_NEWDB | GDBM_FAST, 0600, NULL);
#elif defined(HAVE_NDBM)
  dbm = dbm_open (filename, O_CREAT | O_RDWR, 0600);
#elif defined(HAVE_LIBTC)
  dbm = tcbdbnew();
  if (!tcbdbopen(dbm, filename, BDBOWRITER | BDBOCREAT))
  {
    tcbdbdel(dbm);
    dbm = NULL;
  }
#endif
  if (dbm == NULL)
    {
      fprintf (stderr, "makedbm: Cannot open %s\n", filename);
      exit (1);
    }

  if (masterName && *masterName)
    {
      kdat.dptr = "YP_MASTER_NAME";
      kdat.dsize = strlen (kdat.dptr);
      vdat.dptr = masterName;
      vdat.dsize = strlen (vdat.dptr);
      write_data (kdat, vdat);
    }

  if (domainName && *domainName)
    {
      kdat.dptr = "YP_DOMAIN_NAME";
      kdat.dsize = strlen (kdat.dptr);
      vdat.dptr = domainName;
      vdat.dsize = strlen (vdat.dptr);
      write_data (kdat, vdat);
    }

  if (inputName && *inputName)
    {
      kdat.dptr = "YP_INPUT_NAME";
      kdat.dsize = strlen (kdat.dptr);
      vdat.dptr = inputName;
      vdat.dsize = strlen (vdat.dptr);
      write_data (kdat, vdat);
    }

  if (outputName && *outputName)
    {
      kdat.dptr = "YP_OUTPUT_NAME";
      kdat.dsize = strlen (kdat.dptr);
      vdat.dptr = outputName;
      vdat.dsize = strlen (vdat.dptr);
      write_data (kdat, vdat);
    }

  if (b_flag)
    {
      kdat.dptr = "YP_INTERDOMAIN";
      kdat.dsize = strlen (kdat.dptr);
      vdat.dptr = "";
      vdat.dsize = strlen (vdat.dptr);
      write_data (kdat, vdat);
    }

  if (s_flag)
    {
      kdat.dptr = "YP_SECURE";
      kdat.dsize = strlen (kdat.dptr);
      vdat.dptr = "";
      vdat.dsize = strlen (vdat.dptr);
      write_data (kdat, vdat);
    }

  if (aliases)
    {
      kdat.dptr = "@";
      kdat.dsize = strlen (kdat.dptr);
      vdat.dptr = "@";
      vdat.dsize = strlen (vdat.dptr);
      write_data (kdat, vdat);
    }

  gettimeofday (&tv, &tz);
  sprintf (orderNum, "%ld", (long) tv.tv_sec);
  kdat.dptr = "YP_LAST_MODIFIED";
  kdat.dsize = strlen (kdat.dptr);
  vdat.dptr = orderNum;
  vdat.dsize = strlen (vdat.dptr);
  write_data (kdat, vdat);

  while (!feof (input))
    {
      char *cptr;

      ssize_t n = getline (&key, &keylen, input);
      if (n < 1)
	break;
      if (key[n - 1] == '\n' || key[n - 1] == '\r')
	key[n - 1] = '\0';
      if (n > 1 && (key[n - 2] == '\n' || key[n - 2] == '\r'))
	key[n - 2] = '\0';

      if (remove_comments)
	if ((cptr = strchr (key, '#')) != NULL)
	  {
	    *cptr = '\0';
	    --cptr;
	    while (*cptr == ' ' || *cptr == '\t')
	      {
		*cptr = '\0';
		--cptr;
	      }
	  }

      if (strlen (key) == 0)
	continue;

      if (aliases)
	{
	  int len;

	  len = strlen (key);
	  while (key[len - 1] == ' ' || key[len - 1] == '\t')
	    {
	      key[len - 1] = '\0';
	      --len;
	    }

	  while (key[len - 1] == ',')
	    {
	      char *nkey = NULL;
	      size_t nkeylen = 0;
	      if (getline (&nkey, &nkeylen, input) == -1)
		break;

	      cptr = nkey;
	      while ((*cptr == ' ') || (*cptr == '\t'))
		++cptr;
	      if (strlen (key) + strlen (cptr) < keylen)
		strcat (key, cptr);
	      else
		{
		  keylen += nkeylen;
		  key = realloc (key, keylen);
		  if (key == NULL)
		    abort ();
		  strcat (key, cptr);
		}

	      free (nkey);

	      if ((cptr = strchr (key, '\n')) != NULL)
		*cptr = '\0';
	      len = strlen (key);
	      while (key[len - 1] == ' ' || key[len - 1] == '\t')
		{
		  key[len - 1] = '\0';
		  len--;
		}
	    }
	  if ((cptr = strchr (key, ':')) != NULL)
	    *cptr = ' ';
	}
      else
	while (key[strlen (key) - 1] == '\\')
	  {
	    char *nkey;
	    size_t nkeylen = 0;
	    ssize_t n = getline (&nkey, &nkeylen, input);

	    if (n < 1)
	      break;
	    if (nkey[n - 1] == '\n' || nkey[n - 1] == '\r')
	      nkey[n - 1] = '\0';
	    if (n > 1 && (nkey[n - 2] == '\n' || nkey[n - 2] == '\r'))
	      nkey[n - 2] = '\0';

	    key[strlen (key) - 1] = '\0';

	    if (shortlines)
	      {
		int len;

		len = strlen (key);
		key[len - 1] = '\0';
		len--;
		if ((key[len - 1] != ' ') && (key[len - 1] != '\t'))
		  strcat (key, " ");
		cptr = nkey;
		while ((*cptr == ' ') || (*cptr == '\t'))
		  ++cptr;
		if (len + 1 + strlen (cptr) < keylen)
		  strcat (key, cptr);
		else
		  {
		    keylen += nkeylen;
		    key = realloc (key, keylen);
		    if (key == NULL)
		      abort ();
		    strcat (key, nkey);
		  }
	      }
	    else
	      {
		keylen += nkeylen;
		key = realloc (key, keylen);
		if (key == NULL)
		  abort ();
		strcat (key, nkey);
	      }
	    free (nkey);

	    if ((cptr = strchr (key, '\n')) != NULL)
	      *cptr = '\0';
	  }

      cptr = key;

      /* Hack for spaces in passwd, group and hosts keys. If we
	 find a <TAB> in the string, Makefile generates it to
	 seperate the key. This should be the standard, but is not
	 done for all maps (like bootparamd).  */
      if (strchr (cptr, '\t') == NULL)
	{
	  while (*cptr && *cptr != '\t' && *cptr != ' ')
	    ++cptr;
	}
      else
	{
	  while (*cptr && *cptr != '\t')
	    ++cptr;
	  /* But a key should not end with a space.  */
	  while (cptr[-1] == ' ')
	    --cptr;
	}

      *cptr++ = '\0';

      while (*cptr == '\t' || *cptr == ' ')
	++cptr;

      if (strlen (key) == 0)
	{
	  if (strlen (cptr) != 0)
	    fprintf (stderr,
		     "makedbm: warning: malformed input data (ignored)\n");
	}
      else
	{
	  int i;

	  if (check_limit && strlen (key) > YPMAXRECORD)
	    {
	      fprintf (stderr, "makedbm: warning: key too long: %s\n", key);
	      continue;
	    }
	  kdat.dsize = strlen (key);
	  kdat.dptr = key;

	  if (check_limit && strlen (cptr) > YPMAXRECORD)
	    {
	      fprintf (stderr, "makedbm: warning: data too long: %s\n", cptr);
	      continue;
	    }
	  vdat.dsize = strlen (cptr);
	  vdat.dptr = cptr;

	  if (lower)
	    for (i = 0; i < kdat.dsize; i++)
	      kdat.dptr[i] = tolower (kdat.dptr[i]);

	  write_data (kdat, vdat);
	}
    }

  ypdb_close (dbm);
#if defined(HAVE_NDBM)
#if defined(__GLIBC__) && __GLIBC__ >= 2
  {
    char *dbm_db = strapp (dbmName, ".db");
    char *filedb = strapp (filename, ".db");

    unlink (dbm_db);
    rename (filedb, dbm_db);
  }
#else
  {
    char *dbm_pag = strapp (dbmName, ".pag");
    char *dbm_dir = strapp (dbmName, ".dir");
    char *filepag = strapp (filename, ".pag");
    char *filedir = strapp (filename, ".dir");

    unlink (dbm_pag);
    unlink (dbm_dir);
    rename (filepag, dbm_pag);
    rename (filedir, dbm_dir);
  }
#endif
#else
  unlink (dbmName);
#if defined(HAVE_LIBTC)
	  chmod(filename, S_IRUSR|S_IWUSR);
#endif
  rename (filename, dbmName);
#endif
  free (filename);

  if (strcmp (fileName, "-") != 0)
    fclose (input);
}

static void
dump_file (char *dbmName)
{
  datum key, data;
#if defined(HAVE_COMPAT_LIBGDBM)
  dbm = gdbm_open (dbmName, 0, GDBM_READER, 0600, NULL);
#elif defined(HAVE_NDBM)
  dbm = dbm_open (dbmName, O_RDONLY, 0600);
#elif defined(HAVE_LIBTC)
  dbm = tcbdbnew();
  if (!tcbdbopen (dbm, dbmName, BDBOREADER | BDBONOLCK))
  {
    tcbdbdel(dbm);
    dbm = NULL;
  }
#endif
  if (dbm == NULL)
    {
      fprintf (stderr, "makedbm: Cannot open %s\n", dbmName);
      fprintf (stderr, "makedbm: Consider rebuilding maps using ypinit\n");
      exit (1);
    }
#if defined(HAVE_COMPAT_LIBGDBM)
  for (key = gdbm_firstkey (dbm); key.dptr; key = gdbm_nextkey (dbm, key))
    {
      data = gdbm_fetch (dbm, key);
      if (!data.dptr)
	{
	  fprintf (stderr, "Error:\n");
	  perror (dbmName);
	  exit (1);
	}
      printf ("%.*s\t%.*s\n",
	      key.dsize, key.dptr,
	      data.dsize, data.dptr);
      free (data.dptr);
    }
#elif defined(HAVE_NDBM)
  key = dbm_firstkey (dbm);
  while (key.dptr)
    {
      data = dbm_fetch (dbm, key);
      if (!data.dptr)
	{
	  fprintf (stderr, "Error:\n");
	  perror (dbmName);
	  exit (1);
	}
      printf ("%.*s\t%.*s\n",
	      key.dsize, key.dptr,
	      data.dsize, data.dptr);
      key = dbm_nextkey (dbm);
    }
#elif defined(HAVE_LIBTC)
  {
    BDBCUR *cur;
    cur = tcbdbcurnew (dbm);
    if (tcbdbcurfirst (cur))
      {
        while ((key.dptr = tcbdbcurkey (cur, &key.dsize)) != NULL)
          {
            data.dptr = tcbdbcurval (cur, &data.dsize);
            if (!data.dptr)
	      {
	        fprintf (stderr, "Error:\n");
	        perror (dbmName);
	        exit (1);
              }

            printf ("%.*s\t%.*s\n",
                  key.dsize, key.dptr,
                  data.dsize, data.dptr);

            if (!tcbdbcurnext (cur))
              break;
          }
      }
    tcbdbcurdel (cur);
  }
#endif
  ypdb_close (dbm);
}

static void
send_clear (void)
{
  char in = 0;
  char *out = NULL;
  int stat;
  if ((stat = callrpc ("localhost", YPPROG, YPVERS, YPPROC_CLEAR,
		       (xdrproc_t) xdr_void, &in,
		       (xdrproc_t) xdr_void, out)) != RPC_SUCCESS)
    {
      fprintf (stderr, "failed to send 'clear' to local ypserv: %s",
	       clnt_sperrno ((enum clnt_stat) stat));
    }
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
    {
      if (res0->ai_canonname == NULL)
	{
	  fprintf (stderr, "makedbm: '%s' is not resolvable\n",
		   hostname);
	  exit (1);
	}
      host = strdup (res0->ai_canonname);
    }

  freeaddrinfo (res0);

  return host;
#else
  return strdup (hostname);
#endif
}


static void
Usage (int exit_code)
{
  fprintf (stderr, "usage: makedbm -u dbname\n");
  fprintf (stderr, "       makedbm [-a|-r] [-b] [-c] [-s] [-l] [-i YP_INPUT_NAME]\n");
  fprintf (stderr, "               [-o YP_OUTPUT_NAME] [-m YP_MASTER_NAME] inputfile dbname\n");
  fprintf (stderr, "       makedbm -c\n");
  fprintf (stderr, "       makedbm --version\n");
  exit (exit_code);
}

int
main (int argc, char *argv[])
{
  char *domainName = NULL;
  char *inputName = NULL;
  char *outputName = NULL;
  char masterName[MAXHOSTNAMELEN + 1] = "";
  int dump = 0;
  int aliases = 0;
  int shortline = 0;
  int clear = 0;
  int b_flag = 0;
  int s_flag = 0;
  int remove_comments = 0;
  int check_limit = 1;

  while (1)
    {
      int c;
      int option_index = 0;
      static struct option long_options[] =
      {
	{"version", no_argument, NULL, '\255'},
	{"dump", no_argument, NULL, 'u'},
	{"help", no_argument, NULL, 'h'},
	{"usage", no_argument, NULL, 'h'},
	{"secure", no_argument, NULL, 's'},
	{"aliases", no_argument, NULL, 'a'},
	{"send_clear", no_argument, NULL, 'c'},
	{"remove-spaces", no_argument, NULL, '\254'},
	{"remove-comments", no_argument, NULL, 'r'},
	{"no-limit-check", no_argument, NULL, '\253'},
	{NULL, 0, NULL, '\0'}
      };

      c = getopt_long (argc, argv, "abcd:hi:lm:o:rsu", long_options, &option_index);
      if (c == EOF)
	break;
      switch (c)
	{
	case 'a':
	  aliases++;
	  shortline++;
	  break;
	case 'b':
	  b_flag++;
	  break;
	case 'c':
	  clear++;
	  break;
	case 'l':
	  lower++;
	  break;
	case 'u':
	  dump++;
	  break;
	case '\254':
	  shortline++;
	  break;
	case 'r':
	  remove_comments++;
	  break;
	case 's':
	  s_flag++;
	  break;
	case 'd':
	  domainName = optarg;
	  break;
	case 'i':
	  inputName = optarg;
	  break;
	case 'o':
	  outputName = optarg;
	  break;
	case 'm':
	  if (strlen (optarg) <= MAXHOSTNAMELEN)
	    strcpy (masterName, optarg);
	  else
	    fprintf (stderr, "hostname to long: %s\n", optarg);
	  break;
	case '\253':
	  check_limit = 0;
	  break;
	case '\255':
	  fprintf  (stdout, "makedbm (%s) %s", PACKAGE, VERSION);
	  return 0;
	case 'h':
	  Usage (0);
	  break;
	case '?':
	  Usage (1);
	  break;
	}
    }

  argc -= optind;
  argv += optind;

  if (dump)
    {
      if (argc < 1)
	Usage (1);
      else
	dump_file (argv[0]);
    }
  else
    {
      if (clear && argc == 0)
	{
	  send_clear ();
	  return 0;
	}

      if (argc < 2)
	Usage (1);
      else
	{
	  if (strlen (masterName) == 0)
	    {
	      char *cp;

	      if (gethostname (masterName, sizeof (masterName)) < 0)
		perror ("gethostname");

	      cp = get_canonical_hostname (masterName);
	      strncpy (masterName, cp, sizeof (masterName) -1);
	    }

	  create_file (argv[0], argv[1], masterName, domainName,
		       inputName, outputName, aliases, shortline,
		       b_flag, s_flag, remove_comments, check_limit);

	  if (clear)
	    send_clear ();
	}
    }

  return 0;
}
