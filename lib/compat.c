
#if defined(HAVE_CONFIG_H)
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif
#include "compat.h"

#ifndef HAVE_STPCPY
char *
stpcpy (char *s1, const char *s2)
{
  /* This is a naive implementation for platforms missing the
     function.  It should be rewritten. */
  strcpy (s1, s2);
  return s1 + strlen (s2);
}
#endif /* not HAVE_STPCPY */

#ifndef HAVE_STRNDUP
char *
strndup (const char *s, int size)
{
  int len = strlen (s) + 1;
  char *retval;

  len = len > size ? size : len;
  retval = malloc (len);
  strcpy (retval, s);
  retval[len - 1] = '\0';

  return retval;
}
#endif /* not HAVE_STRNDUP */

#ifndef HAVE_GETOPT_LONG
int
getopt_long (int argc, char *const *argv, const char *shortopts,
	     const struct option *longopts, int *longind)
{
  return getopt (argc, argv, shortopts);
}
#endif /* not HAVE_GETOPT_LONG */

#if !defined(HAVE_GETDELIM) && !defined(HAVE_GETLINE)
ssize_t
getline (char **lineptr, size_t * n, FILE * stream)
{
  return 0;
}
#endif /*  not HAVE_GETDELIM and not HAVE_GETLINE */
