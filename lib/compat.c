
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
/* copied from cvs 1.11.5 source */
/* getline.c -- Replacement for GNU C library function getline

Copyright (C) 1993 Free Software Foundation, Inc.

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License as
published by the Free Software Foundation; either version 2 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.  */

/* Written by Jan Brittenson, bson@gnu.ai.mit.edu.  */

#include <sys/types.h>
#include <stdio.h>
#include <assert.h>
#include <errno.h>

#define GETLINE_NO_LIMIT -1

#if STDC_HEADERS
#include <stdlib.h>
#else
char *malloc (), *realloc ();
#endif

/* Always add at least this many bytes when extending the buffer.  */
#define MIN_CHUNK 64

/* Read up to (and including) a TERMINATOR from STREAM into *LINEPTR
   + OFFSET (and null-terminate it).  If LIMIT is non-negative, then
   read no more than LIMIT chars.

   *LINEPTR is a pointer returned from malloc (or NULL), pointing to
   *N characters of space.  It is realloc'd as necessary.

   Return the number of characters read (not including the null
   terminator), or -1 on error or EOF.  On a -1 return, the caller
   should check feof(), if not then errno has been set to indicate the
   error.  */

int
getstr (char **lineptr, size_t *n, FILE *stream, int terminator,
	int offset, int limit)
{
  int nchars_avail;		/* Allocated but unused chars in *LINEPTR.  */
  char *read_pos;		/* Where we're reading into *LINEPTR. */
  int ret;

  if (!lineptr || !n || !stream)
    {
      errno = EINVAL;
      return -1;
    }

  if (!*lineptr)
    {
      *n = MIN_CHUNK;
      *lineptr = malloc (*n);
      if (!*lineptr)
	{
	  errno = ENOMEM;
	  return -1;
	}
      *lineptr[0] = '\0';
    }

  nchars_avail = *n - offset;
  read_pos = *lineptr + offset;

  for (;;)
    {
      int save_errno;
      register int c;

      if (limit == 0)
          break;
      else
      {
          c = getc (stream);

          /* If limit is negative, then we shouldn't pay attention to
             it, so decrement only if positive. */
          if (limit > 0)
              limit--;
      }

      save_errno = errno;

      /* We always want at least one char left in the buffer, since we
	 always (unless we get an error while reading the first char)
	 NUL-terminate the line buffer.  */

      assert((*lineptr + *n) == (read_pos + nchars_avail));
      if (nchars_avail < 2)
	{
	  if (*n > MIN_CHUNK)
	    *n *= 2;
	  else
	    *n += MIN_CHUNK;

	  nchars_avail = *n + *lineptr - read_pos;
	  *lineptr = realloc (*lineptr, *n);
	  if (!*lineptr)
	    {
	      errno = ENOMEM;
	      return -1;
	    }
	  read_pos = *n - nchars_avail + *lineptr;
	  assert((*lineptr + *n) == (read_pos + nchars_avail));
	}

      if (ferror (stream))
	{
	  /* Might like to return partial line, but there is no
	     place for us to store errno.  And we don't want to just
	     lose errno.  */
	  errno = save_errno;
	  return -1;
	}

      if (c == EOF)
	{
	  /* Return partial line, if any.  */
	  if (read_pos == *lineptr)
	    return -1;
	  else
	    break;
	}

      *read_pos++ = c;
      nchars_avail--;

      if (c == terminator)
	/* Return the line.  */
	break;
    }

  /* Done - NUL terminate and return the number of chars read.  */
  *read_pos = '\0';

  ret = read_pos - (*lineptr + offset);
  return ret;
}

ssize_t
getline (char **lineptr, size_t * n, FILE * stream)
{
  return getstr (lineptr, n, stream, '\n', 0, GETLINE_NO_LIMIT);
}

int
getline_safe (char **lineptr, size_t *n, FILE *stream, int limit)
{
  return getstr (lineptr, n, stream, '\n', 0, limit);
}

#endif /* not HAVE_GETDELIM and not HAVE_GETLINE */

#if !defined(HAVE_SVC_GETCALLER) && !defined(svc_getcaller)
const struct sockaddr_in *
svc_getcaller(const SVCXPRT *xprt)
{
#  ifdef HAVE_SVC_GETRPCCALLER
  const struct netbuf *addr;
  addr = svc_getrpccaller(xprt);
  log_msg ("warning: Bogus svc_getcaller() called");
  /* XXX find out how the result from svc_getrpccaller relates to
     svc_getcaller */
  assert(sizeof(struct sockaddr_in) == addr->len);
  return (const struct sockaddr_in *)addr->buf;
#  else /* not HAVE_SVC_GETRPCCALLER */
#    error "Missing both svc_getcaller() and svc_getrpccaller()"
#  endif /* not HAVE_SVC_GETRPCCALLER */
}
#endif /* not HAVE_SVC_GETCALLER */


#ifndef HAVE__RPC_DTABLESIZE
#  if HAVE_GETDTABLESIZE
int _rpc_dtablesize()
{
        static int size;

        if (size == 0) {
                size = getdtablesize();
        }
        return (size);
}
#  else
#  include <sys/resource.h>
int _rpc_dtablesize()
{
    static int size = 0;
    struct rlimit rlb;

    if (size == 0)
    {
        if (getrlimit(RLIMIT_NOFILE, &rlb) >= 0)
            size = rlb.rlim_cur;
    }

    return size;
}
#  endif /* not HAVE_GETDTABLESIZE */
#endif /* not HAVE__RPC_DTABLESIZE */

#ifndef HAVE_INET_ATON
/* Source: http://mail.gnu.org/archive/html/autoconf/2002-08/msg00036.html */
/*  $Id: compat.c,v 1.1.2.5 2005/05/19 12:12:06 kukuk Exp $
**
**  Replacement for a missing inet_aton.
**
**  Written by Russ Allbery <rra@bogus.example.com>
**  This work is hereby placed in the public domain by its author.
**
**  Provides the same functionality as the standard library routine
**  inet_aton for those platforms that don't have it.  inet_aton is
**  thread-safe.
*/

/* #include "config.h" */
/* #include "clibrary.h" */
#include <netinet/in.h>

/* If we're running the test suite, rename inet_ntoa to avoid conflicts with
   the system version. */
#if TESTING
# define inet_aton test_inet_aton
int test_inet_aton(const char *, struct in_addr *);
#endif

int
inet_aton(const char *s, struct in_addr *addr)
{
    unsigned long octet[4], address;
    const char *p;
    int base, i;
    int part = 0;

    if (s == NULL) return 0;

    /* Step through each period-separated part of the address.  If we see
       more than four parts, the address is invalid. */
    for (p = s; *p != 0; part++) {
        if (part > 3) return 0;

        /* Determine the base of the section we're looking at.  Numbers are
           represented the same as in C; octal starts with 0, hex starts
           with 0x, and anything else is decimal. */
        if (*p == '0') {
            p++;
            if (*p == 'x') {
                p++;
                base = 16;
            } else {
                base = 8;
            }
        } else {
            base = 10;
        }

        /* Make sure there's actually a number.  (A section of just "0"
           would set base to 8 and leave us pointing at a period; allow
           that.) */
        if (*p == '.' && base != 8) return 0;
        octet[part] = 0;

        /* Now, parse this segment of the address.  For each digit, multiply
           the result so far by the base and then add the value of the
           digit.  Be careful of arithmetic overflow in cases where an
           unsigned long is 32 bits; we need to detect it *before* we
           multiply by the base since otherwise we could overflow and wrap
           and then not detect the error. */
        for (; *p != 0 && *p != '.'; p++) {
            if (octet[part] > 0xffffffffUL / base) return 0;

            /* Use a switch statement to parse each digit rather than
               assuming ASCII.  Probably pointless portability.... */
            switch (*p) {
                case '0':           i = 0;  break;
                case '1':           i = 1;  break;
                case '2':           i = 2;  break;
                case '3':           i = 3;  break;
                case '4':           i = 4;  break;
                case '5':           i = 5;  break;
                case '6':           i = 6;  break;
                case '7':           i = 7;  break;
                case '8':           i = 8;  break;
                case '9':           i = 9;  break;
                case 'A': case 'a': i = 10; break;
                case 'B': case 'b': i = 11; break;
                case 'C': case 'c': i = 12; break;
                case 'D': case 'd': i = 13; break;
                case 'E': case 'e': i = 14; break;
                case 'F': case 'f': i = 15; break;
                default:            return 0;
            }
            if (i >= base) return 0;
            octet[part] = (octet[part] * base) + i;
        }

        /* Advance over periods; the top of the loop will increment the
           count of parts we've seen.  We need a check here to detect an
           illegal trailing period. */
        if (*p == '.') {
            p++;
            if (*p == 0) return 0;
        }
    }
    if (part == 0) return 0;

    /* IPv4 allows three types of address specification:

           a.b
           a.b.c
           a.b.c.d

       If there are fewer than four segments, the final segment accounts for
       all of the remaining portion of the address.  For example, in the a.b
       form, b is the final 24 bits of the address.  We also allow a simple
       number, which is interpreted as the 32-bit number corresponding to
       the full IPv4 address.

       The first for loop below ensures that any initial segments represent
       only 8 bits of the address and builds the upper portion of the IPv4
       address.  Then, the remaining segment is checked to make sure it's no
       bigger than the remaining space in the address and then is added into
       the result. */
    address = 0;
    for (i = 0; i < part - 1; i++) {
        if (octet[i] > 0xff) return 0;
        address |= octet[i] << (8 * (3 - i));
    }
    if (octet[i] > (0xffffffffUL >> (i * 8))) return 0;
    address |= octet[i];
    if (addr != NULL) addr->s_addr = htonl(address);
    return 1;
}
#endif /* not HAVE_INET_ATON */


#ifndef HAVE_INET_PTON
#include <arpa/inet.h>
#include <sys/socket.h>
int
inet_pton(int af, const char *src, void *dst)
{
  switch (af) {
  case AF_INET:
    return inet_aton(src, (struct in_addr *)dst);
    break;
#ifdef AF_INET6
  case AF_INET6:
#endif /* AF_INET6 */
  default:
    fprintf(stderr, "warning: Bogus inet_pton() called\n");
    errno = EAFNOSUPPORT;
    return -1;
    break;
  }
}
#endif /* not HAVE_INET_PTON */

#ifndef HAVE_XDR_YPXFRSTAT
#include <rpc/rpc.h>
#include "yp.h"
bool_t
xdr_ypxfrstat(XDR *xdrs, ypxfrstat *objp)
{
    if (!xdr_enum(xdrs, (enum_t *)objp))
	return FALSE;

    return TRUE;
}
#endif /* not HAVE_XDR_YPXFRSTAT */

#ifndef HAVE_XDR_DOMAINNAME
#include <rpc/rpc.h>
bool_t
xdr_domainname(XDR *xdrs, domainname *objp)
{
    if (!xdr_string(xdrs, objp, YPMAXDOMAIN))
	return FALSE;

    return TRUE;
}
#endif /* not HAVE_XDR_DOMAINNAME */

#ifndef HAVE_XDR_YPRESP_XFR
#include <rpc/rpc.h>
bool_t
xdr_ypresp_xfr(XDR *xdrs, ypresp_xfr *objp)
{
    if (!xdr_u_int(xdrs, &objp->transid))
	return FALSE;

    if (!xdr_ypxfrstat(xdrs, &objp->xfrstat))
	return FALSE;

    return TRUE;
}
#endif /* not HAVE_XDR_YPRESP_XFR */

#ifndef HAVE_XDR_YPMAP_PARMS
bool_t
xdr_ypmap_parms(XDR *xdrs, ypmap_parms *objp)
{
  if (!xdr_domainname(xdrs, &objp->domain))
    return (FALSE);
  if (!xdr_mapname(xdrs, &objp->map))
    return (FALSE);
  if (!xdr_u_int(xdrs, &objp->ordernum))
    return (FALSE);
  if (!xdr_peername(xdrs, &objp->peer))
    return (FALSE);
  return (TRUE);
}
#endif /* not HAVE_XDR_YPMAP_PARMS */


#ifndef HAVE_XDR_YPREQ_XFR
bool_t
xdr_ypreq_xfr(XDR *xdrs, ypreq_xfr *objp)
{
  if (!xdr_ypmap_parms(xdrs, &objp->map_parms))
    return (FALSE);
  if (!xdr_u_int(xdrs, &objp->transid))
    return (FALSE);
  if (!xdr_u_int(xdrs, &objp->prog))
    return (FALSE);
  if (!xdr_u_int(xdrs, &objp->port))
    return (FALSE);
  return (TRUE);
}
#endif /* not HAVE_XDR_YPREQ_XFR */

#ifndef HAVE_XDR_MAPNAME
bool_t
xdr_mapname (XDR *xdrs, mapname *objp)
{
  if (!xdr_string (xdrs, objp, YPMAXMAP))
    return FALSE;

  return TRUE;
}
#endif /* not HAVE_XDR_MAPNAME */

#ifndef HAVE_XDR_PEERNAME
bool_t
xdr_peername (XDR *xdrs, peername *objp)
{
  if (!xdr_string (xdrs, objp, YPMAXPEER))
    return (FALSE);
  return (TRUE);
}
#endif /* not HAVE_XDR_PEERNAME */

#ifndef HAVE_XDR_YPSTAT
bool_t
xdr_ypstat (XDR *xdrs, ypstat *objp)
{
  if (!xdr_enum (xdrs, (enum_t *) objp))
    return FALSE;

  return TRUE;
}
#endif /* not HAVE_XDR_YPSTAT */

#ifndef HAVE_XDR_YPRESP_MASTER
bool_t
xdr_ypresp_master (XDR *xdrs, ypresp_master *objp)
{
  if (!xdr_ypstat (xdrs, &objp->stat))
    return FALSE;
  if (!xdr_peername (xdrs, &objp->peer))
    return FALSE;
  return TRUE;
}
#endif /* not HAVE_XDR_YPRESP_MASTER */

#ifndef HAVE_XDR_YPBIND_BINDING
bool_t
xdr_ypbind_binding (XDR *xdrs, ypbind_binding *objp)
{
  if (!xdr_opaque (xdrs, objp->ypbind_binding_addr, 4))
    return FALSE;
  if (!xdr_opaque (xdrs, objp->ypbind_binding_port, 2))
    return FALSE;
  return TRUE;
}
#endif /* not HAVE_XDR_YPBIND_BINDING */

#ifndef HAVE_XDR_YPREQ_NOKEY
bool_t
xdr_ypreq_nokey (XDR *xdrs, ypreq_nokey *objp)
{
  if (!xdr_domainname (xdrs, &objp->domain))
    return FALSE;

  if (!xdr_mapname (xdrs, &objp->map))
    return FALSE;

  return TRUE;
}
#endif /* not HAVE_XDR_YPREQ_NOKEY */

#ifndef HAVE_XDR_YPPUSH_STATUS
bool_t
xdr_yppush_status(XDR *xdrs, yppush_status *objp)
{
  if (!xdr_enum(xdrs, (enum_t *)objp))
    return (FALSE);
  return (TRUE);
}
#endif /* not HAVE_XDR_YPPUSH_STATUS */

#ifndef HAVE_XDR_YPPUSHRESP_XFR
bool_t
xdr_yppushresp_xfr(XDR *xdrs, yppushresp_xfr *objp)
{
  if (!xdr_u_int(xdrs, &objp->transid))
    return (FALSE);
  if (!xdr_yppush_status(xdrs, &objp->status))
    return (FALSE);
  return (TRUE);
}
#endif /* not HAVE_XDR_YPPUSHRESP_XFR */
