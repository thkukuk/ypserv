/* Copyright (c) 2000 Thorsten Kukuk
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
   not, write to the Free Software Foundation, Inc., 675 Mass Ave,
   Cambridge, MA 02139, USA. */

#ifndef _YPSERV_COMPAT_H
#define _YPSERV_COMPAT_H

#include "config.h"

#ifndef HAVE_STPCPY
char *stpcpy(char *, const char *);
#endif /* not HAVE_STPCPY */

#ifndef HAVE_STRNDUP
char *strndup (const char *, int);
#endif /* not HAVE_STRNDUP */

#ifndef HAVE_GETOPT_LONG
struct option {
  const char *name;
  int has_arg;
  int *flag;
  int val;
};

# define no_argument            0
# define required_argument      1
# define optional_argument      2

int getopt_long (int argc, char *const *argv, const char *shortopts,
		 const struct option *longopts, int *longind);
#endif /* not HAVE_GETOPT_LONG */

#if !defined(HAVE_GETDELIM) && !defined(HAVE_GETLINE)
/* Use getline() if getdelim() is missing */
#include <unistd.h> /* size_t */
#include <stdio.h> /* FILE */
ssize_t getline (char **lineptr, size_t *n, FILE *stream);
#endif /*  not HAVE_GETDELIM and not HAVE_GETLINE */

#ifndef HAVE_SVC_GETCALLER
#  include <rpc/rpc.h>
#  if !defined(svc_getcaller)
struct sockaddr_in;
const struct sockaddr_in *svc_getcaller(const SVCXPRT *xprt);
#  endif
#endif /* not HAVE_SVC_GETCALLER */

#ifndef HAVE__RPC_DTABLESIZE
int _rpc_dtablesize(void);
#endif

#ifndef HAVE_INET_PTON
int inet_pton(int af, const char *src, void *dst);
#endif /* not HAVE_INET_PTON */


#endif /* not _YPSERV_COMPAT_H */
