/* Copyright (c) 2000 Thorsten Kukuk
   Author: Thorsten Kukuk <kukuk@suse.de>

   The YP Server is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License
   version 2 as published by the Free Software Foundation.

   The YP Server is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public
   License along with the YP Server; see the file COPYING. If
   not, write to the Free Software Foundation, Inc., 675 Mass Ave,
   Cambridge, MA 02139, USA. */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#define _GNU_SOURCE

#include "yp.h"

/* Default timeout can be changed using clnt_control() */
static struct timeval TIMEOUT = { 25, 0 };

enum clnt_stat
ypproc_match_2 (ypreq_key *argp, ypresp_val *clnt_res, CLIENT *clnt)
{
  return (clnt_call(clnt, YPPROC_MATCH,
		    (xdrproc_t) xdr_ypreq_key, (caddr_t) argp,
		    (xdrproc_t) xdr_ypresp_val, (caddr_t) clnt_res,
		    TIMEOUT));
}
