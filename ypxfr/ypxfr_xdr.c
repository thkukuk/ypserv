/* Copyright (c) 1996, 1997, 1999, 2001, 2003, 2014  Thorsten Kukuk
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
   not, write to the Free Software Foundation, Inc., 51 Franklin Street,
   Suite 500, Boston, MA 02110-1335, USA. */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <memory.h>
#include <unistd.h>
#include <rpc/rpc.h>
#include "yp.h"

struct {
  union {
    ypstat (*encoder) (char *, int, char **, int *, char **, int *);
    int (*decoder) (int, char *, int, char *, int, char *);
  }
  foreach;
  char *data;
} *xdr_ypall_callback;

bool_t
ypxfr_xdr_ypresp_all (XDR *xdrs, ypresp_all *objp)
{
  int CallAgain = 0;

  if (xdrs->x_op == XDR_DECODE)
    {
      while (1)
	{
	  int s = objp->ypresp_all_u.val.status;
	  memset (objp, '\0', sizeof (*objp));
	  objp->ypresp_all_u.val.status = s;
	  if (!xdr_bool (xdrs, &objp->more))
	    return FALSE;

	  switch (objp->more)
	    {
	    case TRUE:
	      if (!xdr_ypresp_key_val (xdrs, &objp->ypresp_all_u.val))
		{
		  printf ("xdr_ypresp_key_val failed\n");
		  return (FALSE);
		}

	      if (CallAgain == 0)
		{
		  CallAgain = (*(xdr_ypall_callback->foreach.decoder))
		    (objp->ypresp_all_u.val.status,
		     objp->ypresp_all_u.val.keydat.keydat_val,
		     objp->ypresp_all_u.val.keydat.keydat_len,
		     objp->ypresp_all_u.val.valdat.valdat_val,
		     objp->ypresp_all_u.val.valdat.valdat_len,
		     xdr_ypall_callback->data);
		}
	      break;
	    case FALSE:
	      return TRUE;
	    }
	  xdr_free ((xdrproc_t) ypxfr_xdr_ypresp_all, (char *) objp);
	}
    }
  else if (xdrs->x_op == XDR_ENCODE)
    {
      while (1)
	{
	  if (!xdr_bool (xdrs, &(objp->more)))
	    return FALSE;

	  if (!xdr_ypresp_key_val (xdrs, &objp->ypresp_all_u.val))
	    {
	      printf ("xdr_ypresp_key_val failed\n");
	      return FALSE;
	    }
	  if (objp->ypresp_all_u.val.status != YP_TRUE)
	    {
	      objp->more = FALSE;
	      if (!xdr_bool (xdrs, &(objp->more)))
		return FALSE;

	      return TRUE;
	    }
	  objp->ypresp_all_u.val.status =
	    (*(xdr_ypall_callback->foreach.encoder))
	    (objp->ypresp_all_u.val.keydat.keydat_val,
	     objp->ypresp_all_u.val.keydat.keydat_len,
	     &(objp->ypresp_all_u.val.keydat.keydat_val),
	     (int *) &(objp->ypresp_all_u.val.keydat.keydat_len),
	     &(objp->ypresp_all_u.val.valdat.valdat_val),
	     (int *) &(objp->ypresp_all_u.val.valdat.valdat_len));
	}
    }
  else
    return TRUE;
}

/* Default timeout can be changed using clnt_control() */
static struct timeval TIMEOUT = { 25, 0 };

enum clnt_stat
ypproc_all_2 (ypreq_nokey *argp, ypresp_all *clnt_res, CLIENT *clnt)
{
  memset(clnt_res, 0, sizeof(ypresp_all));
  return (clnt_call(clnt, YPPROC_ALL,
                    (xdrproc_t) xdr_ypreq_nokey, (caddr_t) argp,
                    (xdrproc_t) ypxfr_xdr_ypresp_all, (caddr_t) clnt_res,
                    TIMEOUT));
}
