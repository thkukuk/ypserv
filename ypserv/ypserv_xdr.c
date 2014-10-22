/* Copyright (C) 2014 Thorsten Kukuk
   Author: Thorsten Kukuk <kukuk@suse.de>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.  */


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <rpc/rpc.h>
#include "yp.h"

#define XDRMAXRECORD (16 * 1024 * 1024)

xdr_ypall_cb_t xdr_ypall_cb;

bool_t
xdr_keydat (XDR *xdrs, keydat *objp)
{
  return xdr_bytes (xdrs, (char **) &objp->keydat_val,
                    (u_int *) &objp->keydat_len, XDRMAXRECORD);
}

bool_t
xdr_valdat (XDR *xdrs, valdat *objp)
{
  return xdr_bytes (xdrs, (char **) &objp->valdat_val,
                    (u_int *) &objp->valdat_len, XDRMAXRECORD);
}



bool_t
xdr_ypreq_key (XDR *xdrs, ypreq_key *objp)
{
  if (!xdr_domainname (xdrs, &objp->domain))
    return FALSE;
  if (!xdr_mapname (xdrs, &objp->map))
    return FALSE;
  return xdr_keydat (xdrs, &objp->key);
}

bool_t
xdr_ypresp_val (XDR *xdrs, ypresp_val *objp)
{
  if (!xdr_ypstat (xdrs, &objp->stat))
    return FALSE;
  return xdr_valdat (xdrs, &objp->val);
}


bool_t
xdr_ypresp_key_val (XDR *xdrs, ypresp_key_val *objp)
{
  if (!xdr_ypstat (xdrs, &objp->stat))
    return FALSE;
  if (!xdr_valdat (xdrs, &objp->val))
    return FALSE;
  return xdr_keydat (xdrs, &objp->key);
}

bool_t
xdr_ypresp_order (XDR *xdrs, ypresp_order *objp)
{
  if (!xdr_ypstat (xdrs, &objp->stat))
    return FALSE;
  return xdr_u_int (xdrs, &objp->ordernum);
}

bool_t
xdr_ypmaplist (XDR *xdrs, ypmaplist *objp)
{
  char **tp;

  if (!xdr_mapname (xdrs, &objp->map))
    return FALSE;
  /* Prevent gcc warning about alias violation.  */
  tp = (void *) &objp->next;
  return xdr_pointer (xdrs, tp, sizeof (ypmaplist), (xdrproc_t) xdr_ypmaplist);
}

bool_t
xdr_ypresp_maplist (XDR *xdrs, ypresp_maplist *objp)
{
  char **tp;

  if (!xdr_ypstat (xdrs, &objp->stat))
    return FALSE;
  /* Prevent gcc warning about alias violation.  */
  tp = (void *) &objp->maps;
  return xdr_pointer (xdrs, tp, sizeof (ypmaplist), (xdrproc_t) xdr_ypmaplist);
}

bool_t
xdr_ypresp_all(XDR *xdrs, ypresp_all *objp)
{
  if (xdrs->x_op == XDR_ENCODE)
    {
      while (1)
	{
	  if (xdr_bool(xdrs, &objp->more) == FALSE ||
	      xdr_ypresp_key_val(xdrs, &objp->ypresp_all_u.val) == FALSE)
	    {
	      if (xdr_ypall_cb.u.close != NULL)
		(*(xdr_ypall_cb.u.close))(xdr_ypall_cb.data);
	      
	      xdr_ypall_cb.data = NULL;
	      
	      return FALSE;
	    }
	  
	  if ((objp->ypresp_all_u.val.stat != YP_TRUE) ||
	      (*xdr_ypall_cb.u.encode)(&objp->ypresp_all_u.val,
				       xdr_ypall_cb.data) != YP_TRUE)
	    {
	      objp->more = FALSE;
	      
	      if (xdr_ypall_cb.u.close != NULL)
		(*(xdr_ypall_cb.u.close))(xdr_ypall_cb.data);
	      
	      xdr_ypall_cb.data = NULL;
	      
	      if (!xdr_bool(xdrs, &objp->more))
		return FALSE;
	      
	      return TRUE;
	    }
	  
	}
    }
  
#ifdef NOTYET /* This code isn't needed in the server */
    else if (xdrs->x_op == XDR_DECODE)
    {
	int more = 0;


	while (1)
	{
	    if (!xdr_bool(xdrs, &objp->more))
		return FALSE;

	    switch (objp->more)
	    {
	      case TRUE:
		if (!xdr_ypresp_key_val(xdrs, &objp->ypresp_all_u.val))
		    return FALSE;

		if (more == 0)
		    more = (*xdr_ypall_callback->foreach.decoder)
			(&objp->ypresp_all_u.val, xdr_ypall_callback->data);
		break;

	      case FALSE:
		return TRUE;

	      default:
		return FALSE;
	    }
	}
	return FALSE;
    }
#endif

    return TRUE;
}
