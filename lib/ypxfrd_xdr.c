/* Copyright (c) 1996, 1997, 1999, 2000 Thorsten Kukuk
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

#include "ypxfrd.h"

bool_t
xdr_xfrstat (XDR *xdrs, xfrstat *objp)
{
  if (!xdr_enum (xdrs, (enum_t *) objp))
    return FALSE;
  return TRUE;
}

bool_t
xdr_xfr_db_type (XDR *xdrs, xfr_db_type *objp)
{
  if (!xdr_enum (xdrs, (enum_t *) objp))
    return FALSE;
  return TRUE;
}

bool_t
xdr_xfr_byte_order (XDR *xdrs, xfr_byte_order *objp)
{
  if (!xdr_enum (xdrs, (enum_t *) objp))
    return FALSE;
  return TRUE;
}

bool_t
xdr_xfrdomain (XDR *xdrs, xfrdomain *objp)
{
  if (!xdr_string (xdrs, objp, ~0))
    return FALSE;
  return TRUE;
}

bool_t
xdr_xfrmap (XDR *xdrs, xfrmap *objp)
{
  if (!xdr_string (xdrs, objp, ~0))
    return FALSE;
  return TRUE;
}

bool_t
xdr_xfrmap_filename (XDR *xdrs, xfrmap_filename *objp)
{
  if (!xdr_string (xdrs, objp, ~0))
    return FALSE;
  return TRUE;
}

bool_t
xdr_ypxfr_mapname (XDR *xdrs, ypxfr_mapname *objp)
{
  if (!xdr_xfrmap (xdrs, &objp->xfrmap))
    return FALSE;
  if (!xdr_xfrdomain (xdrs, &objp->xfrdomain))
    return FALSE;
  if (!xdr_xfrmap_filename (xdrs, &objp->xfrmap_filename))
    return FALSE;
  if (!xdr_xfr_db_type (xdrs, &objp->xfr_db_type))
    return FALSE;
  if (!xdr_xfr_byte_order (xdrs, &objp->xfr_byte_order))
    return FALSE;
  return TRUE;
}

bool_t
xdr_xfr (XDR *xdrs, xfr *objp)
{
  if (!xdr_bool (xdrs, &objp->ok))
    return FALSE;

  switch (objp->ok)
    {
    case TRUE:
      if (!xdr_bytes
	  (xdrs, (char **) &objp->xfr_u.xfrblock_buf.xfrblock_buf_val,
	   (u_int *) &objp->xfr_u.xfrblock_buf.xfrblock_buf_len, ~0))
	return FALSE;
      break;
    case FALSE:
      if (!xdr_xfrstat (xdrs, &objp->xfr_u.xfrstat))
	return FALSE;
      break;
    default:
      return FALSE;
    }
  return TRUE;
}
