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

#ifndef _LIB_YPXFRD_H_
#define _LIB_YPXFRD_H_

#include <rpc/rpc.h>

#define YPXFRBLOCK 32767

enum xfrstat {
  XFR_REQUEST_OK = 1,
  XFR_DENIED = 2,
  XFR_NOFILE = 3,
  XFR_ACCESS = 4,
  XFR_BADDB = 5,
  XFR_READ_OK = 6,
  XFR_READ_ERR = 7,
  XFR_DONE = 8,
  XFR_DB_ENDIAN_MISMATCH = 9,
  XFR_DB_TYPE_MISMATCH = 10
};
typedef enum xfrstat xfrstat;

enum xfr_db_type {
  XFR_DB_ASCII = 1,
  XFR_DB_BSD_HASH = 2,
  XFR_DB_BSD_BTREE = 3,
  XFR_DB_BSD_RECNO = 4,
  XFR_DB_BSD_MPOOL = 5,
  XFR_DB_BSD_NDBM = 6,
  XFR_DB_GNU_GDBM = 7,
  XFR_DB_DBM = 8,
  XFR_DB_NDBM = 9,
  XFR_DB_OPAQUE = 10,
  XFR_DB_ANY = 11,
  XFR_DB_UNKNOWN = 12,
  XFR_DB_GNU_GDBM64 = 13
};
typedef enum xfr_db_type xfr_db_type;

enum xfr_byte_order {
  XFR_ENDIAN_BIG = 1,
  XFR_ENDIAN_LITTLE = 2,
  XFR_ENDIAN_ANY = 3
};
typedef enum xfr_byte_order xfr_byte_order;

typedef char *xfrdomain;
typedef char *xfrmap;
typedef char *xfrmap_filename;

struct ypxfr_mapname {
  xfrmap xfrmap;
  xfrdomain xfrdomain;
  xfrmap_filename xfrmap_filename;
  xfr_db_type xfr_db_type;
  xfr_byte_order xfr_byte_order;
};
typedef struct ypxfr_mapname ypxfr_mapname;

struct xfr {
  bool_t ok;
  union {
    struct {
      u_int xfrblock_buf_len;
      char *xfrblock_buf_val;
    } xfrblock_buf;
    xfrstat xfrstat;
  } xfr_u;
};
typedef struct xfr xfr;

#define YPXFRD_FREEBSD_PROG 600100069
#define YPXFRD_FREEBSD_VERS 1

#define YPXFRD_GETMAP 1
extern  struct xfr *ypxfrd_getmap_1 (ypxfr_mapname *, CLIENT *);
extern  struct xfr *ypxfrd_getmap_1_svc (ypxfr_mapname *, struct svc_req *);
extern  void ypxfrd_freebsd_prog_1 (struct svc_req *, register SVCXPRT *);
extern  int ypxfrd_freebsd_prog_1_freeresult (SVCXPRT *, xdrproc_t, caddr_t);

extern  bool_t xdr_xfrstat (XDR *, xfrstat*);
extern  bool_t xdr_xfr_db_type (XDR *, xfr_db_type*);
extern  bool_t xdr_xfr_byte_order (XDR *, xfr_byte_order*);
extern  bool_t xdr_xfrdomain (XDR *, xfrdomain*);
extern  bool_t xdr_xfrmap (XDR *, xfrmap*);
extern  bool_t xdr_xfrmap_filename (XDR *, xfrmap_filename*);
extern  bool_t xdr_xfrstat (XDR *, xfrstat*);
extern  bool_t xdr_xfr_db_type (XDR *, xfr_db_type*);
extern  bool_t xdr_xfr_byte_order (XDR *, xfr_byte_order*);
extern  bool_t xdr_ypxfr_mapname (XDR *, ypxfr_mapname*);
extern  bool_t xdr_xfr (XDR *, xfr*);

#endif /* !_LIB_YPXFRD_H_ */
