/* Copyright (c) 2000, 2003, 2004 Thorsten Kukuk
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

#ifndef __YPSERV_CONF_H__
#define __YPSERV_CONF_H__

#include <rpc/rpc.h>

/* Struct for ypserv.conf options */
typedef struct conffile
{
  struct in_addr netmask;
  struct in_addr network;
  char *domain;
  char *map;
  int security;
  struct conffile *next;
} conffile_t;

extern int dns_flag;
extern int slp_flag;
extern unsigned long int slp_timeout;
extern int cached_filehandles;
extern int xfr_check_port;
extern char *trusted_master;

extern void load_config(void);
extern conffile_t *load_ypserv_conf(const char *);

/* Defines for ypserv.conf */

/* Security field: */
#define SEC_NONE 0
#define SEC_DENY 1
#define SEC_PORT 2

#endif
