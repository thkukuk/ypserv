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

#ifndef __ACCESS_H__
#define __ACCESS_H__

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <rpc/rpc.h>

/* access.c */
extern void load_config (void);
extern int is_valid_domain (const char *domain);
extern int is_valid (struct svc_req *rqstp, const char *map,
		     const char *domain);

/* securenets.c */
extern void load_securenets (void);
extern int securenet_host (const struct in_addr sin_addr);

#endif
