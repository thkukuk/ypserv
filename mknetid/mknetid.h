/*
** Copyright (c) 1996, 1999 Thorsten Kukuk
**
** This file is part of the NYS YP Server.
**
** The NYS YP Server is free software; you can redistribute it and/or
** modify it under the terms of the GNU General Public License as
** published by the Free Software Foundation; either version 2 of the
** License, or (at your option) any later version.
**
** The NYS YP Server is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
** General Public License for more details.
** 
** You should have received a copy of the GNU General Public
** License along with the NYS YP Server; see the file COPYING.  If
** not, write to the Free Software Foundation, Inc., 675 Mass Ave,
** Cambridge, MA 02139, USA.
**
** Author: Thorsten Kukuk <kukuk@suse.de>
*/

#ifndef _MKNETID_H_
#define _MKNETID_H_

extern int insert_user(const char *key, const char *domain, 
			const char *uid, const char *gid);
extern int insert_host(const char *host, const char *domain);
extern void print_table(void);
extern int add_group(const char *key, const char *grp);

#endif
