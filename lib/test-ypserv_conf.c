/* Copyright (c) 2016  Thorsten Kukuk
   Author: Thorsten Kukuk <kukuk@suse.de>

   The YP Server is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License
   version 2 as published by the Free Software Foundation.

   The YP Server is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>. */

#include <rpc/rpc.h>
#include <rpc/rpc_com.h>

#include "access.h"

extern int debug_flag;
extern const char *confdir;

int
main (void)
{
  debug_flag = 1;
  confdir = "test";

  load_config ();

  return 0;
}
