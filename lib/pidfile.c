/* Copyright (c) 2009, 2011 Thorsten Kukuk
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
   not, write to the Free Software Foundation, Inc., 51 Franklin Street,
   Suite 500, Boston, MA 02110-1335, USA. */

#include "pidfile.h"
#include "log_msg.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <fcntl.h>

void
create_pidfile (const char *filename, const char *daemonname)
{
  int fd, left, written;
  pid_t pid;
  char pbuf[50], *ptr;
  struct flock lock;

  fd = open (filename, O_CREAT | O_RDWR | O_CLOEXEC,
	     S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
  if (fd < 0)
    {
      log_msg ("cannot create pidfile %s", filename);
      if (debug_flag)
	log_msg ("\n");
      exit (1);
    }

  lock.l_type = F_WRLCK;
  lock.l_start = 0;
  lock.l_whence = SEEK_SET;
  lock.l_len = 0;

  /* Is the pidfile locked by another daemon ? */
  if (fcntl (fd, F_GETLK, &lock) < 0)
    {
      log_msg ("fcntl error");
      if (debug_flag)
	log_msg ("\n");
      exit (1);
    }
  if (lock.l_type == F_UNLCK)
    pid = 0;	        /* false, region is not locked by another proc */
  else
    pid = lock.l_pid;	/* true, return pid of lock owner */

  if (0 != pid)
    {
      log_msg ("%s already running (pid %d) - exiting", daemonname, pid);
      if (debug_flag)
	log_msg ("\n");
      exit (1);
    }

  /* write lock */
  lock.l_type = F_WRLCK;
  lock.l_start = 0;
  lock.l_whence = SEEK_SET;
  lock.l_len = 0;
  if (0 != fcntl (fd, F_SETLK, &lock))
    log_msg ("cannot lock pidfile");
  sprintf (pbuf, "%ld\n", (long) getpid ());
  left = strlen (pbuf);
  ptr = pbuf;
  while (left > 0)
    {
      if ((written = write (fd, ptr, left)) <= 0)
	return;			/* error */
      left -= written;
      ptr += written;
    }
  return;
}
