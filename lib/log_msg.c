
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdarg.h>
#include <syslog.h>
#include "log_msg.h"

/*
** Reports a message to stderr, if in debug mode, else to syslog
*/

int debug_flag = 0; /* per default no debug messages */

void 
log_msg (char *fmt,...)
{
  va_list ap;
#ifndef HAVE_VSYSLOG
  char msg[512];
#endif

  va_start (ap, fmt);
  if (debug_flag)
    {
      vfprintf (stderr, fmt, ap);
      fputc ('\n', stderr);
    }
  else
    {
#ifndef HAVE_VSYSLOG
      vsprintf (msg, fmt, ap);
      syslog (LOG_NOTICE, "%s", msg);
#else
      vsyslog (LOG_NOTICE, fmt, ap);
#endif
    }
  va_end (ap);
}
