#ifndef __YP_DB_H__
#define __YP_DB_H__

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#define F_ALL   0x01
#define F_NEXT  0x02

#if defined(HAVE_LIBGDBM)
#include <gdbm.h>

#define DB_FILE GDBM_FILE
#define ypdb_fetch(a,b)  gdbm_fetch(a,b)
#define ypdb_exists(a,b)  gdbm_exists(a,b)
#define ypdb_free(a) free(a)
#define ypdb_firstkey(a) gdbm_firstkey(a)
#define ypdb_nextkey(a,b) gdbm_nextkey(a,b)

#elif defined(HAVE_NDBM)

#include <ndbm.h>

#define DB_FILE DBM*
#define ypdb_fetch(a,b)  dbm_fetch(a,b)
#define ypdb_free(a)

extern int ypdb_exists (DB_FILE file, datum key);
/* extern datum ypdb_firstkey (DB_FILE file); */
#define ypdb_firstkey(a) dbm_firstkey(a)
extern datum ypdb_nextkey (DB_FILE file, datum key);
extern datum ypdb_fetch (DB_FILE file, datum key);

#else

#error "No database found or selected !"

#endif

extern DB_FILE ypdb_open (const char *domain, const char *map);
extern int ypdb_close_all (void);
extern int ypdb_close (DB_FILE file);

#endif
