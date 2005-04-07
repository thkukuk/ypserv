#
# Copyright (c) 2000, 2001, 2003 Thorsten Kukuk <kukuk@suse.de>
#
# Process this file with automake to produce Makefile.in.

AUTOMAKE_OPTIONS = 1.7 gnits

rpcsvcdir = ${prefix}/include/rpcsvc

noinst_LIBRARIES = libyp.a
noinst_HEADERS = log_msg.h yp.h ypserv_conf.h ypxfrd.h access.h yp_db.h \
		compat.h

rpcsvc_HEADERS = ypxfrd.x

DEFS = @DEFS@ -D_REENTRANT=1 -DCONFDIR=\"$(sysconfdir)\" -DUSE_SLP=@USE_SLP@
INCLUDES = -I$(top_srcdir) -I$(top_builddir) -I$(srcdir)
AM_CFLAGS = @PIE_CFLAGS@

libyp_a_SOURCES = log_msg.c ypserv_conf.c ypxfrd_xdr.c \
		ypproc_match_2.c securenets.c access.c yp_db.c compat.c

CLEANFILES = *~
