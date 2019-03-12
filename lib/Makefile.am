#
# Copyright (c) 2000, 2001, 2003 Thorsten Kukuk <kukuk@suse.de>
#
# Process this file with automake to produce Makefile.in.

AUTOMAKE_OPTIONS = 1.7 gnits

rpcsvcdir = ${prefix}/include/rpcsvc

EXTRA_DIST = test/ypserv.conf securenets.test

noinst_LIBRARIES = libyp.a
noinst_HEADERS = log_msg.h yp.h ypserv_conf.h ypxfrd.h access.h yp_db.h \
		pidfile.h

rpcsvc_HEADERS = ypxfrd.x

DEFS = @DEFS@ -D_REENTRANT=1 -DCONFDIR=\"$(sysconfdir)\" \
	-DYPMAPDIR=\"@YPMAPDIR@\" -DUSE_SD_NOTIFY=@USE_SD_NOTIFY@
AM_CPPFLAGS = -I$(top_srcdir) -I$(top_builddir) -I$(srcdir)
AM_CFLAGS = @PIE_CFLAGS@ @NSL_CFLAGS@ @TIRPC_CFLAGS@ -Werror

libyp_a_SOURCES = log_msg.c ypserv_conf.c ypxfrd_xdr.c \
		ypproc_match_2.c securenets.c access.c yp_db.c \
		pidfile.c

check_PROGRAMS = test-securenets test-ypserv_conf
test_securenets_LDADD = securenets.o log_msg.o @TIRPC_LIBS@
test_ypserv_conf_LDADD = libyp.a @TIRPC_LIBS@ @NSL_LIBS@ @LIBDBM@ @SYSTEMD_LIBS@

TESTS = $(check_PROGRAMS)

CLEANFILES = *~
