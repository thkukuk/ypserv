#
# Copyright (c) 2000 SuSE GmbH, Nuernberg
#
# Author: Thorsten Kukuk <kukuk@suse.de>
#
AUTOMAKE_OPTIONS = 1.4 gnits
MAINT_CHARSET = latin1
#
INSTALL_PROGRAM = @INSTALL_PROGRAM@ -s -m 555

localedir = $(datadir)/locale

CFLAGS = @EXTRA_CFLAGS@ @CFLAGS@
DEFS = @DEFS@ -DLOCALEDIR=\"$(localedir)\"
INCLUDES = -I$(top_srcdir)/lib -I$(top_srcdir) -I$(top_builddir) -I$(srcdir)

CLEANFILES = *~

EXTRA_DIST = ${MANS}

man_MANS = ypxfr.8

noinst_HEADERS = ypxfr.h

libexec_PROGRAMS = ypxfr

ypxfr_SOURCES = ypxfr.c ypxfr_clnt.c ypxfr_xdr.c

ypxfr_LDADD = @LIBDBM@ $(top_builddir)/lib/libyp.a
