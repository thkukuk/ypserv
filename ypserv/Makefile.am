#
# Copyright (c) 2000, 2001, 2003, 2007, 2009 Thorsten Kukuk <kukuk@linux-nis.org>
#
AUTOMAKE_OPTIONS = 1.7 gnits

localedir = $(datadir)/locale

DEFS = @DEFS@ -DLOCALEDIR=\"$(localedir)\" -DYPBINDIR=\"$(libexecdir)\" \
	-DYPMAPDIR=\"@YPMAPDIR@\" -DUSE_FQDN=@USE_FQDN@ -DUSE_SLP=@USE_SLP@
INCLUDES = -I$(top_srcdir)/lib -I$(top_srcdir) -I$(top_builddir) -I$(srcdir)

CLEANFILES = *~

EXTRA_DIST = ${MANS} ${XMLS}

man_MANS = ypserv.8
XMLS = ypserv.8.xml

noinst_HEADERS = reg_slp.h

sbin_PROGRAMS = ypserv

ypserv_SOURCES = ypserv.c server.c ypserv_xdr.c reg_slp.c

ypserv_LDADD =  @PIE_LDFLAGS@ $(top_builddir)/lib/libyp.a @LIBDBM@ @LIBSLP@ $(LIBSYSTEMD_DAEMON)
ypserv_CFLAGS = @PIE_CFLAGS@

if ENABLE_REGENERATE_MAN
%.8: %.8.xml
	$(XMLLINT) --nonet --xinclude --postvalid --noout $<
	$(XSLTPROC) -o $(srcdir)/$@ --path $(srcdir) --xinclude --nonet http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl $<
endif
