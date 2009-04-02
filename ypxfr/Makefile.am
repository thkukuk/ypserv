#
# Copyright (c) 2000, 2001, 2003, 2007, 2009 Thorsten Kukuk <kukuk@linux-nis.org>
#
AUTOMAKE_OPTIONS = 1.7 gnits

localedir = $(datadir)/locale

DEFS = @DEFS@ -DLOCALEDIR=\"$(localedir)\" -DYPMAPDIR=\"@YPMAPDIR@\"
INCLUDES = -I$(top_srcdir)/lib -I$(top_srcdir) -I$(top_builddir) -I$(srcdir)

CLEANFILES = *~


EXTRA_DIST = ${MANS} ${XMLS}

man_MANS = ypxfr.8
XMLS = ypxfr.8.xml

noinst_HEADERS = ypxfr.h

libexec_PROGRAMS = ypxfr

ypxfr_SOURCES = ypxfr.c ypxfr_clnt.c ypxfr_xdr.c

ypxfr_LDADD = @LIBDBM@ $(top_builddir)/lib/libyp.a

if ENABLE_REGENERATE_MAN
%.8: %.8.xml
	$(XMLLINT) --nonet --xinclude --postvalid --noout $<
	$(XSLTPROC) -o $(srcdir)/$@ --path $(srcdir) --xinclude --nonet http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl $<
endif
