#
# Copyright (c) 2001, 2003, 2007 Thorsten Kukuk <kukuk@suse.de>
#
AUTOMAKE_OPTIONS = 1.7 gnits
#

localedir = $(datadir)/locale

DEFS = @DEFS@ -DLOCALEDIR=\"$(localedir)\" -DYPBINDIR=\"$(libexecdir)\" \
	-DCONFDIR=\"$(sysconfdir)\" -DYPMAPDIR=\"@YPMAPDIR@\" \
	-DUSE_FQDN=@USE_FQDN@ -DXFRBLOCKSIZE=65535
INCLUDES = -I$(top_srcdir)/lib -I$(top_srcdir) -I$(top_builddir) -I$(srcdir)

CLEANFILES = *~

EXTRA_DIST = ${MANS} ${XMLS}

man_MANS = ypxfrd.8 rpc.ypxfrd.8
XMLS = rpc.ypxfrd.8.xml

sbin_PROGRAMS = rpc.ypxfrd

rpc_ypxfrd_SOURCES = ypxfrd.c ypxfrd_server.c ypxfrd_svc.c

rpc_ypxfrd_LDADD = @PIE_LDFLAGS@ $(top_builddir)/lib/libyp.a @LIBDBM@ $(LIBSYSTEMD_DAEMON)
rpc_ypxfrd_CFLAGS = @PIE_CFLAGS@

if ENABLE_REGENERATE_MAN
%.8: %.8.xml
	$(XMLLINT) --nonet --xinclude --postvalid --noout $<
	$(XSLTPROC) -o $(srcdir)/$@ --path $(srcdir) --xinclude --nonet http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl $<
endif
