#
# Copyright (c) 2001, 2003, 2006 Thorsten Kukuk <kukuk@suse.de>
#
AUTOMAKE_OPTIONS = 1.7 gnits
#

localedir = $(datadir)/locale

DEFS = @DEFS@ -DLOCALEDIR=\"$(localedir)\" -DYPBINDIR=\"$(libexecdir)\" \
	-DCONFDIR=\"$(sysconfdir)\" -DYPMAPDIR=\"@YPMAPDIR@\" \
	-DUSE_FQDN=@USE_FQDN@
AM_CPPFLAGS = -I$(top_srcdir)/lib -I$(top_srcdir) -I$(top_builddir) -I$(srcdir)

CLEANFILES = *~

EXTRA_DIST = ${MANS} ${XMLS}

man_MANS = yppasswdd.8 rpc.yppasswdd.8
XMLS = rpc.yppasswdd.8.xml

noinst_HEADERS = yppwd_local.h yppasswd.x

sbin_PROGRAMS = rpc.yppasswdd

rpc_yppasswdd_SOURCES = update.c yppasswd_xdr.c yppasswdd.c

rpc_yppasswdd_LDADD =  @PIE_LDFLAGS@ $(top_builddir)/lib/libyp.a $(LIBDBM) $(LIBCRYPT) @SYSTEMD_LIBS@ @NIS_LIBS@ @TIRPC_LIBS@
rpc_yppasswdd_CFLAGS = @PIE_CFLAGS@ @SYSTEMD_CFLAGS@ @NIS_CFLAGS@ @TIRPC_CFLAGS@

if ENABLE_REGENERATE_MAN
%.8: %.8.xml
	$(XMLLINT) --nonet --xinclude --postvalid --noout $<
	$(XSLTPROC) -o $(srcdir)/$@ --path $(srcdir) --xinclude --nonet http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl $<
endif

