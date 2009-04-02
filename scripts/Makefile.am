#
# Copyright (c) 2001, 2003, 2007 Thorsten Kukuk <kukuk@linux-nis.org>
#
AUTOMAKE_OPTIONS = 1.7 gnits
#

CLEANFILES = *~ ${SCRIPTS}

EXTRA_DIST = ${MANS} ${XMLS}

varypdir = /var/yp

man_MANS = pwupdate.8 ypinit.8
XMLS = pwupdate.8.xml ypinit.8.xml

libexec_SCRIPTS = ypxfr_1perhour ypxfr_1perday ypxfr_2perday \
		create_printcap match_printcap pwupdate ypinit

noinst_SCRIPTS = ypMakefile

install-data-local:
	$(mkdir_p) "$(DESTDIR)$(varypdir)"
	$(install_sh_DATA) $(top_builddir)/scripts/ypMakefile "$(DESTDIR)$(varypdir)/Makefile"

if ENABLE_REGENERATE_MAN
%.8: %.8.xml
	$(XMLLINT) --nonet --xinclude --postvalid --noout $<
	$(XSLTPROC) -o $(srcdir)/$@ --path $(srcdir) --xinclude --nonet http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl $<
endif
