#
# Copyright (c) 2006 Thorsten Kukuk <kukuk@thkukuk.de>
#

AUTOMAKE_OPTIONS = 1.7 gnits

EXTRA_DIST = README locale netgroup netmasks securenets timezone ypserv.conf \
		${MANS} ${XMLS}

CLEANFILES = *~

man_MANS = netgroup.5 ypserv.conf.5
XMLS = netgroup.5.xml ypserv.conf.5.xml

if ENABLE_REGENERATE_MAN
%.5: %.5.xml
	$(XMLLINT) --nonet --xinclude --postvalid --noout $<
	$(XSLTPROC) -o $(srcdir)/$@ --path $(srcdir) --xinclude --nonet http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl $<
endif
