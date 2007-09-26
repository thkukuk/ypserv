#
# Copyright (c) 2001, 2003 Thorsten Kukuk <kukuk@suse.de>
#
AUTOMAKE_OPTIONS = 1.7 gnits
#

CLEANFILES = *~ ${SCRIPTS}

EXTRA_DIST = $(addsuffix .in,$(MANS)) $(addsuffix .in,$(SCRIPTS))

varypdir = /var/yp

man_MANS = pwupdate.8 ypinit.8

libexec_SCRIPTS = ypxfr_1perhour ypxfr_1perday ypxfr_2perday \
		create_printcap match_printcap pwupdate ypinit

noinst_SCRIPTS = ypMakefile

install-data-local:
	$(mkdir_p) "$(DESTDIR)$(varypdir)"
	$(install_sh_DATA) $(top_builddir)/scripts/ypMakefile "$(DESTDIR)$(varypdir)/Makefile"

