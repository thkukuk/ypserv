#
# Copyright (c) 2001 Thorsten Kukuk <kukuk@suse.de>
#
AUTOMAKE_OPTIONS = 1.4 gnits
MAINT_CHARSET = latin1
#
INSTALL_PROGRAM = @INSTALL_PROGRAM@ -s -m 555

CLEANFILES = *~ ${SCRIPTS}

EXTRA_DIST = $(addsuffix .in,$(MANS)) $(addsuffix .in,$(SCRIPTS))

man_MANS = pwupdate.8 ypinit.8

libexec_SCRIPTS = ypxfr_1perhour ypxfr_1perday ypxfr_2perday \
		create_printcap match_printcap pwupdate ypinit
