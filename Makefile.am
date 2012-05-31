#
# Copyright (c) 2000, 2001, 2006 Thorsten Kukuk <kukuk@thkukuk.de>
#
AUTOMAKE_OPTIONS = 1.5 gnits dist-bzip2
#
SUBDIRS = etc lib ypserv ypxfr yppush makedbm revnetgroup rpc.ypxfrd \
	rpc.yppasswdd yphelper mknetid scripts

CLEANFILES = *~

M4_FILES = $(shell ls $(srcdir)/m4/*.m4)
EXTRA_DIST = $(M4_FILES) conf_post.h

ACLOCAL_AMFLAGS = -I m4

