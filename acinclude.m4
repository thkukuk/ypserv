## ---------------------------------- ##
## Check if --with-efence was given.  ##
## ---------------------------------- ##

# serial 1

AC_DEFUN([AM_WITH_EFENCE],
[AC_MSG_CHECKING(if malloc debugging with efence is wanted)
AC_ARG_WITH(efence,
[  --with-efence           use ElectricFence],
[if test "$withval" = yes; then
  AC_MSG_RESULT(yes)
  AC_DEFINE(WITH_EFENCE,1,
            [Define if using the ElectricFence debugging malloc package])
  LIBS="$LIBS -lefence"
  LDFLAGS="$LDFLAGS -g"
  CFLAGS="-g"
else
  AC_MSG_RESULT(no)
fi], [AC_MSG_RESULT(no)])
])

dnl
dnl JAPHAR_GREP_CFLAGS(flag, cmd_if_missing, cmd_if_present)
dnl
dnl From Japhar.  Report changes to japhar@hungry.com
dnl
AC_DEFUN([JAPHAR_GREP_CFLAGS],
[case "$CFLAGS" in
"$1" | "$1 "* | *" $1" | *" $1 "* )
  ifelse($#, 3, [$3], [:])
  ;;
*)
  $2
  ;;
esac
])


dnl
dnl Test for __attribute__ ((unused))
dnl Based on code from the tcpdump version 3.7.2 source.
dnl

AC_DEFUN([AC_C___ATTRIBUTE__], [
AC_MSG_CHECKING(for __attribute__)
AC_CACHE_VAL(ac_cv___attribute__, [
AC_TRY_COMPILE([
#include <stdlib.h>
static void foo (void) __attribute__ ((unused));

static void
foo (void)
{
  exit(1);
}
],
[
  exit (0);
],
ac_cv___attribute__=yes,
ac_cv___attribute__=no)])
if test "$ac_cv___attribute__" = "yes"; then
  AC_DEFINE(UNUSED, __attribute__ ((unused)), [define if your compiler has __attribute__ ((unused))])
else
  AC_DEFINE(UNUSED,,)
fi
AC_MSG_RESULT($ac_cv___attribute__)
])

dnl
dnl Check whether sys/socket.h defines type socklen_t. Please note
dnl that some systems require sys/types.h to be included before
dnl sys/socket.h can be compiled.
dnl
dnl Source: http://www.gnu.org/software/ac-archive/htmldoc/type_socklen_t.html
dnl Version: 1.2 (last modified: 2000-07-19)
dnl Author: Lars Brinkhoff <lars@nocrew.org>
dnl Changed by Petter Reinholdtsen to use the new AC_DEFINE() arguments
dnl
AC_DEFUN([TYPE_SOCKLEN_T],
[AC_CACHE_CHECK([for socklen_t], ac_cv_type_socklen_t,
[
  AC_TRY_COMPILE(
  [#include <sys/types.h>
   #include <sys/socket.h>],
  [socklen_t len = 42; return 0;],
  ac_cv_type_socklen_t=yes,
  ac_cv_type_socklen_t=no)
])
  if test $ac_cv_type_socklen_t != yes; then
    AC_DEFINE([socklen_t], [int], [Define if socklen_t is missing])
  fi
])
