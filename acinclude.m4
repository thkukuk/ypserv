## ---------------------------------- ##
## Check if --with-efence was given.  ##
## ---------------------------------- ##

# serial 1

AC_DEFUN(AM_WITH_EFENCE,
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
AC_DEFUN(JAPHAR_GREP_CFLAGS,
[case "$CFLAGS" in
"$1" | "$1 "* | *" $1" | *" $1 "* )
  ifelse($#, 3, [$3], [:])
  ;;
*)
  $2
  ;;
esac
])
