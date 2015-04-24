/* Define common preprocessor symbol for HAVE_LIBGDBM and HAVE_LIBQDBM, since
 * libraries gdbm and qdbm have same symbol names. */
#undef HAVE_COMPAT_LIBGDBM
#ifdef HAVE_LIBGDBM
#define HAVE_COMPAT_LIBGDBM
#endif
#ifdef HAVE_LIBQDBM
#define HAVE_COMPAT_LIBGDBM
#endif

