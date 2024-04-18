#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

# bootstrap / init
AC_PREREQ([2.69])

AC_INIT([booth],
    [m4_esyscmd([build-aux/git-version-gen --fallback 1.2 .tarball-version .gitarchivever])],
    [users@clusterlabs.org])

AC_USE_SYSTEM_EXTENSIONS

AM_INIT_AUTOMAKE([-Wno-portability subdir-objects])

AC_CONFIG_MACRO_DIR([build-aux])
AC_CONFIG_SRCDIR([src/main.c])
AC_CONFIG_HEADERS([src/b_config.h src/booth_config.h])

AC_CANONICAL_HOST

AC_LANG([C])

dnl Fix default variables - "prefix" variable if not specified
if test "$prefix" = "NONE"; then
	prefix="/usr"

	dnl Fix "localstatedir" variable if not specified
	if test "$localstatedir" = "\${prefix}/var"; then
		localstatedir="/var"
	fi
	dnl Fix "sysconfdir" variable if not specified
	if test "$sysconfdir" = "\${prefix}/etc"; then
		sysconfdir="/etc"
	fi
	dnl Fix "libdir" variable if not specified
	if test "$libdir" = "\${exec_prefix}/lib"; then
		if test -e /usr/lib64; then
			libdir="/usr/lib64"
		else
			libdir="/usr/lib"
		fi
	fi
fi

AC_MSG_NOTICE(Sanitizing exec_prefix: ${exec_prefix})
case $exec_prefix in
  dnl For consistency with Corosync, map NONE->$prefix
  NONE)   exec_prefix=$prefix;;
  prefix) exec_prefix=$prefix;;
esac

# Checks for programs.

# check stolen from gnulib/m4/gnu-make.m4
if ! ${MAKE-make} --version /cannot/make/this >/dev/null 2>&1; then
	AC_MSG_ERROR([you don't seem to have GNU make; it is required])
fi

AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_RANLIB
PKG_PROG_PKG_CONFIG

AC_PATH_PROGS(ASCIIDOC, asciidoc)
AC_PATH_PROGS(ASCIIDOCTOR, asciidoctor)
AC_PATH_PROGS(A2X, a2x)

AM_CONDITIONAL(IS_ASCIIDOC, test x"${ASCIIDOC}" != x"")
AM_CONDITIONAL(IS_A2X, test x"${A2X}" != x"")
AM_CONDITIONAL(BUILD_ASCIIDOC, test x"${A2X}" != x"" || test x"${ASCIIDOCTOR}" != x"")

AC_CHECK_LIB([xml2], xmlReadDoc)
PKG_CHECK_MODULES(XML, [libxml-2.0])
PKG_CHECK_MODULES(GLIB, [glib-2.0])
PKG_CHECK_MODULES([PCMK], [pacemaker-service],,
		  [PKG_CHECK_MODULES([PCMK], [pcmk-service])])

# Python casing, prefer 3.3+ to 2.{6...}
if test "x$PYTHON" = "x"; then
	AM_PATH_PYTHON([3.3],, [AM_PATH_PYTHON([2.6])])
else
	# Just set Automake variables (mainly PYTHON_VERSION)
	AM_PATH_PYTHON
fi
PYTHON_SHEBANG="$PYTHON ${PYTHON_OPTS--Es}"
AC_SUBST([PYTHON_SHEBANG])
AM_CONDITIONAL(PYTHON_IS_VERSION3, test "x${PYTHON_VERSION%%.*}" = "x3")

# Checks for header files.
AC_FUNC_ALLOCA
AC_HEADER_DIRENT
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([arpa/inet.h fcntl.h limits.h netdb.h netinet/in.h stdint.h \
		  stdlib.h string.h sys/ioctl.h sys/param.h sys/socket.h \
		  sys/time.h syslog.h unistd.h sys/types.h getopt.h malloc.h \
		  sys/sockio.h utmpx.h])
AC_CHECK_HEADERS(heartbeat/glue_config.h)
AC_CHECK_HEADER([zlib.h],
		[AC_SUBST(ZLIB_LIBS, ["-lz"])],
		[AC_MSG_ERROR([zlib development files required])])
saved_CPPFLAGS="${CPPFLAGS}"
CPPFLAGS="${CPPFLAGS} ${PCMK_CFLAGS} ${GLIB_CFLAGS}"
AC_CHECK_HEADER([crm/services.h], [],
		[AC_MSG_ERROR([crm/services.h header required])])
CPPFLAGS="${saved_CPPFLAGS}"

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_UID_T
AC_C_INLINE
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_INT8_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T
AC_C_VOLATILE

# Checks for library functions.
AC_FUNC_CLOSEDIR_VOID
AC_FUNC_ERROR_AT_LINE
AC_REPLACE_FNMATCH
AC_FUNC_FORK
AC_PROG_GCC_TRADITIONAL
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_REALLOC
AC_FUNC_SELECT_ARGTYPES
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([alarm alphasort atexit bzero dup2 endgrent endpwent fcntl \
		getcwd getpeerucred getpeereid gettimeofday memmove \
		memset mkdir scandir select socket strcasecmp strchr strdup \
		strerror strrchr strspn strstr \
		sched_get_priority_max sched_setscheduler])

AC_CONFIG_FILES([Makefile
		 booth.pc
		 src/Makefile
		 docs/Makefile
		 conf/Makefile])
AC_CONFIG_FILES([conf/booth-arbitrator.service conf/booth@.service])
AC_CONFIG_FILES([script/service-runnable], [chmod +x script/service-runnable])

# ===============================================
# Helpers
# ===============================================

## PKG_CHECK_VAR wrapper that allows defining a default value
## when value from pkg-config is not detected

AC_DEFUN([BOOTH_PKG_CHECK_VAR], [
	  varname=$1
	  default=$4
	  AC_MSG_CHECKING([for pkg-conf $2 var $3])
	  PKG_CHECK_VAR([$1], [$2], [$3])
	  AS_VAR_IF([$1], [""],
		    [AS_VAR_IF([default], [""],
			       AC_MSG_ERROR([not found]),
			       [AS_VAR_COPY([$varname], [default]) && AC_MSG_RESULT([not found, using default ${!varname}])])],
		    [AC_MSG_RESULT([yes (detected: ${!varname})])])
])

## helper for CC stuff
cc_supports_flag() {
         local CFLAGS="-Werror $@"
         AC_MSG_CHECKING(whether $CC supports "$@")
         AC_COMPILE_IFELSE([AC_LANG_SOURCE([[int main(){return 0;}]])],
           [RC=0; AC_MSG_RESULT(yes)],[RC=1; AC_MSG_RESULT(no)])
         return $RC
}

## local defines
PACKAGE_FEATURES=""

# local options

AC_ARG_ENABLE([fatal-warnings],
	[  --enable-fatal-warnings         : enable fatal warnings. ],
	[ default="no" ])

AC_ARG_ENABLE([debug],
	[  --enable-debug                  : enable debug build. ],
	[ default="no" ])

AC_ARG_ENABLE([user-flags],
	[  --enable-user-flags             : rely on user environment. ],
	[ default="no" ])

AC_ARG_ENABLE([coverage],
	[  --enable-coverage               : coverage analysis of the codebase. ],
	[ default="no" ])

AC_ARG_WITH([initddir],
	[  --with-initddir=DIR             : path to init script directory. ],
	[ INITDDIR="$withval" ],
	[ INITDDIR="$sysconfdir/init.d" ])

AC_ARG_WITH([html_man],
	[  --with-html_man                 : Enable generating man pages in HTML.])

AM_CONDITIONAL(BUILD_ASCIIDOC_HTML_MAN,
	       (test "x${ASCIIDOC}" != "x" || test x"${ASCIIDOCTOR}" != x"") && test "x$with_html_man" = "xyes")

AC_ARG_WITH([glue],
	[  --without-glue                  : Avoid libraries from (cluster-)glue project.],
	[],
	[with_glue=yes])

AC_ARG_WITH([run_build_tests],
	[  --with-run-build-tests          : Enable running build tests when generating RPM],
	[run_build_tests=yes],
	[])
AM_CONDITIONAL([RUN_BUILD_TESTS], [test "x$run_build_tests" = "xyes"])

# figure out ocfdir automatically and allow manual override (mostly for CI)

BOOTH_PKG_CHECK_VAR([OCFROOT], [resource-agents], [ocfrootdir], [/usr/lib/ocf])

AC_ARG_WITH([ocfdir],
	[  --with-ocfdir=DIR               : path to ocfdir (default: autodetected). ],
	[ ocfdir="$withval" ],
	[ ocfdir="$OCFROOT" ])

AC_SUBST([ocfdir])

AC_ARG_WITH([hmac_library],
	[  --with-hmac-library=LIBRARY     : Select HMAC library to use (default: autodetect one of gnutls, gcrypt or mhash).])

# GnuTLS, libgcrypt or mhash for hmac
hmac_library_installed="no"
if test "x$with_hmac_library" == "x" && test "x$hmac_library_installed" == "xno" || \
    test "x$with_hmac_library" == "xgnutls"; then
	libgnutls_installed="yes"
	PKG_CHECK_MODULES([LIBGNUTLS], [gnutls >= 2.10.0], [
	    AC_DEFINE([HAVE_LIBGNUTLS], [1], [Have gnutls library])
	    libgnutls_installed="yes"
	    ], [libgnutls_installed="no"])
	hmac_library_installed="${libgnutls_installed}"
fi

if test "x$with_hmac_library" == "x" && test "x$hmac_library_installed" == "xno" || \
    test "x$with_hmac_library" == "xgcrypt"; then
	libgcrypt_installed="yes"
	AC_CHECK_HEADERS(gcrypt.h, , [libgcrypt_installed="no"],)
	AC_CHECK_LIB(gcrypt, gcry_md_open, , [libgcrypt_installed="no"])
	hmac_library_installed="${libgcrypt_installed}"
fi

if test "x$with_hmac_library" == "x" && test "x$hmac_library_installed" == "xno" || \
    test "x$with_hmac_library" == "xmhash"; then
	mhash_installed="yes"
	AC_CHECK_HEADERS(mhash.h, , [mhash_installed="no"],)
	AC_CHECK_LIB(mhash, mhash_init, , [mhash_installed="no"])
	hmac_library_installed="${mhash_installed}"
fi

if test "x$with_hmac_library" != "x" && test "x$hmac_library_installed" == "xno";then
	AC_MSG_ERROR([required HMAC library not detected])
fi

AM_CONDITIONAL(BUILD_AUTH_C, test "x${hmac_library_installed}" = "xyes")

# figure out logging provider
logging_provider=""
if test "x$logging_provider" = "x" && test "x$with_glue" = "xyes"; then
	AC_CHECK_LIB([plumb], [cl_log], [logging_provider="libplumb"])
fi
if test "x$logging_provider" = "x" && test "x$with_glue" = "xno"; then
	PKG_CHECK_MODULES([LIBQB], [libqb])
	AC_DEFINE([LOGGING_LIBQB], [], [use libqb as a logging provider])
	PKG_CHECK_MODULES([LIBQB1], [libqb >= 1.0],
			  [AC_DEFINE([LOGGING_LIBQB_MAJOR], [1],
				     [libqb major version lower bound])],
			  [AC_MSG_WARN([[syslog identifier will not get changed]])])
	logging_provider=libqb
fi
case "$logging_provider" in
libplumb)
	LOGGER="ha_logger"
	;;
libqb)
	LOGGER="logger -t booth-script"
	;;
*)
	AC_MSG_ERROR([logging provider required (libplumb, or libqb when --without-glue)])
	;;
esac
AM_CONDITIONAL([LOGGING_LIBQB], [test "x$logging_provider" = "xlibqb"])
AC_SUBST([LOGGER])

# figure out range2random provider
range2random_provider=""
if test "x$range2random_provider" = "x" && test "x$with_glue" = "xyes"; then
       AC_CHECK_LIB([plumb], [get_next_random], [range2random_provider="libplumb"])
       AC_CHECK_DECL([cl_rand_from_interval], [], [range2random_provider=""],
		     [#include <clplumbing/cl_random.h>])
fi
if test "x$range2random_provider" = "x" && test "x$with_glue" = "xno"; then
       AC_CHECK_LIB([glib-2.0], [g_random_int_range], [range2random_provider="glib"])
fi
case "$range2random_provider" in
libplumb)
	;;
glib)
	PKG_CHECK_MODULES([GLIB], [glib-2.0])
	AC_DEFINE([RANGE2RANDOM_GLIB], [], [use glib as a range2random provider])
	;;
*)
	AC_MSG_ERROR([range2random provider required (libplumb, or glib when --without-glue)])
	;;
esac
AM_CONDITIONAL([RANGE2RANDOM_GLIB], [test "x$range2random_provider" = "xglib"])

# figure out nametag/distinguished-role provider
nametag_provider=""
if test "x$nametag_provider" = "x" && test "x$with_glue" != "xno"; then
	AC_CHECK_LIB([plumbgpl], [set_proc_title], [nametag_provider="libplumbgpl"])
fi
if test "x$nametag_provider" = "x" && test "x$with_glue" = "xno"; then
	AC_SEARCH_LIBS([sd_notify], [systemd systemd-daemon], [nametag_provider="libsystemd"])
fi
NOTIFY_ACCESS_SWITCH='# '
case "$nametag_provider" in
libplumbgpl)
	;;
libsystemd)
	PKG_CHECK_MODULES([LIBSYSTEMD], [libsystemd],, [
		PKG_CHECK_MODULES([LIBSYSTEMD], [libsystemd-daemon])
	])
	AC_DEFINE([NAMETAG_LIBSYSTEMD], [], [use libsystemd as a nametag provider])
	NOTIFY_ACCESS_SWITCH=
	;;
*)
	AC_MSG_ERROR([nametag provider required (libplumbgpl, or libsystemd when --without-glue)])
	;;
esac
AM_CONDITIONAL([NAMETAG_LIBSYSTEMD], [test "x$nametag_provider" = "xlibsystemd"])
AC_SUBST([NOTIFY_ACCESS_SWITCH])

# figure out if "coredump nursing" supported and desired
coredump_nursing="no"
if test "x$with_glue" != "xno"; then
	AC_CHECK_LIB([plumb], [cl_enable_coredumps], [coredump_nursing="libplumb"])
fi
if test "x$coredump_nursing" != "xno"; then
	AC_DEFINE(COREDUMP_NURSING, [], [eligible for coredump nursing])
fi
AM_CONDITIONAL([COREDUMP_NURSING], [test "x$coredump_nursing" != "xno"])

# define CRM daemon user & group
BOOTH_PKG_CHECK_VAR([CRM_DAEMON_USER], [pacemaker], [daemon_user], [hacluster])
AC_DEFINE_UNQUOTED(CRM_DAEMON_USER,"$CRM_DAEMON_USER", User to run Booth daemon as)

BOOTH_PKG_CHECK_VAR([CRM_DAEMON_GROUP], [pacemaker], [daemon_group], [haclient])
AC_DEFINE_UNQUOTED(CRM_DAEMON_GROUP,"$CRM_DAEMON_GROUP", Group to run Booth daemon as)

# If libpacemaker is available, use it
PKG_CHECK_MODULES([LIBPACEMAKER], [libpacemaker >= 2.1.7])
if test "x$LIBPACEMAKER_CFLAGS" != "xno"; then
    AC_DEFINE([LIBPACEMAKER], [1], [use libpacemaker for ticket manipulation])
fi

# *FLAGS handling goes here

ENV_CFLAGS="$CFLAGS"
ENV_CPPFLAGS="$CPPFLAGS"
ENV_LDFLAGS="$LDFLAGS"

# debug build stuff
if test "x${enable_debug}" = xyes; then
	AC_DEFINE_UNQUOTED([DEBUG], [1], [Compiling Debugging code])
	OPT_CFLAGS="-O0 -U_FORTIFY_SOURCE"
	PACKAGE_FEATURES="$PACKAGE_FEATURES debug"
else
	OPT_CFLAGS="-O3"
fi

# gdb flags
if test "x${GCC}" = xyes; then
	GDB_FLAGS="-ggdb3"
else
	GDB_FLAGS="-g"
fi

dnl Check for POSIX clock_gettime
dnl
AC_CACHE_CHECK([have clock_gettime],ac_cv_HAVE_CLOCK_GETTIME,[
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <time.h>
]],
[[ struct timespec tv; clock_gettime(CLOCK_REALTIME, &tv); return 0;]])],
[ac_cv_HAVE_CLOCK_GETTIME=yes], [ac_cv_HAVE_CLOCK_GETTIME=no])])
AM_CONDITIONAL(BUILD_TIMER_C, test x"$ac_cv_HAVE_CLOCK_GETTIME" = x"yes")

# extra warnings
EXTRA_WARNINGS=""

WARNLIST="
	all
	shadow
	missing-prototypes
	missing-declarations
	strict-prototypes
	declaration-after-statement
	pointer-arith
	write-strings
	bad-function-cast
	missing-format-attribute
	format=2
	format-security
	format-nonliteral
	no-long-long
	unsigned-char
	gnu89-inline
	no-strict-aliasing
	"

for j in $WARNLIST; do
	if cc_supports_flag -W$j; then
		EXTRA_WARNINGS="$EXTRA_WARNINGS -W$j";
	fi
done

if test "x${enable_coverage}" = xyes && \
		cc_supports_flag -ftest-coverage && \
		cc_supports_flag -fprofile-arcs ; then
	AC_MSG_NOTICE([Enabling Coverage (enable -O0 by default)])
	OPT_CFLAGS="-O0"
	COVERAGE_CFLAGS="-ftest-coverage -fprofile-arcs"
	COVERAGE_LDFLAGS="-ftest-coverage -fprofile-arcs"
	PACKAGE_FEATURES="$PACKAGE_FEATURES coverage"
else
	COVERAGE_CFLAGS=""
	COVERAGE_LDFLAGS=""
fi

if test "x${enable_fatal_warnings}" = xyes && \
		cc_supports_flag -Werror ; then
	AC_MSG_NOTICE([Enabling Fatal Warnings (-Werror)])
	WERROR_CFLAGS="-Werror"
	PACKAGE_FEATURES="$PACKAGE_FEATURES fatal-warnings"
else
	WERROR_CFLAGS=""
fi

# don't add addtional cflags
if test "x${enable_user_flags}" = xyes; then
  OPT_CFLAGS=""
  GDB_FLAGS=""
  EXTRA_WARNINGS=""
fi

# final build of *FLAGS
CFLAGS="$ENV_CFLAGS $OPT_CFLAGS $GDB_FLAGS $OS_CFLAGS \
	$COVERAGE_CFLAGS $EXTRA_WARNINGS $WERROR_CFLAGS $LIBGNUTLS_CFLAGS"
CPPFLAGS="$ENV_CPPFLAGS $OS_CPPFLAGS $GLIB_CFLAGS $RESMON_CFLAGS $XML_CFLAGS"
LDFLAGS="$ENV_LDFLAGS $COVERAGE_LDFLAGS $OS_LDFLAGS"
LIBS="$LIBS $XML_LIBS $LIBGNUTLS_LIBS $LIBPACEMAKER_LIBS"

# substitute what we need:
AC_SUBST([INITDDIR])

BOOTH_LIB_DIR=${localstatedir}/lib/booth
BOOTH_CORE_DIR=${localstatedir}/lib/booth/cores
BOOTHSYSCONFDIR=${sysconfdir}/booth

AC_SUBST([HAVE_LOG_CIB_DIFF])
AC_SUBST([HAVE_XML_LOG_PATCHSET])
AC_SUBST([BOOTH_LIB_DIR])
AC_SUBST([BOOTH_CORE_DIR])
AC_SUBST([BOOTHSYSCONFDIR])

AC_DEFINE_UNQUOTED([BOOTH_LIB_DIR], "$(eval echo ${BOOTH_LIB_DIR})", [booth lib directory])
AC_DEFINE_UNQUOTED([BOOTH_CORE_DIR], "$(eval echo ${BOOTH_CORE_DIR})", [booth working directory])
AC_DEFINE_UNQUOTED([BOOTHSYSCONFDIR], "$(eval echo ${BOOTHSYSCONFDIR})", [booth config directory])

AC_DEFINE_UNQUOTED([PACKAGE_FEATURES], "${PACKAGE_FEATURES}", [booth built-in features])

AC_OUTPUT

AC_MSG_RESULT([])
AC_MSG_RESULT([$PACKAGE configuration:])
AC_MSG_RESULT([  Version                  = ${VERSION}])
AC_MSG_RESULT([  Prefix                   = ${prefix}])
AC_MSG_RESULT([  Executables              = ${sbindir}])
AC_MSG_RESULT([  Man pages                = ${mandir}])
AC_MSG_RESULT([  Doc dir                  = ${docdir}])
AC_MSG_RESULT([  Libraries                = ${libdir}])
AC_MSG_RESULT([  Header files             = ${includedir}])
AC_MSG_RESULT([  Arch-independent files   = ${datadir}])
AC_MSG_RESULT([  State information        = ${localstatedir}])
AC_MSG_RESULT([  System configuration     = ${sysconfdir}])
AC_MSG_RESULT([  System init.d directory  = ${INITDDIR}])
AC_MSG_RESULT([  booth config dir         = ${BOOTHSYSCONFDIR}])
AC_MSG_RESULT([  ocf dir                  = ${ocfdir}])
AC_MSG_RESULT([  Features                 = ${PACKAGE_FEATURES}])
AC_MSG_RESULT([  Logging provider         = ${logging_provider}])
AC_MSG_RESULT([  Range2random provider    = ${range2random_provider}])
AC_MSG_RESULT([  Nametag provider         = ${nametag_provider}])
AC_MSG_RESULT([  Coredump nursing         = ${coredump_nursing}])
AC_MSG_RESULT([  Working directory        = ${BOOTH_CORE_DIR}])
AC_MSG_RESULT([  HA group name            = ${CRM_DAEMON_GROUP}])
AC_MSG_RESULT([  HA user name             = ${CRM_DAEMON_USER}])
AC_MSG_RESULT([])
AC_MSG_RESULT([$PACKAGE build info:])
AC_MSG_RESULT([  Default optimization     = ${OPT_CFLAGS}])
AC_MSG_RESULT([  Default debug options    = ${GDB_CFLAGS}])
AC_MSG_RESULT([  Extra compiler warnings  = ${EXTRA_WARNING}])
AC_MSG_RESULT([  Env. defined CFLAG       = ${ENV_CFLAGS}])
AC_MSG_RESULT([  Env. defined CPPFLAGS    = ${ENV_CPPFLAGS}])
AC_MSG_RESULT([  Env. defined LDFLAGS     = ${ENV_LDFLAGS}])
AC_MSG_RESULT([  Coverage     CFLAGS      = ${COVERAGE_CFLAGS}])
AC_MSG_RESULT([  Coverage     LDFLAGS     = ${COVERAGE_LDFLAGS}])
AC_MSG_RESULT([  Fatal War.   CFLAGS      = ${WERROR_CFLAGS}])
AC_MSG_RESULT([  Final        CFLAGS      = ${CFLAGS}])
AC_MSG_RESULT([  Final        CPPFLAGS    = ${CPPFLAGS}])
AC_MSG_RESULT([  Final        LDFLAGS     = ${LDFLAGS}])
