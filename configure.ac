#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT(ssg, 1.0, support@shashouge.com)

# Checks for programs.
AC_PROG_AWK
AC_PROG_CXX(gxlc++ g++)
AC_PROG_MAKE_SET


if test "x$CXX" = "xgxlc++" ; then
    LDFLAGS="$LDFLAGS "
    CPPFLAGS="-w -g -m64 -fPIC -fpic -D__WM_POWER_LINUX "
    CXXFLAGS="-w -g -m64 -fPIC -fpic -D__WM_POWER_LINUX "
    LIB_CFLAGS="-shared -fPIC -fpic"
    LIB_LDFLAGS="-shared -fPIC -fpic"
    ARCHIVE="ar"
    AR_FLAGS="-r"
    LIB_SUFFIX="so"
    STS_SUFFIX="a"
elif test "x$CXX" = "xg++" ; then
    LDFLAGS="$LDFLAGS "
    CPPFLAGS="-g -Wall -D__WM_LINUX -fPIC -fpic -m64 -std=c++11 -pthread"
    CXXFLAGS="-g -Wall -D__WM_LINUX -fPIC -fpic -m64 -std=c++11 -pthread"
    LIB_CFLAGS="-shared -fPIC -fpic"
    LIB_LDFLAGS="-shared -fPIC -fpic"
    ARCHIVE="ar"
    AR_FLAGS="-r"
    LIB_SUFFIX="so"
    STS_SUFFIX="a"
fi

AC_SUBST(LIB_CFLAGS)
AC_SUBST(LIB_LDFLAGS)
AC_SUBST(ARCHIVE)
AC_SUBST(AR_FLAGS)
AC_SUBST(LIB_SUFFIX)
AC_SUBST(STS_SUFFIX)

if test "x$prefix" = "xNONE" ; then
     prefix=`pwd`
fi

com=`chmod +x upversion-sh`

libdir=@prefix@/lib
# Checks for libraries.

# Checks for header files.
#AC_CHECK_HEADERS([arpa/inet.h fcntl.h limits.h netinet/in.h stdlib.h string.h sys/socket.h sys/time.h unistd.h])
AC_CHECK_HEADERS([string.h])
# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.
#AC_FUNC_FORK
#AC_FUNC_MKTIME
#AC_FUNC_SELECT_ARGTYPES
#AC_TYPE_SIGNAL
#AC_FUNC_VPRINTF
#AC_CHECK_FUNCS([alarm dup2 gettimeofday inet_ntoa localtime_r memset select socket strcasecmp strerror strrchr strtol])
AC_CHECK_FUNCS([strlwr])

AC_OUTPUT([Makefile
	base/Makefile
	base/test/Makefile
	src/Makefile
	src/gateway/Makefile
    src/gateway/gateway/Makefile
    src/gateway/gateway_send/Makefile
    src/gateway/channeldll/Makefile
    src/gateway/channeldll/cmpp2/Makefile
    src/gateway/channeldll/cmpp3/Makefile
    src/gateway/channeldll/sgip/Makefile
    src/gateway/channeldll/smgp/Makefile
    src/gateway/channeldll/http/Makefile
    src/gateway/manager/Makefile
    src/gateway/uniqio/Makefile
    tool/simulator/sim_service/Makefile
    tool/simulator/cmpp2/Makefile
    tool/simulator/cmpp3/Makefile
    tool/simulator/sgip/Makefile
    tool/simulator/smgp/Makefile
    tool/ipc_tool/Makefile
])
