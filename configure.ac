#configure.ac
AC_INIT([user_manager],[1.0],[lorenzopiombini3@gmail.com])
AC_PREREQ([2.69])

#check for C compilers
AC_PROG_CC

#set include path and lib path
CFLAGS="$CFLAGS -I/usr/local/include"
LDFLAGS="$LDFLAGS -L/usr/local/lib"

#check for header file
AC_CHECK_HEADERS([str_op.h], [
    AC_DEFINE([HAVE_STR_OP_H], [1],[define to 1 if str_op.h is found])
], [
    AC_DEFINE([HAVE_STR_OP_H], [0],[define to 0 if str_op.h is not found])
])

#check fo libraries
AC_CHECK_LIB([strOP], [main], [
    AC_DEFINE([HAVE_LIBSTROP], [1], [define to 1 if libstrOP is found])
    AC_SUBST([HAVE_LIBSTROP])
], [
    AC_DEFINE([HAVE_LIBSTROP], [0], [define to 0 if libstrOP is not found])
    AC_SUBST([HAVE_LIBSTROP])
])


#create config.h
AC_CONFIG_HEADERS([config.h])

#create make file
AC_CONFIG_FILES([Makefile])

AC_OUTPUT
