#
#
#

### Prerequisites
AC_INIT([cjose], [0.7.0])
AM_INIT_AUTOMAKE([foreign])
LT_PREREQ([2.2])
LT_INIT([dlopen])
AC_CONFIG_MACRO_DIR([m4])

### Basic program checks
AC_PROG_CC

### Check for Doxygen
DX_FEATURE_pdf([OFF])
DX_FEATURE_ps([OFF])
DX_INIT_DOXYGEN([CJOSE], [Doxyfile], [doc])

### Check for CHECK
PKG_CHECK_MODULES([CHECK],
        [check >= 0.9.4],
        [have_check="yes"],
        [   AC_MSG_WARN([Check not found; cannot run unit tests!]);
            [have_check="no"]
        ])
AM_CONDITIONAL(HAVE_CHECK, test x"$have_check" = "xyes")

#### Find OpenSSL
AC_MSG_CHECKING([for --with-openssl])
AC_ARG_WITH(
    [openssl],
    [AS_HELP_STRING([--with-openssl],[Location where OpenSSL can be found])],
    [ LDFLAGS="$LDFLAGS -L$with_openssl/lib";
      CFLAGS="$CFLAGS -I$with_openssl/include/";
      CPPFLAGS="$CPPFLAGS -I$with_openssl/include/";
      AC_MSG_RESULT([$with_openssl])
    ],
    [ AC_MSG_RESULT([no])]
)

AC_CHECK_LIB([crypto],
    [CRYPTO_new_ex_data],
    [],
    [AC_MSG_ERROR([OpenSSL is missing; it is required for this software])]
)

##### Check for Fundamental EC #####
AC_CHECK_HEADERS([openssl/fec.h])

#### Find Jansson
AC_MSG_CHECKING([for --with-jansson])
AC_ARG_WITH(
    [jansson],
    [AS_HELP_STRING([--with-jansson], [Location where Jansson can be found])],
    [ LDFLAGS="$LDFLAGS -L$with_jansson/lib";
      CFLAGS="$CFLAGS -I$with_jansson/include/";
      CPPFLAGS="$CPPFLAGS -I$with_jansson/include/";
      AC_MSG_RESULT([$with_jansson])
    ],
    [ AC_MSG_RESULT([no])]
)

AC_CHECK_LIB([jansson],
    [json_object],
    [],
    [AC_MSG_ERROR([Jansson is missing; it is required for this software])]
)

#### Allow risky rsa pkcs 1.5 for systems where this is really needed
AC_MSG_CHECKING([for RSA PKCS v1.5])
AC_ARG_WITH(
    [rsapkcs1_5],
    [AS_HELP_STRING([--with-rsapkcs1_5], [Enable risky RSA PKCS v1.5])],
    [rsapkcs1_5=${withval}],
    [rsapkcs1_5=no])

AC_MSG_RESULT([$rsapkcs1_5])

if test "x$rsapkcs1_5" == xyes ; then
    AC_DEFINE(HAVE_RSA_PKCS1_PADDING, 1)
fi

AM_EXTRA_RECURSIVE_TARGETS([package])
AC_CONFIG_FILES([Makefile
                 include/Makefile include/cjose/version.h
                 src/Makefile
                 test/Makefile
                 doc/Makefile doc/Doxyfile
                 platform/Makefile platform/centos/Makefile platform/debian/Makefile
                 cjose.pc])

AC_OUTPUT

echo "
  ($PACKAGE_NAME) version $PACKAGE_VERSION
  Prefix.........: $prefix
  Using OpenSSL..: $with_openssl
  Using Jansson..: $with_jansson
  Unit tests.....: $have_check
"
