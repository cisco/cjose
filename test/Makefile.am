if HAVE_CHECK

AM_CPPFLAGS =-std=gnu99 --pedantic -Wall -g -O2 -I$(top_builddir)/include

AM_CPPFLAGS += @CHECK_CFLAGS@
TESTS = check_cjose

check_PROGRAMS = $(TESTS)
check_cjose_CFLAGS = @CHECK_CFLAGS@ -I$(top_builddir)/include \
                     -I$(top_builddir)/src
check_cjose_LDADD = $(top_builddir)/src/libcjose.la @CHECK_LIBS@
check_cjose_SOURCES = check_cjose.c \
                      check_version.c \
                      check_util.c \
                      check_base64.c \
                      check_concatkdf.c \
                      check_jwk.c \
                      check_jwe.c \
                      check_jws.c \
                      check_header.c \
                      check_cjose.h 

endif
