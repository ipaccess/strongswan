
INCLUDES = -I$(top_srcdir)/src/libstrongswan

AM_CFLAGS = -rdynamic

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-gmp.la
else
plugin_LTLIBRARIES = libstrongswan-gmp.la
endif

libstrongswan_gmp_la_SOURCES = \
	gmp_plugin.h gmp_plugin.c \
	gmp_util.c gmp_util.h \
	gmp_diffie_hellman.c gmp_diffie_hellman.h \
	gmp_rsa_private_key.c gmp_rsa_private_key.h \
	gmp_rsa_public_key.c gmp_rsa_public_key.h \
	gmp_rsa_private_key_share.c gmp_rsa_private_key_share.h

libstrongswan_gmp_la_LDFLAGS = -module -avoid-version
libstrongswan_gmp_la_LIBADD  = -lgmp
