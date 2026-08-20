# sbase version
VERSION = 0.1

# paths
PREFIX = /usr/
MANPREFIX = $(PREFIX)/share/man

# tools
CC = clang
#AR =
RANLIB = ranlib
# OpenBSD requires SMAKE to be scripts/make
# SMAKE = scripts/make
SMAKE = $(MAKE)

# -lrt might be needed on some systems
# -DYYDEBUG adds more debug info when yacc is involved
CFLAGS   = -static
# LDFLAGS  =
