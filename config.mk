PREFIX    = /usr
MANPREFIX = $(PREFIX)/share/man

CC = cc

CPPFLAGS = -D_DEFAULT_SOURCE -D_BSD_SOURCE -D_XOPEN_SOURCE=700
CFLAGS   = -std=c99 -O2
LDFLAGS  = -s -lkeccak

# To use libpassphrase, add -DWITH_LIBPASSPHRASE to CPPFLAGS and -lpassphrase to LDFLAGS
