PREFIX    = /usr
MANPREFIX = $(PREFIX)/share/man

CC = c99

CPPFLAGS = -D_DEFAULT_SOURCE -D_BSD_SOURCE -D_XOPEN_SOURCE=700
CFLAGS   = -O2
LDFLAGS  = -s -lkeccak

# To use libpassphrase, add -DWITH_LIBPASSPHRASE to CPPFLAGS and -lpassphrase to LDFLAGS
