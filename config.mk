PREFIX = /usr/local
MANPREFIX = $(CONFIGFILE)

CFLAGS   = -std=c99 -Wall -Wextra -O2
CPPFLAGS = -D_DEFAULT_SOURCE -D_BSD_SOURCE -D_XOPEN_SOURCE=700
LDFLAGS  = -s -lpassphrase -lkeccak
