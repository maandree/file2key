.POSIX:

CONFIGFILE = config.mk
include $(CONFIGFILE)

all: file2key

file2key: file2key.o
	$(CC) -o $@ file2key.o $(LDFLAGS)

file2key.o: file2key.c settings.h config.h
	$(CC) -c -o $@ file2key.c $(CFLAGS) $(CPPFLAGS)

install: file2key
	mkdir -p -- "$(DESTDIR)$(PREFIX)/bin"
	mkdir -p -- "$(DESTDIR)$(MANPREFIX)/man1"
	cp -- file2key "$(DESTDIR)$(PREFIX)/bin/"
	cp -- file2key.1 "$(DESTDIR)$(MANPREFIX)/man1/"

uninstall:
	-rm -f -- "$(DESTDIR)$(PREFIX)/bin/file2key"
	-rm -f -- "$(DESTDIR)$(MANPREFIX)/man1/file2key.1"

clean:
	-rm -rf -- *.o file2key

.PHONY: all install uninstall clean
