/* See LICENSE file for copyright and license details. */
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef WITH_LIBPASSPHRASE
# include <termios.h>
#endif
#include <unistd.h>

#ifdef WITH_LIBPASSPHRASE
# include <passphrase.h>
#endif
#include <libkeccak.h>

#include "config.h"
#include "settings.h"


/**
 * Map from hexadecimal to colour-coded hexadecimal
 */
const char *const COLOUR_HEX[] = {
	['0'] = "\033[31m0",
	['1'] = "\033[31m1",
	['2'] = "\033[32m2",
	['3'] = "\033[33m3",
	['4'] = "\033[32m4",
	['5'] = "\033[33m5",
	['6'] = "\033[31m6",
	['7'] = "\033[34m7",
	['8'] = "\033[34m8",
	['9'] = "\033[34m9",
	['a'] = "\033[32ma",
	['b'] = "\033[31mb",
	['c'] = "\033[33mc",
	['d'] = "\033[34md",
	['e'] = "\033[33me",
	['f'] = "\033[32mf",
};



/**
 * `argv[0]` from `main`
 */
static char *argv0;



/**
 * Ask the user for the passphrase
 * 
 * @param   passphrasep  Output parameter for the passphrase
 * @return               Zero on success, an appropriate exit value on error
 */
static int
get_passphrase(char **passphrasep)
{
#ifndef WITH_LIBPASSPHRASE
	struct termios stty, stty_saved;
	char *passphrase = NULL, *new;
	size_t len = 0, size = 0;
	ssize_t r;
#endif
	int ttyfd;
	ttyfd = open("/dev/tty", O_RDONLY);
	if (ttyfd < 0) {
		perror(argv0);
		return 2;
	}

#ifdef WITH_LIBPASSPHRASE
	passphrase_disable_echo1(ttyfd);
	fprintf(stderr, "%s", PASSPHRASE_PROMPT_STRING);
	fflush(stderr);
	*passphrasep = passphrase_read2(ttyfd, PASSPHRASE_READ_EXISTING);
	if (!*passphrasep)
		perror(argv0);
	passphrase_reenable_echo1(ttyfd);
	close(ttyfd);
	return *passphrasep ? 0 : 2;

#else
	memset(&stty, 0, sizeof(stty));
	if (tcgetattr(ttyfd, &stty)) {
		perror(argv0);
		close(ttyfd);
		return 2;
	}
	memcpy(&stty_saved, &stty, sizeof(stty));
	stty.c_lflag &= (tcflag_t)~ECHO;
	tcsetattr(ttyfd, TCSAFLUSH, &stty);
	fprintf(stderr, "%s", PASSPHRASE_PROMPT_STRING);
	fflush(stderr);

	for (;;) {
		if (len == size) {
			new = realloc(passphrase, size += 32);
			if (!new) {
				perror(argv0);
				close(ttyfd);
				if (passphrase) {
					memset(passphrase, 0, len);
					free(passphrase);
				}
				return 2;
			}
			passphrase = new;
		}
		r = read(ttyfd, &passphrase[len], 1);
		if (r < 0) {
			perror(argv0);
			memset(passphrase, 0, len);
			free(passphrase);
			close(ttyfd);
			return 2;
		} else if (!r || passphrase[len] == '\n') {
			passphrase[len] = 0;
			break;
		} else {
			len += 1;
		}
	}

	fprintf(stderr, "\n");
	tcsetattr(ttyfd, TCSAFLUSH, &stty_saved);
	close(ttyfd);
	*passphrasep = passphrase;
	return 0;
#endif
}


/**
 * Hash, and display, passphrase so to hint the
 * user whether it as typed correctly or not
 * 
 * @param   passphrase  The passphrase
 * @return              Zero on success, an appropriate exit value on error
 */
static int
hash_passphrase(const char *passphrase)
{
	struct libkeccak_spec spec;
	struct libkeccak_state state;
	char hashsum[PASSPHRASE_KECCAK_OUTPUT / 8];
	char hexsum[PASSPHRASE_KECCAK_OUTPUT / 4 + 1];
	size_t i, n;

	spec.bitrate  = PASSPHRASE_KECCAK_RATE;
	spec.capacity = PASSPHRASE_KECCAK_CAPACITY;
	spec.output   = PASSPHRASE_KECCAK_OUTPUT;

	if (libkeccak_spec_check(&spec) || PASSPHRASE_KECCAK_SQUEEZES <= 0) {
		fprintf(stderr, "%s: bad passhprase hashing parameters, please recompile file2key with with "
		                    "proper values on PASSPHRASE_KECCAK_RATE, PASSPHRASE_KECCAK_CAPACITY, "
		                    "PASSPHRASE_KECCAK_OUTPUT and PASSPHRASE_KECCAK_SQUEEZES", argv0);
		return 1;
	}

	if (libkeccak_state_initialise(&state, &spec)) {
		perror(argv0);
		return 2;
	}

	if (libkeccak_digest(&state, passphrase, strlen(passphrase), 0, NULL, PASSPHRASE_KECCAK_SQUEEZES == 1 ? hashsum : NULL)) {
		perror(argv0);
		libkeccak_state_destroy(&state);
		return 2;
	}
	if (PASSPHRASE_KECCAK_SQUEEZES > 2)
		libkeccak_fast_squeeze(&state, PASSPHRASE_KECCAK_SQUEEZES - 2);
	if (PASSPHRASE_KECCAK_SQUEEZES > 1)
		libkeccak_squeeze(&state, hashsum);

	libkeccak_state_destroy(&state);

	libkeccak_behex_lower(hexsum, hashsum, sizeof(hashsum) / sizeof(char));
	fprintf(stderr, "%s: passphrase hash: ", argv0);
	for (i = 0, n = strlen(hexsum); i < n; i++)
		fprintf(stderr, "%s", COLOUR_HEX[(unsigned char)hexsum[i]]);
	fprintf(stderr, "\033[00m\n");

	return 0;
}


/**
 * @return  0: success
 *          1: user error
 *          2: on system error
 */
int
main(int argc, char *argv[])
{
	struct libkeccak_generalised_spec gspec;
	struct libkeccak_spec spec;
	struct libkeccak_state state;
	char *passphrase = NULL;
	char *hash = NULL;
	size_t hash_size = 0;
	size_t hash_ptr = 0;
	char *data = NULL;
	size_t data_size = 0;
	size_t data_ptr = 0;
	size_t blksize = 4096;
	int r, fd = -1;
	struct stat attr;
	size_t start;
	ssize_t n;

	argv0 = *argv++, argc--;
	if (argc > 0 && argv[0][0] == '-') {
		if (argv[0][1] == '-' && !argv[0][2])
			argv++, argc--;
		else if (argv[0][1])
			goto usage;
	}
	if (argc > 1) {
	usage:
		fprintf(stderr, "usage: %s [file]\n", argv0);
		return 1;
	}

	if (argc > 0 && strcmp(argv[0], "-")) {
		fd = open(argv[0], O_RDONLY);
		if (fd < 0)
			goto pfail;
	} else {
		fd = STDIN_FILENO;
	}
	if (isatty(fd)) {
		fprintf(stderr, "%s: input file must not be a terminal\n", argv0);
		close(fd);
		return 1;
	}
	if (fstat(fd, &attr) == 0)
		if (attr.st_blksize > 0)
			blksize = (size_t)attr.st_blksize;

	libkeccak_generalised_spec_initialise(&gspec);
	libkeccak_degeneralise_spec(&gspec, &spec);
	if (libkeccak_state_initialise(&state, &spec))
		goto pfail;
	if ((r = get_passphrase(&passphrase)))
		goto fail;
	if ((r = hash_passphrase(passphrase)))
		goto fail;
	if (libkeccak_update(&state, passphrase, strlen(passphrase)))
		goto pfail;
#ifdef WITH_LIBPASSPHRASE
	passphrase_wipe(passphrase, strlen(passphrase));
#else
	memset(passphrase, 0, strlen(passphrase));
#endif
	free(passphrase);
	passphrase = NULL;

	hash_size = (size_t)(spec.output / 8);
	if (!(hash = malloc(hash_size)))
		goto pfail;
	if (!(data = malloc(blksize)))
		goto pfail;

	if (libkeccak_digest(&state, KEY_PEPPER, strlen(KEY_PEPPER), 0, NULL, hash))
		goto pfail;

	for (;;) {
		if (hash_ptr == hash_size) {
			libkeccak_squeeze(&state, hash);
			hash_ptr = 0;
		}

		if (data_ptr == data_size) {
			n = read(fd, data, blksize);
			if (n <= 0) {
				if (!n)
					break;
				goto pfail;
			}
			data_size = (size_t)n;
			data_ptr = 0;
		}

		start = data_ptr;
		while (hash_ptr < hash_size && data_ptr < data_size)
			data[data_ptr++] ^= hash[hash_ptr++];

		while (start < data_ptr) {
			n = write(STDOUT_FILENO, &data[start], data_ptr - start);
			if (n <= 0)
				goto pfail;
			start += (size_t)n;
		}
	}

	r = 0;
	goto done;

pfail:
	r = 2;
	perror(*argv);
fail:
	if (passphrase) {
#ifdef WITH_LIBPASSPHRASE
		passphrase_wipe(passphrase, strlen(passphrase));
#else
		memset(passphrase, 0, strlen(passphrase));
#endif
		free(passphrase);
	}
done:
	libkeccak_state_destroy(&state);
	free(data);
	free(hash);
	if (argc > 0 && fd >= 0)
		close(fd);
	return r;
}
