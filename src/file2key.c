/**
 * file2key – A simple command that generates a key from a file and a passphrase
 * 
 * Copyright © 2014  Mattias Andrée (maandree@member.fsf.org)
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>

#include <passphrase.h>
#include <libkeccak.h>



/**
 * Random string created with `dd if=/dev/random bs=1024 count=1 | tr -d -c a-zA-Z0-9`
 */
#define STATIC_SALT  "5EbppWrYxMuBKQmbDz8rOCVCONsSLas74qrjMLTiJqsYWcTePNeshVXcmAWGkh88VeFh"


/**
 * Prompt string that tells you to enter your passphrase
 */
#ifndef PASSPHRASE_PROMPT_STRING
# define PASSPHRASE_PROMPT_STRING  "[file2key] Enter passphrase: "
# warning: you should personalise PASSPHRASE_PROMPT_STRING.
#endif

/**
 * The rate parameter for the Keccak sponge when hashing master passphrase
 */
#ifndef PASSPHRASE_KECCAK_RATE
# define PASSPHRASE_KECCAK_RATE  576
#endif

/**
 * The capacity parameter for the Keccak sponge when hashing master passphrase
 */
#ifndef PASSPHRASE_KECCAK_CAPACITY
# define PASSPHRASE_KECCAK_CAPACITY  1024
#endif

/**
 * The output parameter for the Keccak sponge when hashing master passphrase
 */
#ifndef PASSPHRASE_KECCAK_OUTPUT
# define PASSPHRASE_KECCAK_OUTPUT  32
#endif

/**
 * The number of times to squeeze the master passphrase
 */
#ifndef PASSPHRASE_KECCAK_SQUEEZES
# define PASSPHRASE_KECCAK_SQUEEZES  10000
#endif



/**
 * Map from hexadecimal to colour-coded hexadecimal
 */
const char* const COLOUR_HEX[] =
  {
    ['0'] = "\033[31m0",
    ['1'] = "\033[31m1",
    ['2'] = "\033[31m2",
    ['3'] = "\033[31m3",
    ['4'] = "\033[31m4",
    ['5'] = "\033[32m5",
    ['6'] = "\033[32m6",
    ['7'] = "\033[32m7",
    ['8'] = "\033[32m8",
    ['9'] = "\033[32m9",
    ['a'] = "\033[34ma",
    ['b'] = "\033[34mb",
    ['c'] = "\033[34mc",
    ['d'] = "\033[34md",
    ['e'] = "\033[34me",
    ['f'] = "\033[34mf",
  };



#define USER_ERROR(string)				\
  (fprintf(stderr, "%s: %s.\n", execname, string), 1)

#define tt(expr)  if ((r = (expr)))  goto fail

#define t(expr)  if (expr)  goto pfail



/**
 * `argv[0]` from `main`
 */
static char* execname;



/**
 * Ask the user for the passphrase
 * 
 * @param   passphrase  Output parameter for the passphrase
 * @return              Zero on success, an appropriate exit value on error
 */
static int get_passphrase(char** passphrase)
{
  passphrase_disable_echo();
  fprintf(stderr, "%s", PASSPHRASE_PROMPT_STRING);
  fflush(stderr);
  *passphrase = passphrase_read();
  if (*passphrase == NULL)
    perror(execname);
  passphrase_reenable_echo();
  return *passphrase ? 0 : 2;
}


/**
 * Hash, and display, passphrase so to hint the
 * user whether it as typed correctly or not
 * 
 * @param   passphrase  The passphrase
 * @return              Zero on success, an appropriate exit value on error
 */
static int hash_passphrase(const char* passphrase)
{
#define SQUEEZES  PASSPHRASE_KECCAK_SQUEEZES
  libkeccak_spec_t spec;
  libkeccak_state_t state;
  char hashsum[PASSPHRASE_KECCAK_OUTPUT / 8];
  char hexsum[PASSPHRASE_KECCAK_OUTPUT / 4 + 1];
  size_t i, n;
  
  spec.bitrate = PASSPHRASE_KECCAK_RATE;
  spec.capacity = PASSPHRASE_KECCAK_CAPACITY;
  spec.output = PASSPHRASE_KECCAK_OUTPUT;
  
  if (libkeccak_spec_check(&spec) || (SQUEEZES <= 0))
    return USER_ERROR("bad passhprase hashing parameters, please recompile file2key with with "
		      "proper values on PASSPHRASE_KECCAK_RATE, PASSPHRASE_KECCAK_CAPACITY, "
		      "PASSPHRASE_KECCAK_OUTPUT and PASSPHRASE_KECCAK_SQUEEZES");
  
  if (libkeccak_state_initialise(&state, &spec))
    return perror(execname), 2;
  
  if (libkeccak_digest(&state, passphrase, strlen(passphrase), 0, NULL, SQUEEZES == 1 ? hashsum : NULL))
    return perror(execname), libkeccak_state_destroy(&state), 2;
  if (SQUEEZES > 2)  libkeccak_fast_squeeze(&state, SQUEEZES - 2);
  if (SQUEEZES > 1)  libkeccak_squeeze(&state, hashsum);
  
  libkeccak_state_destroy(&state);
  
  libkeccak_behex_lower(hexsum, hashsum, sizeof(hashsum) / sizeof(char));
  fprintf(stderr, "%s: passphrase hash: ", execname);
  for (i = 0, n = strlen(hexsum); i < n; i++)
    fprintf(stderr, "%s", COLOUR_HEX[(unsigned char)(hexsum[i])]);
  fprintf(stderr, "\033[00m\n");
  
  return 0;
#undef SQUEEZES
}


/**
 * Here we go!
 * 
 * @param   argc  The number of command line argumnets
 * @param   argv  Command line argumnets
 * @return        Zero on success, 1 on user error, 2 on system error
 */
int main(int argc, char** argv)
{
  libkeccak_generalised_spec_t gspec;
  libkeccak_spec_t spec;
  libkeccak_state_t state;
  char* passphrase = NULL;
  char* hash = NULL;
  size_t hash_size = 0;
  size_t hash_ptr = 0;
  char* data = NULL;
  size_t data_size = 0;
  size_t data_ptr = 0;
  size_t blksize = 4096;
  int r, fd = -1;
  struct stat attr;
  
  execname = *argv;
  
  if ((argc != 2) || (argv[1][0] == '-'))
    {
      fprintf(stderr, "USAGE: %s FILE\n", execname);
      return !!strcmp(argv[1], "--help");
    }
  
  libkeccak_generalised_spec_initialise(&gspec);
  libkeccak_degeneralise_spec(&gspec, &spec);
  t (libkeccak_state_initialise(&state, &spec));
  
  tt (get_passphrase(&passphrase));
  tt (hash_passphrase(passphrase));
  
  t (libkeccak_update(&state, passphrase, strlen(passphrase)));
  
  passphrase_wipe(passphrase, strlen(passphrase));
  free(passphrase), passphrase = NULL;
  
  t ((fd = open(argv[1], O_RDONLY), fd < 0));
  if (fstat(fd, &attr) == 0)
    if (attr.st_blksize > 0)
      blksize = (size_t)(attr.st_blksize);
  
  hash_size = (size_t)(spec.output / 8);
  t ((hash = malloc(hash_size), hash == NULL));
  t ((data = malloc(blksize),   data == NULL));
  
  t (libkeccak_digest(&state, STATIC_SALT, strlen(STATIC_SALT), 0, NULL, hash));
  
  for (;;)
    {
      size_t start;
      ssize_t n;
      
      if (hash_ptr == hash_size)
	libkeccak_squeeze(&state, hash), hash_ptr = 0;
      
      if (data_ptr == data_size)
	{
	  n = read(fd, data, blksize);
	  t (n < 0);
	  if (n == 0)
	    break;
	  data_size = (size_t)n;
	}
      
      start = data_ptr;
      while ((hash_ptr < hash_size) && (data_ptr < data_size))
	data[data_ptr++] ^= hash[hash_ptr++];
      
      while (start < data_ptr)
	{
	  n = write(STDOUT_FILENO, data + start, data_ptr - start);
	  t (n <= 0);
	  start += (size_t)n;
	}
    }
  
  r = 0;
  goto done;
  
 pfail:
  r = 2;
  perror(*argv);
 fail:
  if (passphrase)
    passphrase_wipe(passphrase, strlen(passphrase));
  free(passphrase);
 done:
  libkeccak_state_destroy(&state);
  free(data);
  free(hash);
  if (fd >= 0)
    close(fd);
  return r;
}

