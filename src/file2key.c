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
#include "keccak.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#include <passphrase.h>


/**
 * Random string created with `dd if=/dev/random bs=1024 count=1 | tr -d -c a-zA-Z0-9`
 * 
 * DO NOT EDIT!
 */
#define STATIC_SALT  "5EbppWrYxMuBKQmbDz8rOCVCONsSLas74qrjMLTiJqsYWcTePNeshVXcmAWGkh88VeFh"



const char* const COLOUR_HEX[] =
  {
    "\033[31m0",
    "\033[31m1",
    "\033[31m2",
    "\033[31m3",
    "\033[31m4",
    "\033[32m5",
    "\033[32m6",
    "\033[32m7",
    "\033[32m8",
    "\033[32m9",
    "\033[34ma",
    "\033[34mb",
    "\033[34mc",
    "\033[34md",
    "\033[34me",
    "\033[34mf",
  };



int main(int argc, char** argv)
{
  int is_echo_disabled = 0;
  int is_hash_initialised = 0;
  
  FILE* file = NULL;
  char* passphrase = NULL;
  size_t passphrase_n;
  char* hash;
  char* data = NULL;
  size_t ptr;
  size_t blksize;
  size_t got;
  struct stat attr;
  
  if ((argc != 2) || (argv[1][0] == '-'))
    {
      printf("USAGE: %s FILE\n", *argv);
      return 0;
    }
  
  if (stat(argv[1], &attr) < 0)
    goto pfail;
  if (S_ISREG(attr.st_mode) == 0)
    {
      fprintf(stderr, "%s: input file is not a regular file\n", *argv);
      goto fail;
    }
  if (attr.st_size < 100 << 10)
    fprintf(stderr, "%s: warning: input file is small (less than 100 KB)\n", *argv);
  
  file = fopen(argv[1], "r");
  if (file == NULL)
    goto pfail;
  data = malloc((size_t)(attr.st_size) * sizeof(char));
  if (data == NULL)
    goto pfail;
  
  blksize = attr.st_blksize ? (size_t)(attr.st_blksize) : (size_t)(8 << 10);
  
  for (ptr = 0; ptr < (size_t)(attr.st_size); ptr += got)
    {
      got = fread(data + ptr, 1, blksize, file);
      if (got < blksize)
	{
	  if (ferror(file))
	    goto pfail;
	  break;
	}
    }
  
  fclose(file), file = NULL;
  
  passphrase_disable_echo(), is_echo_disabled = 1;
  fprintf(stderr, "[%s] Enter passphrase: ", *argv);
  fflush(stderr);
  passphrase = passphrase_read();
  if (passphrase == NULL)
    goto pfail;
  passphrase_n = strlen(passphrase);
  passphrase_reenable_echo(), is_echo_disabled = 0;
  
  initialise(), is_hash_initialised = 1;
  
  update(passphrase, passphrase_n);
  passphrase_wipe(passphrase, passphrase_n);
  free(passphrase), passphrase = NULL;
  
  for (ptr = 0; ptr < (size_t)(attr.st_size); ptr += 72)
    {
      size_t i, n = (size_t)(attr.st_size) - ptr;
      if (n > 72)
	n = 72;
      
      if (ptr == 0)
	{
	  char* phash = malloc((20 * 6) + 1 * sizeof(char));
	  if (phash == NULL)
	    goto pfail;
	  hash = digest(STATIC_SALT, strlen(STATIC_SALT));
	  
	  for (i = 0; i < 10; i++)
	    {
	      memcpy(phash + (i * 2 + 0) * 6, COLOUR_HEX[((unsigned char)(hash[i]) >> 4) & 15], 6 * sizeof(char));
	      memcpy(phash + (i * 2 + 1) * 6, COLOUR_HEX[((unsigned char)(hash[i]) >> 0) & 15], 6 * sizeof(char));
	    }
	  phash[20 * 6] = '\0';
	  
	  fprintf(stderr, "%s: passphrase hash: %s\033[00m\n", *argv, phash);
	  free(phash);
	}
      else
	hash = squeeze();
      
      for (i = 0; i < n; i++)
	*(hash + i) ^= *(data + ptr + i);
      
      if (fwrite(hash, 1, n, stdout) < n)
	goto pfail;
    }
  
  free(data), data = NULL;
  dispose(), is_hash_initialised = 0;
  return 0;
  
 pfail:
  perror(*argv);
 fail:
  if (file)
    fclose(file);
  if (data)
    free(data);
  if (is_echo_disabled)
    passphrase_reenable_echo();
  if (passphrase)
    {
      passphrase_wipe(passphrase, passphrase_n);
      free(passphrase);
    }
  if (is_hash_initialised)
    dispose();
  return 1;
}

