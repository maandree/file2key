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


#define lane_t    int_fast64_t
#define ulane_t  uint_fast64_t



# pragma GCC diagnostic push
# pragma GCC diagnostic ignored "-Wsign-conversion"
/**
 * Round contants
 */
static const lane_t RC[] = {
  0x0000000000000001LL, 0x0000000000008082LL, 0x800000000000808ALL, 0x8000000080008000LL,
  0x000000000000808BLL, 0x0000000080000001LL, 0x8000000080008081LL, 0x8000000000008009LL,
  0x000000000000008ALL, 0x0000000000000088LL, 0x0000000080008009LL, 0x000000008000000ALL,
  0x000000008000808BLL, 0x800000000000008BLL, 0x8000000000008089LL, 0x8000000000008003LL,
  0x8000000000008002LL, 0x8000000000000080LL, 0x000000000000800ALL, 0x800000008000000ALL,
  0x8000000080008081LL, 0x8000000000008080LL, 0x0000000080000001LL, 0x8000000080008008LL};
# pragma GCC diagnostic pop

/**
 * Keccak-f round temporary
 */
static lane_t B[25];

/**
 * Keccak-f round temporary
 */
static lane_t C[5];

/**
 * The current state
 */
static lane_t* S = NULL;

/**
 * Left over water to fill the sponge with at next update
 */
static int8_t* M = NULL;

/**
 * Pointer for {@link #M}
 */
static long mptr = 0;

/**
 * Size of {@link #M}
 */
static long mlen = 0;

/**
 * Hash output buffer
 */
static int8_t* output = NULL;



/**
 * Copy an array segment into an array in start to end order
 * 
 * @param  src     The source array
 * @param  soff    The source array offset
 * @param  dest    The destination array
 * @param  doff    The destination array offset
 * @param  length  The number of elements to copy
 */
static inline void arraycopy(const int8_t* restrict src, long soff, int8_t* restrict dest, long doff, long length)
{
  long i;
  src += soff;
  dest += doff;
  
  #define __(X)  dest[X] = src[X]
  #define __0  *dest = *src
  #define __1  __(0x01)
  #define __2  __(0x02); __(0x03)
  #define __3  __(0x04); __(0x05); __(0x06); __(0x07)
  #define __4  __(0x08); __(0x09); __(0x0A); __(0x0B); __(0x0C); __(0x0D); __(0x0E); __(0x0F)
  #define __5  __(0x10); __(0x11); __(0x12); __(0x13); __(0x14); __(0x15); __(0x16); __(0x17); __(0x18); __(0x19); __(0x1A); __(0x1B); __(0x1C); __(0x1D); __(0x1E); __(0x1F)
  #define __6  __(0x20); __(0x21); __(0x22); __(0x23); __(0x24); __(0x25); __(0x26); __(0x27); __(0x28); __(0x29); __(0x2A); __(0x2B); __(0x2C); __(0x2D); __(0x2E); __(0x2F); \
               __(0x30); __(0x31); __(0x32); __(0x33); __(0x34); __(0x35); __(0x36); __(0x37); __(0x38); __(0x39); __(0x3A); __(0x3B); __(0x3C); __(0x3D); __(0x3E); __(0x3F)
  #define __7  __(0x40); __(0x41); __(0x42); __(0x43); __(0x44); __(0x45); __(0x46); __(0x47); __(0x48); __(0x49); __(0x4A); __(0x4B); __(0x4C); __(0x4D); __(0x4E); __(0x4F); \
               __(0x50); __(0x51); __(0x52); __(0x53); __(0x54); __(0x55); __(0x56); __(0x57); __(0x58); __(0x59); __(0x5A); __(0x5B); __(0x5C); __(0x5D); __(0x5E); __(0x5F); \
               __(0x60); __(0x61); __(0x62); __(0x63); __(0x64); __(0x65); __(0x66); __(0x67); __(0x68); __(0x69); __(0x6A); __(0x6B); __(0x6C); __(0x6D); __(0x6E); __(0x6F); \
               __(0x70); __(0x71); __(0x72); __(0x73); __(0x74); __(0x75); __(0x76); __(0x77); __(0x78); __(0x79); __(0x7A); __(0x7B); __(0x7C); __(0x7D); __(0x7E); __(0x7F)
  #define __8  __(0x80); __(0x81); __(0x82); __(0x83); __(0x84); __(0x85); __(0x86); __(0x87); __(0x88); __(0x89); __(0x8A); __(0x8B); __(0x8C); __(0x8D); __(0x8E); __(0x8F); \
               __(0x90); __(0x91); __(0x92); __(0x93); __(0x94); __(0x95); __(0x96); __(0x97); __(0x98); __(0x99); __(0x9A); __(0x9B); __(0x9C); __(0x9D); __(0x9E); __(0x9F); \
               __(0xA0); __(0xA1); __(0xA2); __(0xA3); __(0xA4); __(0xA5); __(0xA6); __(0xA7); __(0xA8); __(0xA9); __(0xAA); __(0xAB); __(0xAC); __(0xAD); __(0xAE); __(0xAF); \
               __(0xB0); __(0xB1); __(0xB2); __(0xB3); __(0xB4); __(0xB5); __(0xB6); __(0xB7); __(0xB8); __(0xB9); __(0xBA); __(0xBB); __(0xBC); __(0xBD); __(0xBE); __(0xBF); \
               __(0xC0); __(0xC1); __(0xC2); __(0xC3); __(0xC4); __(0xC5); __(0xC6); __(0xC7); __(0xC8); __(0xC9); __(0xCA); __(0xCB); __(0xCC); __(0xCD); __(0xCE); __(0xCF); \
               __(0xD0); __(0xD1); __(0xD2); __(0xD3); __(0xD4); __(0xD5); __(0xD6); __(0xD7); __(0xD8); __(0xD9); __(0xDA); __(0xDB); __(0xDC); __(0xDD); __(0xDE); __(0xDF); \
               __(0xE0); __(0xE1); __(0xE2); __(0xE3); __(0xE4); __(0xE5); __(0xE6); __(0xE7); __(0xE8); __(0xE9); __(0xEA); __(0xEB); __(0xEC); __(0xED); __(0xEE); __(0xEF); \
               __(0xF0); __(0xF1); __(0xF2); __(0xF3); __(0xF4); __(0xF5); __(0xF6); __(0xF7); __(0xF8); __(0xF9); __(0xFA); __(0xFB); __(0xFC); __(0xFD); __(0xFE); __(0xFF)
  
  if ((length & 15))
    {
      if ((length &   1))  {  __0;   src += 1;  dest += 1;  }
      if ((length &   2))  {  __0;  __1;   src += 2;  dest += 2;  }
      if ((length &   4))  {  __0;  __1;  __2;   src += 4;  dest += 4;  }
      if ((length &   8))  {  __0;  __1;  __2;  __3;   src += 8;  dest += 8;  }
    }
  if ((length & 240))
    {
      if ((length &  16))  {  __0;  __1;  __2;  __3;  __4;   src += 16;  dest += 16;  }
      if ((length &  32))  {  __0;  __1;  __2;  __3;  __4;  __5;   src += 32;  dest += 32;  }
      if ((length &  64))  {  __0;  __1;  __2;  __3;  __4;  __5;  __6;   src += 64;  dest += 64;  }
      if ((length & 128))  {  __0;  __1;  __2;  __3;  __4;  __5;  __6;  __7;   src += 128;  dest += 128;  }
    }
  length &= ~255;
  for (i = 0; i < length; i += 256)
    {
      __0;  __1;  __2;  __3;  __4;  __5;  __6;  __7;  __8;   src += 256;  dest += 256;
    }
  
  #undef __8
  #undef __7
  #undef __6
  #undef __5
  #undef __4
  #undef __3
  #undef __2
  #undef __1
  #undef __0
  #undef __
}


/**
 * Copy an array segment into an array in end to start order
 * 
 * @param  src     The source array
 * @param  soff    The source array offset
 * @param  dest    The destination array
 * @param  doff    The destination array offset
 * @param  length  The number of elements to copy
 */
static inline void revarraycopy(const int8_t* restrict src, long soff, int8_t* restrict dest, long doff, long length)
{
  long copyi;
  for (copyi = length - 1; copyi >= 0; copyi--)
    dest[copyi + doff] = src[copyi + soff];
}



/**
 * Rotate a 64-bit word
 * 
 * @param   X:lane_t  The value to rotate
 * @param   N:long    Rotation steps, may not be 0
 * @return   :lane_t  The value rotated
 */
#define rotate(X, N)  ((lane_t)((ulane_t)(X) >> (64 - (N))) + ((X) << (N)))


/**
 * Perform one round of computation
 * 
 * @param  A   The current state
 * @param  rc  Round constant
 */
static void keccakFRound(lane_t* restrict A, lane_t rc)
{
  lane_t da, db, dc, dd, de;
  
  /* θ step (step 1 and 2 of 3) */
  #define __C(I, J0, J1, J2, J3, J4)  C[I] = (A[J0] ^ A[J1]) ^ (A[J2] ^ A[J3]) ^ A[J4]
  __C(0,   0,  1,  2,  3,  4);
  __C(1,   5,  6,  7,  8,  9);
  __C(2,  10, 11, 12, 13, 14);
  __C(3,  15, 16, 17, 18, 19);
  __C(4,  20, 21, 22, 23, 24);
  #undef __C
  
  da = C[4] ^ rotate(C[1], 1);
  dd = C[2] ^ rotate(C[4], 1);
  db = C[0] ^ rotate(C[2], 1);
  de = C[3] ^ rotate(C[0], 1);
  dc = C[1] ^ rotate(C[3], 1);
  
  /* ρ and π steps, with last two part of θ */
  #define __B(Bi, Ai, Dv, R)  B[Bi] = rotate(A[Ai] ^ Dv, R)
  B[0] = A[0] ^ da;     __B( 1, 15, dd, 28);  __B( 2,  5, db,  1);  __B( 3, 20, de, 27);  __B( 4, 10, dc, 62);
  __B( 5,  6, db, 44);  __B( 6, 21, de, 20);  __B( 7, 11, dc,  6);  __B( 8,  1, da, 36);  __B( 9, 16, dd, 55);
  __B(10, 12, dc, 43);  __B(11,  2, da,  3);  __B(12, 17, dd, 25);  __B(13,  7, db, 10);  __B(14, 22, de, 39);
  __B(15, 18, dd, 21);  __B(16,  8, db, 45);  __B(17, 23, de,  8);  __B(18, 13, dc, 15);  __B(19,  3, da, 41);
  __B(20, 24, de, 14);  __B(21, 14, dc, 61);  __B(22,  4, da, 18);  __B(23, 19, dd, 56);  __B(24,  9, db,  2);
  #undef __B
  
  /* ξ step */
  #define __A(X, X5, X10)  A[X] = B[X] ^ ((~(B[X5])) & B[X10])
  __A( 0,  5, 10);  __A( 1,  6, 11);  __A( 2,  7, 12);  __A( 3,  8, 13);  __A( 4,  9, 14);
  __A( 5, 10, 15);  __A( 6, 11, 16);  __A( 7, 12, 17);  __A( 8, 13, 18);  __A( 9, 14, 19);
  __A(10, 15, 20);  __A(11, 16, 21);  __A(12, 17, 22);  __A(13, 18, 23);  __A(14, 19, 24);
  __A(15, 20,  0);  __A(16, 21,  1);  __A(17, 22,  2);  __A(18, 23,  3);  __A(19, 24,  4);
  __A(20,  0,  5);  __A(21,  1,  6);  __A(22,  2,  7);  __A(23,  3,  8);  __A(24,  4,  9);
  #undef __A
  
  /* ι step */
  A[0] ^= rc;
}


/**
 * Perform Keccak-f function
 * 
 * @param  A  The current state
 */
static void keccakF(lane_t* restrict A)
{
# pragma GCC diagnostic push
# pragma GCC diagnostic ignored "-Wsign-conversion"
  keccakFRound(A, 0x0000000000000001LL);
  keccakFRound(A, 0x0000000000008082LL);
  keccakFRound(A, 0x800000000000808ALL);
  keccakFRound(A, 0x8000000080008000LL);
  keccakFRound(A, 0x000000000000808BLL);
  keccakFRound(A, 0x0000000080000001LL);
  keccakFRound(A, 0x8000000080008081LL);
  keccakFRound(A, 0x8000000000008009LL);
  keccakFRound(A, 0x000000000000008ALL);
  keccakFRound(A, 0x0000000000000088LL);
  keccakFRound(A, 0x0000000080008009LL);
  keccakFRound(A, 0x000000008000000ALL);
  keccakFRound(A, 0x000000008000808BLL);
  keccakFRound(A, 0x800000000000008BLL);
  keccakFRound(A, 0x8000000000008089LL);
  keccakFRound(A, 0x8000000000008003LL);
  keccakFRound(A, 0x8000000000008002LL);
  keccakFRound(A, 0x8000000000000080LL);
  keccakFRound(A, 0x000000000000800ALL);
  keccakFRound(A, 0x800000008000000ALL);
  keccakFRound(A, 0x8000000080008081LL);
  keccakFRound(A, 0x8000000000008080LL);
  keccakFRound(A, 0x0000000080000001LL);
  keccakFRound(A, 0x8000000080008008LL);
# pragma GCC diagnostic pop
}


/**
 * Convert a chunk of byte:s to a 64-bit word
 * 
 * @param   message  The message
 * @param   msglen   The length of the message
 * @param   off      The offset in the message
 * @return           Lane
 */
static inline lane_t toLane(const int8_t* restrict message, long msglen, long off)
{
  long n = msglen < 128 ? msglen : 128;
  return ((off + 7 < n) ? ((lane_t)(message[off + 7] & 255) << 56) : 0L) |
         ((off + 6 < n) ? ((lane_t)(message[off + 6] & 255) << 48) : 0L) |
         ((off + 5 < n) ? ((lane_t)(message[off + 5] & 255) << 40) : 0L) |
         ((off + 4 < n) ? ((lane_t)(message[off + 4] & 255) << 32) : 0L) |
         ((off + 3 < n) ? ((lane_t)(message[off + 3] & 255) << 24) : 0L) |
         ((off + 2 < n) ? ((lane_t)(message[off + 2] & 255) << 16) : 0L) |
         ((off + 1 < n) ? ((lane_t)(message[off + 1] & 255) <<  8) : 0L) |
         ((off     < n) ? ((lane_t)(message[off    ] & 255)      ) : 0L);
}


/**
 * pad 10*1
 * 
 * @param   msg     The message to pad
 * @param   len     The length of the message
 * @param   outlen  The length of the padded message (out parameter)
 * @return          The message padded
 */
static inline int8_t* pad10star1(const int8_t* restrict msg, long len, long* restrict outlen)
{
  int8_t* message;
  
  long nrf = (len <<= 3) >> 3;
  long nbrf = len & 7;
  long ll = len & 1023;
  long i;
  
  int8_t b = (int8_t)(nbrf == 0 ? 1 : ((msg[nrf] >> (8 - nbrf)) | (1 << nbrf)));
  
  if ((1016 <= ll) && (ll <= 1022))
    {
      message = malloc((size_t)(len = nrf + 1) * sizeof(int8_t));
      message[nrf] = (int8_t)(b ^ 128);
    }
  else
    {
      int8_t* m;
      long n;
      len = (nrf + 1) << 3;
      len = ((len - (len & 1023) + 1016) >> 3) + 1;
      message = malloc((size_t)len * sizeof(int8_t));
      message[nrf] = b;
      n = len - nrf - 1;
      m = message + nrf + 1;
      
      #define __(X)  m[X] = 0
      #define __0  *m = 0
      #define __1  __(0x01)
      #define __2  __(0x02); __(0x03)
      #define __3  __(0x04); __(0x05); __(0x06); __(0x07)
      #define __4  __(0x08); __(0x09); __(0x0A); __(0x0B); __(0x0C); __(0x0D); __(0x0E); __(0x0F)
      #define __5  __(0x10); __(0x11); __(0x12); __(0x13); __(0x14); __(0x15); __(0x16); __(0x17); __(0x18); __(0x19); __(0x1A); __(0x1B); __(0x1C); __(0x1D); __(0x1E); __(0x1F)
      #define __6  __(0x20); __(0x21); __(0x22); __(0x23); __(0x24); __(0x25); __(0x26); __(0x27); __(0x28); __(0x29); __(0x2A); __(0x2B); __(0x2C); __(0x2D); __(0x2E); __(0x2F); \
                   __(0x30); __(0x31); __(0x32); __(0x33); __(0x34); __(0x35); __(0x36); __(0x37); __(0x38); __(0x39); __(0x3A); __(0x3B); __(0x3C); __(0x3D); __(0x3E); __(0x3F)
      #define __7  __(0x40); __(0x41); __(0x42); __(0x43); __(0x44); __(0x45); __(0x46); __(0x47); __(0x48); __(0x49); __(0x4A); __(0x4B); __(0x4C); __(0x4D); __(0x4E); __(0x4F); \
                   __(0x50); __(0x51); __(0x52); __(0x53); __(0x54); __(0x55); __(0x56); __(0x57); __(0x58); __(0x59); __(0x5A); __(0x5B); __(0x5C); __(0x5D); __(0x5E); __(0x5F); \
                   __(0x60); __(0x61); __(0x62); __(0x63); __(0x64); __(0x65); __(0x66); __(0x67); __(0x68); __(0x69); __(0x6A); __(0x6B); __(0x6C); __(0x6D); __(0x6E); __(0x6F); \
                   __(0x70); __(0x71); __(0x72); __(0x73); __(0x74); __(0x75); __(0x76); __(0x77); __(0x78); __(0x79); __(0x7A); __(0x7B); __(0x7C); __(0x7D); __(0x7E); __(0x7F)
      #define __8  __(0x80); __(0x81); __(0x82); __(0x83); __(0x84); __(0x85); __(0x86); __(0x87); __(0x88); __(0x89); __(0x8A); __(0x8B); __(0x8C); __(0x8D); __(0x8E); __(0x8F); \
                   __(0x90); __(0x91); __(0x92); __(0x93); __(0x94); __(0x95); __(0x96); __(0x97); __(0x98); __(0x99); __(0x9A); __(0x9B); __(0x9C); __(0x9D); __(0x9E); __(0x9F); \
                   __(0xA0); __(0xA1); __(0xA2); __(0xA3); __(0xA4); __(0xA5); __(0xA6); __(0xA7); __(0xA8); __(0xA9); __(0xAA); __(0xAB); __(0xAC); __(0xAD); __(0xAE); __(0xAF); \
                   __(0xB0); __(0xB1); __(0xB2); __(0xB3); __(0xB4); __(0xB5); __(0xB6); __(0xB7); __(0xB8); __(0xB9); __(0xBA); __(0xBB); __(0xBC); __(0xBD); __(0xBE); __(0xBF); \
                   __(0xC0); __(0xC1); __(0xC2); __(0xC3); __(0xC4); __(0xC5); __(0xC6); __(0xC7); __(0xC8); __(0xC9); __(0xCA); __(0xCB); __(0xCC); __(0xCD); __(0xCE); __(0xCF); \
                   __(0xD0); __(0xD1); __(0xD2); __(0xD3); __(0xD4); __(0xD5); __(0xD6); __(0xD7); __(0xD8); __(0xD9); __(0xDA); __(0xDB); __(0xDC); __(0xDD); __(0xDE); __(0xDF); \
                   __(0xE0); __(0xE1); __(0xE2); __(0xE3); __(0xE4); __(0xE5); __(0xE6); __(0xE7); __(0xE8); __(0xE9); __(0xEA); __(0xEB); __(0xEC); __(0xED); __(0xEE); __(0xEF); \
                   __(0xF0); __(0xF1); __(0xF2); __(0xF3); __(0xF4); __(0xF5); __(0xF6); __(0xF7); __(0xF8); __(0xF9); __(0xFA); __(0xFB); __(0xFC); __(0xFD); __(0xFE); __(0xFF)
      
      if ((n & 15))
	{
	  if ((n &   1))  {  __0;   m += 1;  }
	  if ((n &   2))  {  __0;  __1;   m += 2;  }
	  if ((n &   4))  {  __0;  __1;  __2;   m += 4;  }
	  if ((n &   8))  {  __0;  __1;  __2;  __3;   m += 8;  }
	}
      if ((n & 240))
	{
	  if ((n &  16))  {  __0;  __1;  __2;  __3;  __4;   m += 16;  }
	  if ((n &  32))  {  __0;  __1;  __2;  __3;  __4;  __5;   m += 32;  }
	  if ((n &  64))  {  __0;  __1;  __2;  __3;  __4;  __5;  __6;   m += 64;  }
	  if ((n & 128))  {  __0;  __1;  __2;  __3;  __4;  __5;  __6;  __7;   m += 128;  }
	}
      n &= ~255;
      for (i = 0; i < n; i += 256)
	{
	  __0;  __1;  __2;  __3;  __4;  __5;  __6;  __7;  __8;   m += 256;
	}
      
      #undef __8
      #undef __7
      #undef __6
      #undef __5
      #undef __4
      #undef __3
      #undef __2
      #undef __1
      #undef __0
      #undef __
      
      message[len - 1] = -128;
    }
  arraycopy(msg, 0, message, 0, nrf);
  
  *outlen = len;
  return message;
}


/**
 * Initialise Keccak[r=1024, c=576, n=576] sponge
 */
void initialise(void)
{
  long i;
  
  output = malloc(72 * sizeof(int8_t));
  S = malloc(25 * sizeof(lane_t));
  M = malloc((size_t)(mlen = 409600) * sizeof(int8_t));
  mptr = 0;
  
  for (i = 0; i < 25; i++)
    *(S + i) = 0;
}

/**
 * Dispose of the Keccak sponge
 */
void dispose(void)
{
  free(output);
  free(S);
  free(M);
}

/**
 * Absorb the more of the message message to the Keccak sponge
 * 
 * @param  msg     The partial message
 * @param  msglen  The length of the partial message
 */
void update(const int8_t* restrict msg, long msglen)
{
  long i, len, nnn;
  int8_t* message;
  int8_t* _msg;
  
  if (mptr + msglen > mlen)
    {
      int8_t* buf = malloc((size_t)(mlen = (mlen + msglen) << 1) * sizeof(int8_t));
      arraycopy(M, 0, buf, 0, mptr);
      free(M);
      M = buf;
    }
  arraycopy(msg, 0, M, mptr, msglen);
  len = mptr += msglen;
  len -= len % 204800;
  _msg = message = malloc((size_t)len * sizeof(int8_t));
  arraycopy(M, 0, message, 0, len);
  mptr -= len;
  revarraycopy(M, nnn = len, M, 0, mptr);
  
  /* Absorbing phase */
  for (i = 0; i < nnn; i += 128)
    {
      #define __S(Si, OFF)  S[Si] ^= toLane(message, len, OFF)
      __S( 0,   0);  __S( 5,   8);  __S(10,  16);  __S(15,  24);  __S(20,  32);
      __S( 1,  40);  __S( 6,  48);  __S(11,  56);  __S(16,  64);  __S(21,  72);
      __S( 2,  80);  __S( 7,  88);  __S(12,  96);  __S(17, 104);  __S(22, 112);
      __S( 3, 120);  __S( 8, 128);  __S(13, 136);  __S(18, 144);  __S(23, 152);
      __S( 4, 160);  __S( 9, 168);  __S(14, 176);  __S(19, 184);  __S(24, 192);
      #undef __S
      keccakF(S);
      message += 128;
      len -= 128;
    }
  
  free(_msg);
}


/**
 * Absorb the last part of the message and squeeze the Keccak sponge
 * 
 * @param   msg     The rest of the message, may be {@code NULL}
 * @param   msglen  The length of the partial message
 * @return          The hash sum
 */
int8_t* digest(const int8_t* restrict msg, long msglen)
{
  int8_t* message;
  int8_t* rc;
  int8_t* _msg;
  long len, i, j, ptr = 0, nnn;
  
  if ((msg == NULL) || (msglen == 0))
    message = pad10star1(M, mptr, &len);
  else
    {
      if (mptr + msglen > mlen)
	{
	  int8_t* buf = malloc((size_t)(mlen += msglen) * sizeof(int8_t));
	  arraycopy(M, 0, buf, 0, mptr);
	  free(M);
	  M = buf;
	}
      arraycopy(msg, 0, M, mptr, msglen);
      message = pad10star1(M, mptr + msglen, &len);
    }
  free(M);
  M = NULL;
  nnn = len;
  _msg = message;
  
  /* Absorbing phase */
  for (i = 0; i < nnn; i += 128)
    {
      #define __S(Si, OFF)  S[Si] ^= toLane(message, len, OFF)
      __S( 0,   0);  __S( 5,   8);  __S(10,  16);  __S(15,  24);  __S(20,  32);
      __S( 1,  40);  __S( 6,  48);  __S(11,  56);  __S(16,  64);  __S(21,  72);
      __S( 2,  80);  __S( 7,  88);  __S(12,  96);  __S(17, 104);  __S(22, 112);
      __S( 3, 120);  __S( 8, 128);  __S(13, 136);  __S(18, 144);  __S(23, 152);
      __S( 4, 160);  __S( 9, 168);  __S(14, 176);  __S(19, 184);  __S(24, 192);
      #undef __S
      keccakF(S);
      message += 128;
      len -= 128;
    }
  
  free(_msg);
  
  /* Squeezing phase */
  for (i = 0; i < 9; i++)
    {
      lane_t v = S[(i % 5) * 5 + i / 5];
      for (j = 0; j < 8; j++)
	{
	  output[ptr++] = (int8_t)v;
	  v >>= 8;
	}
    }
  
  return output;
}


/**
 * Squeeze out another digest
 * 
 * @return  The hash sum
 */
int8_t* squeeze(void)
{
  long i, j, ptr;
  
  keccakF(S); /* Last squeeze did not do a ending squeeze */
  
  ptr = 0;
  
  for (i = 0; i < 9; i++)
    {
      lane_t v = S[(i % 5) * 5 + i / 5];
      for (j = 0; j < 8; j++)
	{
          *(output + ptr++) = (int8_t)v;
	  v >>= 8;
	}
    }
  
  return output;
}

