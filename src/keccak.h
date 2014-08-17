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
#include <stdlib.h>
#include <inttypes.h>



/**
 * Initialise Keccak sponge
 */
void initialise(void);


/**
 * Dispose of the Keccak sponge
 */
void dispose(void);


/**
 * Absorb the more of the message message to the Keccak sponge
 * 
 * @param  msg     The partial message
 * @param  msglen  The length of the partial message
 */
void update(const int8_t* restrict msg, long msglen);


/**
 * Absorb the last part of the message and squeeze the Keccak sponge
 * 
 * @param   msg     The rest of the message, may be {@code null}
 * @param   msglen  The length of the partial message
 * @return          The hash sum
 */
int8_t* digest(const int8_t* restrict msg, long msglen);


/**
 * Squeeze out another digest
 * 
 * @return  The hash sum
 */
int8_t* squeeze(void);

