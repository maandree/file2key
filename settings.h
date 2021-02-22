/* See LICENSE file for copyright and license details. */

/**
 * Random string created with `dd if=/dev/random bs=1024 count=1 | tr -d -c a-zA-Z0-9`
 */
#define KEY_PEPPER "5EbppWrYxMuBKQmbDz8rOCVCONsSLas74qrjMLTiJqsYWcTePNeshVXcmAWGkh88VeFh"

/**
 * The rate parameter for the Keccak sponge when hashing master passphrase
 */
#ifndef PASSPHRASE_KECCAK_RATE
# define PASSPHRASE_KECCAK_RATE 576
#endif

/**
 * The capacity parameter for the Keccak sponge when hashing master passphrase
 */
#ifndef PASSPHRASE_KECCAK_CAPACITY
# define PASSPHRASE_KECCAK_CAPACITY 1024
#endif

/**
 * The output parameter for the Keccak sponge when hashing master passphrase
 */
#ifndef PASSPHRASE_KECCAK_OUTPUT
# define PASSPHRASE_KECCAK_OUTPUT 32
#endif

/**
 * The number of times to squeeze the master passphrase
 */
#ifndef PASSPHRASE_KECCAK_SQUEEZES
# define PASSPHRASE_KECCAK_SQUEEZES 10000
#endif
