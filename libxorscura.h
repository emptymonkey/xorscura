
#define _GNU_SOURCE

#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/types.h>

/*
	 From initstate() manpage:
	 Current "optimal" values for the size of the state array n are 8, 32, 64, 128, and 256 bytes;
	 other amounts will be rounded down to  the  nearest  known  amount. Using less than 8 bytes will cause an error.
 */
#define PRNG_STATELEN 256

// Uncomment to enable verbose error messages.
//#define DEBUG

// Bitwise flags for use in the xod alloc_flag value.
#define ALLOC_PLAINTEXT	1
#define ALLOC_CIPHERTEXT	2
#define ALLOC_KEY	4

// xorscura object data
struct xod {

	size_t buf_count;	
	unsigned char *plaintext_buf;
	unsigned char *key_buf;
	unsigned char *ciphertext_buf;

	unsigned int seed;

	// Used to track what has been malloc()d by libxorscura. If you malloc() it on your own,
	// it's up to you to manage it.
	// Or flip this flag, then we'll free() the memory in xorscura_free_xod().
	unsigned char alloc_flag;

};

int xorscura_encrypt(struct xod *data);
int xorscura_decrypt(struct xod *data);

// xorscura_compare() performs a bitwise check, ensuring the encrypted string doesn't end up decrypted in memory.
// Returns 0 on match, 1 on difference, and -1 on error. (Attempt to mimic match value behavior of strcmp().)
int xorscura_compare(struct xod *data);

// decrypt or compare using the seed for random() instead of a flat key.
// Calling the xorscura_decrypt() and xorscura_compare() functions will check for this case on their own 
// and do the right thing. No need (generally) to call these yourself.
int xorscura_decrypt_prng(struct xod *data);
int xorscura_compare_prng(struct xod *data);

// Clears out the xod data structure. Does not free the struct itself.
void xorscura_free_xod(struct xod *data);

// Prints values of the xod data structure.
void xorscura_debug_xod(struct xod *data);

