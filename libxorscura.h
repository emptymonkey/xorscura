
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


#define PRNG_STATELEN 256

// Uncomment to enable verbose error messages.
//#define DEBUG

// xorscura object data
struct xod {
	
	size_t buf_count;	
	unsigned char *plaintext_buf;
	unsigned char *key_buf;
	unsigned char *ciphertext_buf;

	unsigned int seed;

};

int xorscura_encrypt(struct xod *data);
int xorscura_decrypt(struct xod *data);

// xorscura_compare() performs a bitwise check, ensuring the encrypted string doesn't end up decrypted in memory.
// Returns 0 on match, 1 on difference, and -1 on error.
int xorscura_compare(struct xod *data);

// decrypt or compare using the seed for random() instead of a flat key.
// Calling the above functions check for this case and do the right thing. 
// No need (generally) to call these yourself.
int xorscura_decrypt_prng(struct xod *data);
int xorscura_compare_prng(struct xod *data);

void xorscura_free_xod(struct xod *data);

