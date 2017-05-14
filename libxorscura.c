
/**********************************************************************************************************************
 *
 * libxorscura
 *
 *	@emptymonkey
 *	2017-04-17
 *
 *	A library to simplify string obfuscation with xor.
 *
 *	Note: libobscura will malloc() it's own data for responses. It will then free() these automatically when the 
 *	xorscura_free_xod() function is called.
 *
 **********************************************************************************************************************/

#include "libxorscura.h"



/**********************************************************************************************************************
 *
 * xorscura_encrypt()
 *
 *	Input: A pointer to the xod data structure.
 *		xod->plaintext_buf should have a pointer to the data to encrypt.
 *		xod->buf_count should contain the number of bytes in xod->plaintext_buf.
 *
 *	Output: 0 on success, -1 on error.
 *		xod->ciphertext_buf will have a pointer to the ciphertext data.
 *		xod->key will have a pointer to the key data.
 *		xod->seed will have the prng seed to generate the key.
 *
 *	Purpose: Encrypt the data pointed to in the plaintext_buf buffer.
 *
 **********************************************************************************************************************/
int xorscura_encrypt(struct xod *data){

	char *seed_ptr = (char *) &(data->seed);
	size_t seed_count;

	size_t key_count;

	int retval;
	int tmp_fd;

	int i;

	char prng_state[PRNG_STATELEN];
	struct random_data *prng_buf;
	int32_t prng_result;
	char *prng_result_ptr = (char *) &prng_result;


	if(!data){
#ifdef DEBUG
		fprintf(stderr, "xorscura_encrypt(): No data!\n");
#endif
		return(-1);
	}

	// Initialize prng seed straight from urandom.
	if((tmp_fd = open("/dev/urandom", O_RDONLY)) == -1){
#ifdef DEBUG
		fprintf(stderr, "xorscura_encrypt(): open(\"/dev/urandom\")\n");
#endif
		return(-1);
	}

	seed_count = 0;
	while((retval = read(tmp_fd, seed_ptr + seed_count, (int) (sizeof(unsigned int) - seed_count))) != (int) (sizeof(data->seed) - seed_count)){
		if(retval == -1){
#ifdef DEBUG
			fprintf(stderr, "xorscura_encrypt(): read(%d, 0x%lx, %d)\n", tmp_fd, (unsigned long) (seed_ptr + seed_count), (int) (sizeof(data->seed) - seed_count));
#endif
		return(-1);
		}
		seed_count += retval;
	}
	seed_count += retval;
	close(tmp_fd);

	// Initialize the buffers we plan to fill.
	if((data->ciphertext_buf = (unsigned char *) calloc(data->buf_count, sizeof(char))) == NULL){
#ifdef DEBUG
		fprintf(stderr, "xorscura_encrypt(): calloc(%d, %d)\n", (int) data->buf_count, (int)sizeof(char));
#endif
		return(-1);
	}
	data->alloc_flag |= ALLOC_CIPHERTEXT;

  if((data->key_buf = (unsigned char *) calloc(data->buf_count, sizeof(char))) == NULL){
#ifdef DEBUG
		fprintf(stderr, "xorscura_encrypt(): calloc(%d, %d)\n", (int) data->buf_count, (int) sizeof(char));
#endif
    return(-1);
  }
	data->alloc_flag |= ALLOC_KEY;

	// Initialize the prng.
	if((prng_buf = (struct random_data *) calloc(1, sizeof(struct random_data))) == NULL){
#ifdef DEBUG
		fprintf(stderr, "xorscura_encrypt(): calloc(1, %d)\n", (int) sizeof(struct random_data));
#endif
    return(-1);
	}

	memset(prng_state, '\0', PRNG_STATELEN);
	if(initstate_r(data->seed, prng_state, PRNG_STATELEN, prng_buf) == -1){
#ifdef DEBUG
		fprintf(stderr, "xorscura_encrypt(): initstate_r(0x%x, %lx, %d, %lx)\n", data->seed, (unsigned long) prng_state, PRNG_STATELEN, (unsigned long) prng_buf);
#endif
    return(-1);
	}

	// Generate the next random char, add it to key, and create the cipher.
	key_count = 0;
	while(key_count < data->buf_count){
		if(random_r(prng_buf, &prng_result) == -1){
#ifdef DEBUG
			fprintf(stderr, "xorscura_encrypt(): random_r(%lx, %lx)\n", (unsigned long) prng_buf, (unsigned long) &prng_result);
#endif
			return(-1);
		}

		for(i = 0; i < (int) sizeof(int32_t); i++){
			data->key_buf[key_count] = prng_result_ptr[i];
			data->ciphertext_buf[key_count] = data->plaintext_buf[key_count] ^ data->key_buf[key_count];
			key_count++;
			
			if(key_count == data->buf_count){
				break;
			}
		}
	}

	free(prng_buf);

	return(0);
}



/**********************************************************************************************************************
 *
 * xorscura_decrypt()
 *
 *	Input: A pointer to the xod data structure.
 *		xod->ciphertext_buf should have a pointer to the ciphertext data.
 *		xod->buf_count should contain the number of bytes in xod->ciphertext_buf.
 *		xod->key should have a pointer to the key data *OR*
 *		xod->seed should have the prng seed needed to generate the key.
 *
 *	Output: 0 on success, -1 on error.
 *		xod->plaintext_buf will have a pointer to the unencrypted data.
 *
 *	Purpose: Decrypt the data pointed to in the ciphertext_buf buffer.
 *
 **********************************************************************************************************************/
int xorscura_decrypt(struct xod *data){

	int i;


	if(!(data->seed || data->key_buf)){
#ifdef DEBUG
		fprintf(stderr, "xorscura_decrypt(): No key or seed provided.\n");
#endif
		return(-1);
	}

	// Check if we have the prng case, or straight xor of arrays.
	if(data->seed){
		return(xorscura_decrypt_prng(data));
	}

	// Making the plaintext buf one char bigger because the common case will be a string. This allows for implicit null termination.
	// As a result, most of the string functions should work fine against the resulting plaintext.
	if((data->plaintext_buf = (unsigned char *) calloc(data->buf_count + 1, sizeof(char))) == NULL){
#ifdef DEBUG
		fprintf(stderr, "xorscura_decrypt(): calloc(%d, %d)\n", (int) data->buf_count + 1, (int) sizeof(char));
#endif
		return(-1);
	}
	data->alloc_flag |= ALLOC_PLAINTEXT;

	// Decrypt.
	for(i = 0; i < (int) data->buf_count; i++){
		data->plaintext_buf[i] = data->ciphertext_buf[i] ^ data->key_buf[i];
	}

	return(0);
}



/**********************************************************************************************************************
 *
 * xorscura_decrypt_prng()
 *
 *	Input: A pointer to the xod data structure.
 *		xod->ciphertext_buf should have a pointer to the ciphertext data.
 *		xod->buf_count should contain the number of bytes in xod->ciphertext_buf.
 *		xod->seed should have the prng seed needed to generate the key.
 *
 *	Output: 0 on success, -1 on error.
 *		xod->plaintext_buf will have a pointer to the unencrypted data.
 *
 *	Purpose: Decrypt the data pointed to in the ciphertext_buf buffer.
 *
 *	Note: This function is called inside of xorscura_decrypt_prng() after a seed check. There shouldn't be any reason
 *	to call this directly, unless you know what you're doing.
 *
 **********************************************************************************************************************/
int xorscura_decrypt_prng(struct xod *data){

	int i;

	size_t key_count;

	char prng_state[PRNG_STATELEN];
	struct random_data *prng_buf;
	int32_t prng_result;
	char *prng_result_ptr = (char *) &prng_result;


	// Initialize plaintext buffer. Again, +1 to cover the general case of it being a string, allowing for string
	// functions to be called directly on the buf by the caller.	
	if((data->plaintext_buf = (unsigned char *) calloc(data->buf_count + 1, sizeof(char))) == NULL){
#ifdef DEBUG
		fprintf(stderr, "xorscura_decrypt_prng(): calloc(%d, %d)\n", (int) data->buf_count + 1, sizeof(char));
#endif
		return(-1);
	}
	data->alloc_flag |= ALLOC_PLAINTEXT;

	// Initialize the prng.
	if((prng_buf = (struct random_data *) calloc(1, sizeof(struct random_data))) == NULL){
#ifdef DEBUG
		fprintf(stderr, "xorscura_decrypt_prng(): calloc(1, %d)\n", (int) sizeof(struct random_data));
#endif
		return(-1);
	}

	memset(prng_state, '\0', PRNG_STATELEN);
	if(initstate_r(data->seed, prng_state, PRNG_STATELEN, prng_buf) == -1){
#ifdef DEBUG
		fprintf(stderr, "xorscura_decrypt_prng(): initstate_r(0x%x, %lx, %d, %lx)\n", data->seed, (unsigned long) prng_state, PRNG_STATELEN, (unsigned long) prng_buf);
#endif
		return(-1);
	}

	// Grab a key character, decrypt the char of ciphertext, and store it in the plaintext.
	key_count = 0;
	while(key_count < data->buf_count){
		if(random_r(prng_buf, &prng_result) == -1){
#ifdef DEBUG
			fprintf(stderr, "xorscura_decrypt_prng(): random_r(%lx, %lx)\n", (unsigned long) prng_buf, (unsigned long) &prng_result);
#endif
			return(-1);
		}

		for(i = 0; i < (int) sizeof(int32_t); i++){
			data->plaintext_buf[key_count] = data->ciphertext_buf[key_count] ^ prng_result_ptr[i];
			key_count++;

			if(key_count == data->buf_count){
				break;
			}
		}
	}

	free(prng_buf);

	return(0);
}



/**********************************************************************************************************************
 *
 * xorscura_compare()
 *
 *	Input: A pointer to the xod data structure.
 *		xod->plaintext_buf should have a pointer to the unencrypted data.
 *		xod->buf_count should contain the number of bytes in xod->plaintext_buf.
 *		xod->ciphertext_buf should have a pointer to the ciphertext data.
 *		xod->key should have a pointer to the key data *OR*
 *		xod->seed should have the prng seed needed to generate the key.
 *
 *	Output: 0 on match, 1 on non-match, -1 on error.
 *
 *	Purpose: Compare the plaintext and ciphertext strings in a way that won't leave the secret exposed in memory.
 *
 *	Note: 0 on match is a behavior we chose in an attempt to mimic the behavior of the strcmp() function.
 *
 **********************************************************************************************************************/
int xorscura_compare(struct xod *data){

	int i;
	char tmp_char;

	if(!(data->seed || data->key_buf)){
#ifdef DEBUG
		fprintf(stderr, "xorscura_compare(): No key or seed provided.\n");
#endif
		return(-1);
	}

	// Check if we have the prng case, or straight xor of arrays.
	if(data->seed){
		return(xorscura_compare_prng(data));
	}

	// Compare.
	for(i = 0; i < (int) data->buf_count; i++){
		tmp_char = (data->ciphertext_buf[i] ^ data->key_buf[i]);
		if((data->plaintext_buf[i]) != tmp_char){
			return(1);
		}
	}

	return(0);
}



/**********************************************************************************************************************
 *
 * xorscura_compare_prng()
 *
 *	Input: A pointer to the xod data structure.
 *		xod->plaintext_buf should have a pointer to the unencrypted data.
 *		xod->buf_count should contain the number of bytes in xod->plaintext_buf.
 *		xod->ciphertext_buf should have a pointer to the ciphertext data.
 *		xod->seed should have the prng seed needed to generate the key.
 *
 *	Output: 0 on match, 1 on non-match, -1 on error.
 *
 *	Purpose: Compare the plaintext and ciphertext strings in a way that won't leave the secret exposed in memory.
 *
 *	Note: 0 on match is a behavior we chose in an attempt to mimic the behavior of the strcmp() function.
 *
 *	Note: This function is called inside of xorscura_compare_prng() after a seed check. There shouldn't be any reason
 *	to call this directly, unless you know what you're doing.
 *
 **********************************************************************************************************************/
int xorscura_compare_prng(struct xod *data){

	int i;

	size_t key_count;

	char prng_state[PRNG_STATELEN];
	struct random_data *prng_buf;
	int32_t prng_result;
	char *prng_result_ptr = (char *) &prng_result;

	char tmp_char;


	// Initialize the prng.
	if((prng_buf = (struct random_data *) calloc(1, sizeof(struct random_data))) == NULL){
#ifdef DEBUG
		fprintf(stderr, "xorscura_compare_prng(): calloc(1, %d)\n", (int) sizeof(struct random_data));
#endif
		return(-1);
	}

	memset(prng_state, '\0', PRNG_STATELEN);
	if(initstate_r(data->seed, prng_state, PRNG_STATELEN, prng_buf) == -1){
#ifdef DEBUG
		fprintf(stderr, "xorscura_compare_prng(): initstate_r(0x%x, %lx, %d, %lx)\n", data->seed, (unsigned long) prng_state, PRNG_STATELEN, (unsigned long) prng_buf);
#endif
		return(-1);
	}

	key_count = 0;
	while(key_count < data->buf_count){
		if(random_r(prng_buf, &prng_result) == -1){
#ifdef DEBUG
			fprintf(stderr, "xorscura_compare_prng(): random_r(%lx, %lx)\n", (unsigned long) prng_buf, (unsigned long) &prng_result);
#endif
			return(-1);
		}

		// Generate key char, decrypt cipher char, and compare with plain char.
		for(i = 0; i < (int) sizeof(int32_t); i++){
			tmp_char = (data->ciphertext_buf[key_count] ^ prng_result_ptr[i]);
			if((data->plaintext_buf[key_count]) != tmp_char){
				free(prng_buf);
				return(1);
			}
			key_count++;

			if(key_count == data->buf_count){
				break;
			}
		}
	}

	free(prng_buf);

	return(0);
}



/**********************************************************************************************************************
 *
 * xorscura_free_xod()
 *
 *	Input: A pointer to the xod data structure.
 *	Output: None.
 *
 *	Purpose: Clear the xod data structure. free() anything we malloc()d. Zero/NULL everything out. 
 *
 *	Note: Does not free the xod structure itself.
 *	Note: The buffers we malloc()d will be tracked with bitwise flags in alloc_flag. Those buffers will be free()d.
 *
 **********************************************************************************************************************/
void xorscura_free_xod(struct xod *data){

	if(data->alloc_flag & ALLOC_PLAINTEXT){
		free(data->plaintext_buf);
		data->alloc_flag &= !ALLOC_PLAINTEXT;
	}
	data->plaintext_buf = NULL;

	if(data->alloc_flag & ALLOC_CIPHERTEXT){
		free(data->ciphertext_buf);
		data->alloc_flag &= !ALLOC_CIPHERTEXT;
	}
	data->ciphertext_buf = NULL;

	if(data->alloc_flag & ALLOC_KEY){
		free(data->key_buf);
		data->alloc_flag &= !ALLOC_KEY;
	}
	data->key_buf = NULL;

	data->seed = 0;
	data->buf_count = 0;

}

// Print DEBUG info about the xod structures.
void xorscura_debug_xod(struct xod *data){

	unsigned int i;

  printf("DEBUG: xorscura_debug_xod(): alloc_flag: %d\n", data->alloc_flag);
  printf("DEBUG: xorscura_debug_xod(): buf_count: %d\n", (int) data->buf_count);
  printf("DEBUG: xorscura_debug_xod(): seed: %u\n", data->seed);

	printf("DEBUG: xorscura_debug_xod(): plaintext_buf: %lx\n", (unsigned long) data->plaintext_buf);
	if(data->plaintext_buf){
		printf("DEBUG: xorscura_debug_xod(): *plaintext_buf: ");
		for(i = 0; i < data->buf_count; i++){
			printf("%02x", data->plaintext_buf[i]);
		}
		printf("\n");
	}

	printf("DEBUG: xorscura_debug_xod(): ciphertext_buf: %lx\n", (unsigned long) data->ciphertext_buf);
	if(data->ciphertext_buf){
		printf("DEBUG: xorscura_debug_xod(): *ciphertext_buf: ");
		for(i = 0; i < data->buf_count; i++){
			printf("%02x", data->ciphertext_buf[i]);
		}
		printf("\n");
	}

	printf("DEBUG: xorscura_debug_xod(): key_buf: %lx\n", (unsigned long) data->key_buf);
	if(data->key_buf){
		printf("DEBUG: xorscura_debug_xod(): *key_buf: ");
		for(i = 0; i < data->buf_count; i++){
			printf("%02x", data->key_buf[i]);
		}
		printf("\n");
	}
	
}


