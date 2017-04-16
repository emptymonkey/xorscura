
#include "libxorscura.h"


int xorscura_encrypt(struct xod *data){

	char *seed_ptr = (char *) &(data->seed);
	size_t seed_count;

	size_t key_count;
/*
	char *plaintext_buffer;
	int plaintext_count;

	// ciphertext_buffer and key_buffer will always be the same size.
	char *ciphertext_buffer;
	char *key_buffer;
	int key_count;
*/

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

	if((data->ciphertext_buf = (char *) malloc(data->buf_count)) == NULL){
#ifdef DEBUG
		fprintf(stderr, "xorscura_encrypt(): malloc(%d)\n", (int) data->buf_count);
#endif
		return(-1);
	}

  if((data->key_buf = (char *) malloc(data->buf_count)) == NULL){
#ifdef DEBUG
		fprintf(stderr, "xorscura_encrypt(): malloc(%d)\n", (int) data->buf_count);
#endif
    return(-1);
  }

	if((prng_buf = (struct random_data *) malloc(sizeof(struct random_data))) == NULL){
#ifdef DEBUG
		fprintf(stderr, "xorscura_encrypt(): malloc(%d)\n", (int) sizeof(struct random_data));
#endif
    return(-1);
	}

	if(initstate_r(data->seed, prng_state, PRNG_STATELEN, prng_buf) == -1){
#ifdef DEBUG
		fprintf(stderr, "xorscura_encrypt(): initstate_r(0x%x, %lx, %d, %lx)\n", data->seed, (unsigned long) prng_state, PRNG_STATELEN, (unsigned long) prng_buf);
#endif
    return(-1);
	}

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


int xorscura_decrypt(struct xod *data){

	int i;

	if(!(data->seed || data->key_buf)){
#ifdef DEBUG
		fprintf(stderr, "xorscura_decrypt(): No key or seed provided.\n");
#endif
		return(-1);
	}

	if(data->seed){
		return(xorscura_decrypt_prng(data));
	}

	if((data->plaintext_buf = (char *) malloc(data->buf_count)) == NULL){
#ifdef DEBUG
		fprintf(stderr, "xorscura_decrypt(): malloc(%d)\n", (int) data->buf_count);
#endif
		return(-1);
	}

	for(i = 0; i < (int) data->buf_count; i++){
		data->plaintext_buf[i] = data->ciphertext_buf[i] ^ data->key_buf[i];
	}

	return(0);
}


int xorscura_compare(struct xod *data){

	int i;

	if(!(data->seed || data->key_buf)){
#ifdef DEBUG
		fprintf(stderr, "xorscura_compare(): No key or seed provided.\n");
#endif
		return(-1);
	}

	if(data->seed){
		return(xorscura_compare_prng(data));
	}

	for(i = 0; i < (int) data->buf_count; i++){
		if(data->plaintext_buf[i] != (data->ciphertext_buf[i] ^ data->key_buf[i])){
			return(1);
		}
	}

	return(0);
}


int xorscura_decrypt_prng(struct xod *data){
	int i;

	size_t key_count;

	char prng_state[PRNG_STATELEN];
	struct random_data *prng_buf;
	int32_t prng_result;
	char *prng_result_ptr = (char *) &prng_result;


	if((data->plaintext_buf = (char *) malloc(data->buf_count)) == NULL){
#ifdef DEBUG
		fprintf(stderr, "xorscura_decrypt_prng(): malloc(%d)\n", (int) data->buf_count);
#endif
		return(-1);
	}

	if((prng_buf = (struct random_data *) malloc(sizeof(struct random_data))) == NULL){
#ifdef DEBUG
		fprintf(stderr, "xorscura_decrypt_prng(): malloc(%d)\n", (int) sizeof(struct random_data));
#endif
		return(-1);
	}

	if(initstate_r(data->seed, prng_state, PRNG_STATELEN, prng_buf) == -1){
#ifdef DEBUG
		fprintf(stderr, "xorscura_decrypt_prng(): initstate_r(0x%x, %lx, %d, %lx)\n", data->seed, (unsigned long) prng_state, PRNG_STATELEN, (unsigned long) prng_buf);
#endif
		return(-1);
	}

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


int xorscura_compare_prng(struct xod *data){
	int i;

	size_t key_count;

	char prng_state[PRNG_STATELEN];
	struct random_data *prng_buf;
	int32_t prng_result;
	char *prng_result_ptr = (char *) &prng_result;


	if((prng_buf = (struct random_data *) malloc(sizeof(struct random_data))) == NULL){
#ifdef DEBUG
		fprintf(stderr, "xorscura_compare_prng(): malloc(%d)\n", (int) sizeof(struct random_data));
#endif
		return(-1);
	}

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

		for(i = 0; i < (int) sizeof(int32_t); i++){
			if(data->plaintext_buf[key_count] != (data->ciphertext_buf[key_count] ^ prng_result_ptr[i])){
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

void xorscura_free_xod(struct xod *data){

	/*
		 struct xod {

		 size_t buf_count;
		 char *plaintext_buf;
		 char *key_buf;
		 char *ciphertext_buf;

		 unsigned int seed;

		 };

	 */

	if(data->plaintext_buf){
		free(data->plaintext_buf);
		data->plaintext_buf = NULL;
	}

	if(data->key_buf){
		free(data->plaintext_buf);
		data->key_buf = NULL;
	}

	if(data->ciphertext_buf){
		free(data->plaintext_buf);
		data->ciphertext_buf = NULL;
	}

	free(data);
}

