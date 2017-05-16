
/**********************************************************************************************************************
 *
 * xorscura
 *
 *	@emptymonkey
 *	2017-04-17
 *
 *	A tool to simplify string obfuscation with xor.
 *	This is the cli frontend for the libxorscura library.
 *
 *
 *	Example:
 *
 *		empty@monkey:~$ echo "hello, world" | xorscura 
 *		plaintext: 68656c6c6f2c20776f726c640a
 *		seed: 2081836537
 *		key: a95b2c261058ce0260cb63138c
 *		cipher: c13e404a7f74ee750fb90f7786
 *
 *		empty@monkey:~$ xorscura -d -c c13e404a7f74ee750fb90f7786 -k a95b2c261058ce0260cb63138c
 *		hello, world
 *
 *		empty@monkey:~$ xorscura -d -c c13e404a7f74ee750fb90f7786 -s 2081836537
 *		hello, world
 *
 **********************************************************************************************************************/


#include "libxorscura.h"


void usage(){

	fprintf(stderr, "usage(): %s [-e|-d|-x|-h] [-C] [-p PLAINTEXT] [-c CIPHERTEXT] [-k KEY] [-s SEED]\n", program_invocation_short_name);
	fprintf(stderr, "\t-e\t:\tEncrypt. (Requires PLAINTEXT and KEY.)\n");
	fprintf(stderr, "\t-d\t:\tDecrypt. (Requires CIPHERTEXT and KEY.)\n");
	fprintf(stderr, "\t-x\t:\tCompare. (Requires PLAINTEXT, CIPHERTEXT, and KEY.)\n");
	fprintf(stderr, "\t-h\t:\tHelp!\n");
	fprintf(stderr, "\t-C\t:\tOutput as a C style byte array.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Purpose: Useful tool / library for obscuring strings in your binaries with the help of xor.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Author: @emptymonkey : https://github.com/emptymonkey/xorscura\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Notes:\n");
	fprintf(stderr, "- Encrypt is the default mode, so -e never needs to be specified.\n");
	fprintf(stderr, "- PLAINTEXT is normally taken in its binary form from STDIN.\n");
	fprintf(stderr, "- Any of PLAINTEXT, CIPHERTEXT, or KEY can be specified on the commandline using the appropriate switches.\n");
	fprintf(stderr, "  The format of these arguments is expected to be \"postscript continuous hexdump style\". (man xxd)\n");
	fprintf(stderr, "- The SEED argument can be used instead of KEY. This will be used as the seed to random() in place of KEY\n");
	fprintf(stderr, "  for decrypt and compare operations. This allows you to save memory in your binary by storing only\n");
	fprintf(stderr, "  CIPHERTEXT and SEED. SEED format is expected as a uint.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Example:\n");
	fprintf(stderr, "\n");
	exit(-1);

}


// returns the size of the newly malloc()d bin, or -1 on error.
int ps2bin(char *ps, unsigned char **bin);
int fill_from_stdin(unsigned char **bin);



int main(int argc, char **argv){

	struct xod *data;

	int retval;
	int i;

	int opt;

#define ENCRYPT	0
#define DECRYPT	1
#define COMPARE	2
	unsigned int operation = ENCRYPT;

#define PS_STYLE 0
#define C_STYLE 1
	int output = PS_STYLE;

	char *open_str;
	char *close_str;
	char *numeric_str;
	char *separating_str;

	char *cli_plaintext = NULL;
	char *cli_ciphertext = NULL;
	char *cli_key = NULL;
	char *cli_seed = NULL;


	while((opt = getopt(argc, argv, "edxhCp:c:k:s:")) != -1){
		switch (opt){
			case 'h':
				usage();

			case 'e':
				break;

			case 'd':
				if(operation){
					usage();
				}
				operation = DECRYPT;
				break;

			case 'x':
				if(operation){
					usage();
				}
				operation = COMPARE;
				break;

			case 'C':
				output = C_STYLE;
				break;

			case 'p':
				cli_plaintext = optarg;
				break;

			case 'c':
				cli_ciphertext = optarg;
				break;

			case 'k':
				cli_key = optarg;
				break;

			case 's':
				cli_seed = optarg;
				break;

			default:
				usage();
		}
	}

	// Initialize and fill out the appropriate buffers.
	if((data = (struct xod *) calloc(1, sizeof(struct xod))) == NULL){
		error(-1, errno, "calloc(1, %d)", (int) sizeof(struct xod));
	}

	// Both ENCRYPT and COMPARE will need PLAINTEXT.
	if(operation == ENCRYPT || operation == COMPARE){
		if(cli_plaintext){
			if((retval = ps2bin(cli_plaintext, &(data->plaintext_buf))) == -1){
				error(-1, errno, "ps2bin(%lx, %lx)", (unsigned long) cli_plaintext, (unsigned long) &(data->plaintext_buf));
			}
			data->buf_count = (size_t) retval;
		}else{
			if((retval = fill_from_stdin(&(data->plaintext_buf))) == -1){
				error(-1, errno, "fill_from_stdin(%lx)", (unsigned long) &(data->plaintext_buf));
			}
			data->buf_count = (size_t) retval;
		}
	}

	// Both DECRYPT and COMPARE will need CIPHERTEXT and KEY (or SEED).
	if(operation == DECRYPT || operation == COMPARE){
		if(cli_ciphertext){
			if((retval = ps2bin(cli_ciphertext, &(data->ciphertext_buf))) == -1){
				error(-1, errno, "ps2bin(%lx, %lx)", (unsigned long) cli_ciphertext, (unsigned long) &(data->ciphertext_buf));
			}

			if(operation == COMPARE && retval != (int) data->buf_count){
				printf("PLAINTEXT and CIPHERTEXT differ. (Different lengths.)\n");
				return(0);
			}

			data->buf_count = (size_t) retval;

		}else{
			fprintf(stderr, "Error: No CIPHERTEXT provided.\n");
			usage();
		}

		if(cli_key || cli_seed){
			if(cli_key && cli_seed){
				fprintf(stderr, "Error: Either KEY or SEED must be provided for this operation, not both.\n");
				usage();
			}

			if(cli_key){
				if((retval = ps2bin(cli_key, &(data->key_buf))) == -1){
					error(-1, errno, "ps2bin(%lx, %lx)", (unsigned long) cli_key, (unsigned long) &(data->key_buf));
				}

				if(retval != (int) data->buf_count){
					fprintf(stderr, "Error: KEY and CIPHERTEXT are different lengths.\n");
					usage();
				}

			}else{
				errno = 0;
				data->seed = strtoul(cli_seed, NULL, 10);
				if(errno){
					error(-1, errno, "strtoul(%lx, NULL, 10)", (unsigned long) cli_seed);
				}	
			}

		}else{
			fprintf(stderr, "Error: At least one of KEY or SEED must be provided for this operation.\n");
			usage();
		}
	}


	if(operation == ENCRYPT){

		open_str = "";
		close_str = "";
		numeric_str = "";
		separating_str = "";

		if(output == C_STYLE){
			open_str = "{";
			close_str = "}";
			numeric_str = "0x";
			separating_str = ",";
		}

		// Encrypt.
		if(xorscura_encrypt(data) == -1){
			error(-1, errno, "xorscura_encrypt(%lx)", (unsigned long) data);
		}

		// Report.
		printf("plaintext: %s", open_str);
		for(i = 0; i < (int) data->buf_count; i++){
			if(i){
				printf("%s", separating_str);
			}
			printf("%s%02x", numeric_str, (unsigned int) (unsigned char) data->plaintext_buf[i]);
		}
		printf("%s\n", close_str);

		printf("seed: %u\n", data->seed);

		printf("key: %s", open_str);
		for(i = 0; i < (int) data->buf_count; i++){
			if(i){
				printf("%s", separating_str);
			}
			printf("%s%02x", numeric_str, (unsigned int) (unsigned char) data->key_buf[i]);
		}
		printf("%s\n", close_str);

		printf("cipher: %s", open_str);
		for(i = 0; i < (int) data->buf_count; i++){
			if(i){
				printf("%s", separating_str);
			}
			printf("%s%02x", numeric_str, (unsigned int) (unsigned char) data->ciphertext_buf[i]);
		}
		printf("%s\n", close_str);


	}else if(operation == DECRYPT){

		// Decrypt.
		if(xorscura_decrypt(data) == -1){
			error(-1, errno, "xorscura_decrypt(%lx)", (unsigned long) data);
		}

		// Report.
		printf("%s", data->plaintext_buf);


	}else if(operation == COMPARE){

		// Compare.
		if((retval = xorscura_compare(data)) == -1){
			error(-1, errno, "xorscura_compare(%lx)", (unsigned long) data);
		}

		// Report.
		if(retval){
			printf("No match!\n");
		}else{
			printf("Match!\n");
		}
	}

	// We're at the end, so we don't need to free() this stuff, but I'd prefer to be verbose as this could 
	// also be used as example code.
	xorscura_free_xod(data);
	free(data);
	data = NULL;

	return(0);
}


// Take the "postscript raw hex" format and turn it into a binary aray.
int ps2bin(char *ps, unsigned char **bin){

	int count;
	int i;

	char buf[3];
	buf[2] = '\0';

	count = strlen(ps);

	if(count % 2){
		fprintf(stderr, "ps2bin(): Bad format of string: %s\n", ps);
		return(-1);
	}
	count /= 2;

	if((*bin = (unsigned char *) malloc(count)) == NULL){
		fprintf(stderr, "ps2bin(): malloc(%d)", count);
		return(-1);
	}

	for(i = 0; i < count; i++){
		memcpy(buf, ps + (i*2), 2);
		(*bin)[i] = (char) strtol(buf, NULL, 16);
	}

	return(count);
}

// Read plaintext from stdin.
int fill_from_stdin(unsigned char **bin){

	long pagesize;
	size_t buffer_pages;

	int retval;
	int count;

	if((pagesize = sysconf(_SC_PAGESIZE)) == -1){
		fprintf(stderr, "fill_from_stdin(): sysconf(_SC_PAGESIZE)");
	}

	if((*bin = (unsigned char *) malloc(pagesize)) == NULL){
		fprintf(stderr, "fill_from_stdin(): malloc(%ld)", pagesize);
	}
	buffer_pages = 1;

	count = 0;
	while((retval = read(STDIN_FILENO, *bin + count, (pagesize * buffer_pages) - count))){
		if(retval == -1){
			fprintf(stderr, "fill_from_stdin(): read(STDIN_FILENO, 0x%lx, %ld)", (unsigned long) (*bin + count), (pagesize * buffer_pages) - count);
			return(-1);
		}
		count += retval;

		if(!(count % pagesize)){
			buffer_pages++;
			if((*bin = realloc(*bin, pagesize * buffer_pages)) == NULL){
				fprintf(stderr, "fill_from_stdin(): realloc(0x%lx, %ld)", (unsigned long) *bin, pagesize * buffer_pages);
			}
		}
	}

	return(count);
}
