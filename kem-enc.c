/* kem-enc.c
 * simple encryption utility providing CCA2 security.
 * based on the KEM/DEM hybrid model. */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <fcntl.h>
#include <openssl/sha.h>
#include <sys/mman.h>
#include "ske.h"
#include "rsa.h"
#include "prf.h"

static const char* usage =
"Usage: %s [OPTIONS]...\n"
"Encrypt or decrypt data.\n\n"
"   -i,--in     FILE   read input from FILE.\n"
"   -o,--out    FILE   write output to FILE.\n"
"   -k,--key    FILE   the key.\n"
"   -r,--rand   FILE   use FILE to seed RNG (defaults to /dev/urandom).\n"
"   -e,--enc           encrypt (this is the default action).\n"
"   -d,--dec           decrypt.\n"
"   -g,--gen    FILE   generate new key and write to FILE{,.pub}\n"
"   -b,--BITS   NBITS  length of new key (NOTE: this corresponds to the\n"
"                      RSA key; the symmetric key will always be 256 bits).\n"
"                      Defaults to %lu.\n"
"   --help             show this message and exit.\n";

#define FNLEN 255

enum modes {
	ENC,
	DEC,
	GEN
};

/* Let SK denote the symmetric key.  Then to format ciphertext, we
 * simply concatenate:
 * +------------+----------------+
 * | RSA-KEM(X) | SKE ciphertext |
 * +------------+----------------+
 * NOTE: reading such a file is only useful if you have the key,
 * and from the key you can infer the length of the RSA ciphertext.
 * We'll construct our KEM as KEM(X) := RSA(X)|H(X), and define the
 * key to be SK = KDF(X).  Naturally H and KDF need to be "orthogonal",
 * so we will use different hash functions:  H := SHA256, while
 * KDF := HMAC-SHA512, where the key to the hmac is defined in ske.c
 * (see KDF_KEY).
 * */

#define HASHLEN 32 /* for sha256 */

int kem_encrypt(const char* fnOut, const char* fnIn, RSA_KEY* K)
{
	/* TODO: encapsulate random symmetric key (SK) using RSA and SHA256;
	 * encrypt fnIn with SK; concatenate encapsulation and cihpertext;
	 * write to fnOut. */
// SKE KEYGEN
/*Create a random entropy of the same size as the rsa keys length, and
* use it to generate the SKE key*/
	size_t symmetricKeyLen = rsa_numBytesN(K);
	unsigned char* x = malloc(symmetricKeyLen);
	SKE_KEY SK;
	ske_keyGen(&SK,x,symmetricKeyLen);
	unsigned char* encapkey = malloc(symmetricKeyLen + HASHLEN);

// HASH FUNCTION
/*Hash the entropy and append it to rsa(x)*/
	unsigned char* tempHash = malloc(HASHLEN);
	SHA256(x,symmetricKeyLen,tempHash);
	rsa_encrypt(encapkey, x,symmetricKeyLen, K);
	memcpy(encapkey + symmetricKeyLen,tempHash,HASHLEN);

//Writing the encapsulated key into the output file
	int fdOut;
	fdOut = open(fnOut, O_RDWR|O_CREAT, S_IRWXU);
	int wr = write(fdOut, encapkey, symmetricKeyLen + HASHLEN);
	if (wr< 0) {
		fprintf(stderr, "Error writing to file");
		return 1;
	}
	close(fdOut);

//Encrypting the file
	unsigned char* IV = malloc(16);
	randBytes(IV,16);
	ske_encrypt_file(fnOut, fnIn, &SK, IV,symmetricKeyLen + HASHLEN );
	
	return 0;
}

/* NOTE: make sure you check the decapsulation is valid before continuing */
int kem_decrypt(const char* fnOut, const char* fnIn, RSA_KEY* K)
{
	/* TODO: write this. */
	/* step 1: recover the symmetric key */
	/* step 2: check decapsulation */
	/* step 3: derive key from ephemKey and decrypt data. */

//The first n bytes are the RSA, the remaining bytes are the ciphertext
	int fdIn;
	unsigned char* mappedFile; //for mmap
	size_t fileSize;
	struct stat st;	
	
	fdIn = open(fnIn, &st);
	fileSize = st.st_size;
	//Copy the file and put it in a buffer
	mappedFile = mmap(NULL, fileSize, PROT_READ, MAP_PRIVATE, fdIn, 0);
	if (mappedFile == MAP_FAILED){
		fprintf(stderr, "Error");
	}
	close(fdIn);

	size_t keylen = rsa_numBytesN(K);
	unsigned char* EncFile = malloc(keylen); 
	memcpy(EncFile, mappedFile, keylen); 
	unsigned char* DecFile = malloc(keylen);
	rsa_decrypt(DecFile, EncFile, keylen, K); 	
	
//HASH Check
/*Hash the entropy and compares it to h(x) */ 
	unsigned char* tempHash=malloc(HASHLEN);
	SHA256(DecFile,keylen,tempHash);
	unsigned char* hashCheck = malloc(HASHLEN);
	memcmp(hashCheck, mappedFile+keylen, HASHLEN);
	for(size_t i=0; i<HASHLEN; ++i){
		if(hashCheck[i] != tempHash[i]){
   			printf("Decapsualtion failed: Hash incorrect");
    			return -1;
		}
  	}
//Generate ske key and decrypt the file
	SKE_KEY SK;
	ske_keyGen(&SK, DecFile, keylen);

	ske_decrypt_file(fnOut, fnIn, &SK, keylen+HASHLEN);

	return 0;
}

int main(int argc, char *argv[]) {
	/* define long options */
	static struct option long_opts[] = {
		{"in",      required_argument, 0, 'i'},
		{"out",     required_argument, 0, 'o'},
		{"key",     required_argument, 0, 'k'},
		{"rand",    required_argument, 0, 'r'},
		{"gen",     required_argument, 0, 'g'},
		{"bits",    required_argument, 0, 'b'},
		{"enc",     no_argument,       0, 'e'},
		{"dec",     no_argument,       0, 'd'},
		{"help",    no_argument,       0, 'h'},
		{0,0,0,0}
	};
	/* process options: */
	char c;
	int opt_index = 0;
	char fnRnd[FNLEN+1] = "/dev/urandom";
	fnRnd[FNLEN] = 0;
	char fnIn[FNLEN+1];
	char fnOut[FNLEN+1];
	char fnKey[FNLEN+1];
	memset(fnIn,0,FNLEN+1);
	memset(fnOut,0,FNLEN+1);
	memset(fnKey,0,FNLEN+1);
	int mode = ENC;
	// size_t nBits = 2048;
	size_t nBits = 1024;
	while ((c = getopt_long(argc, argv, "edhi:o:k:r:g:b:", long_opts, &opt_index)) != -1) {
		switch (c) {
			case 'h':
				printf(usage,argv[0],nBits);
				return 0;
			case 'i':
				strncpy(fnIn,optarg,FNLEN);
				break;
			case 'o':
				strncpy(fnOut,optarg,FNLEN);
				break;
			case 'k':
				strncpy(fnKey,optarg,FNLEN);
				break;
			case 'r':
				strncpy(fnRnd,optarg,FNLEN);
				break;
			case 'e':
				mode = ENC;
				break;
			case 'd':
				mode = DEC;
				break;
			case 'g':
				mode = GEN;
				strncpy(fnOut,optarg,FNLEN);
				break;
			case 'b':
				nBits = atol(optarg);
				break;
			case '?':
				printf(usage,argv[0],nBits);
				return 1;
		}
	}

	/* TODO: finish this off.  Be sure to erase sensitive data
	 * like private keys when you're done with them (see the
	 * rsa_shredKey function). */

	RSA_KEY K;
	FILE* rsa_publicKey;
	FILE* rsa_privateKey;
	switch (mode) {
		case ENC:
			rsa_publicKey = fopen(fnKey, "r");
			if( rsa_publicKey == NULL){
				printf("ERROR with key");
				return -1;
			}
			rsa_readPublic(rsa_publicKey, &K);
			kem_encrypt(fnOut, fnIn, &K);
			fclose(rsa_publicKey);
			rsa_shredKey(&K);
			break;
		case DEC:
			rsa_privateKey = fdopen(fnKey, "r");
			rsa_readPrivate(rsa_privateKey, &K);
			kem_decrypt(fnOut, fnIn, &K);
			fclose(rsa_privateKey);
			rsa_shredKey(&K);
			break;
		case GEN:
			rsa_keyGen(nBits, &K);
//Generate new key and write keys to file
			rsa_privateKey = fopen(fnOut, "w+");
			rsa_writePrivate(rsa_privateKey, &K);
//Append '.pub to filename for public Key
			strcat(fnOut, ".pub"); 			
			rsa_publicKey = fopen(fnOut, "w+");			
			rsa_writePublic(rsa_publicKey, &K);

	
			fclose(rsa_publicKey);
			fclose(rsa_privateKey);
			rsa_shredKey(&K);
			break;
	}
 	
	return 0;
}
