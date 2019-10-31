/* kem-enc.c
 * simple encryption utility providing CCA2 security.
 * based on the KEM/DEM hybrid model. */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <fcntl.h>
#include <openssl/sha.h>

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
	unsigend char* x = malloc(symmetricKeyLen);
	randBytes(x,symmetricKeyLen -1 );
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
	FILE *outFile = fopen(fnOut, "w");
	fwrite(encapkey, 1, symmetricKeyLen + HASHLEN, outFile);
	if (fclose(outFile) != 0) {
		fprintf(stderr, "Unable to close output file stream\n");
		return 1;
	}

//Encrypting the file
	ske_encrypt_file(fnOut, fnIn, &SK, NULL,symmetricKeyLen + HASHLEN );
	
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
	FILE *inputFile = fopen(fnIn, "r");
	if (inputFile == NULL) {
		fprintf(stderr, "An error occurred opening the input file\n");
		return 1;
	}

	size_t keylen = rsa_numBytesN(K);
	unsigned int encapKeyLen = keylen + HASHLEN;
	unsigned char *encapKey = calloc(encapKeyLen, 1);
	assert(encapKey != NULL);
	int amountRead = fread(encapKey, 1, encapKeyLen, inputFile);
	fclose(inputFile);
	if (amountRead < 0) {
		fprintf(stderr, "An error occurred reading from the file\n");
		return 1;
	}

//Split the encapsulated key into the RSA and HASH parts and Decrypt
	unsigned char *rsa = calloc(keylen, 1);
	unsigned char *sha = calloc(HASHLEN, 1);
	memcpy(rsa, encapKey, keylen);
	memcpy(sha, &encapKey[keylen], HASHLEN);
	unsigned char *symmetricKey = calloc(keylen, 1);
	assert(symmetricKey != NULL);
	rsa_decrypt(symmetricKey, rsa, keylen, K);

//HASH Check
/*Hash the entropy and compares it to h(x) */ 
	unsigned char* tempHash=malloc(HASHLEN);
	SHA256(symmetricKey,keylen,tempHash);
	unsigned char* hashCheck = malloc(HASHLEN);
	if (memcmp(sha, tempHASH, HASHLEN) != 0) {
   		printf("Decapsualtion failed: corrupted message\n");
    		exit(1);
  	}
//Generate ske key and decrypt the file
	SKE_KEY SK;
	ske_keyGen(&SK, symmetricKey, keylen);

	ske_decrypt_file(fnOut, fnIn, &SK, encapKeyLen);

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
	switch (mode) {
		case ENC:
			int keyFd = open(fnKey, O_RDWR | O_CREAT, 0666);
			FILE *kFile = fdopen(keyFd, "r+");
			rsa_readPublic(kFile, &K);
			kem_encrypt(fnOut, fnIn, &K);
		case DEC:
			int keyFd = open(fnKey, O_RDWR | O_CREAT, 0666);
			FILE *kFile = fdopen(keyFd, "r+");
			rsa_readPrivate(kFile, &K);
			kem_decrypt(fnOut, fnIn, &K);
		case GEN:
			rsa_keyGen(nBits, &K);
//Generate new key and write private key to $FILE, public key to $FILE.pub
			char *publicKeyFn = calloc(FNLEN + 4, 1);
			assert(publicKeyFn != NULL);
			strcat(publicKeyFn, fnOut);
			strcat(publicKeyFn, ".pub");

			FILE *publicKeyFile = fopen(publicKeyFn, "w");
			FILE *privKeyFile = fopen(fnOut, "w");
			rsa_writePublic(publicKeyFile, &K);
			rsa_writePrivate(privKeyFile, &K);
	
			fclose(publicKeyFile);
			fclose(privKeyFile);
	}
 	rsa_shredKey(&K);
	return 0;
}
