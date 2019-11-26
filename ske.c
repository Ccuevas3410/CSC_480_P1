#include "ske.h"
#include "prf.h"
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h> /* memcpy */
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#ifdef LINUX
#define MMAP_SEQ MAP_PRIVATE|MAP_POPULATE
#else
#define MMAP_SEQ MAP_PRIVATE
#endif

//Worked on by Marissa Almolsino & Raymund Rodriguez 


/* NOTE: since we use counter mode, we don't need padding, as the
 * ciphertext length will be the same as that of the plaintext.
 * Here's the message format we'll use for the ciphertext:
 * +------------+--------------------+----------------------------------+
 * | 16 byte IV | C = AES(plaintext) | HMAC(IV|C) (32 bytes for SHA256) |
 * +------------+--------------------+----------------------------------+
 * */

/* we'll use hmac with sha256, which produces 32 byte output */
#define HM_LEN 32
#define KDF_KEY "qVHqkOVJLb7EolR9dsAMVwH1hRCYVx#I"
/* need to make sure KDF is orthogonal to other hash functions, like
 * the one used in the KDF, so we use hmac with a key. */

int ske_keyGen(SKE_KEY* K, unsigned char* entropy, size_t entLen)
{
	/* TODO: write this.  If entropy is given, apply a KDF to it to get
	 * the keys (something like HMAC-SHA512 with KDF_KEY will work).
	 * If entropy is null, just get a random key (you can use the PRF). */

	unsigned char keyMaterial[64];
	if (entropy) {
		HMAC(EVP_sha512(), KDF_KEY, strlen(KDF_KEY), entropy, entLen, keyMaterial, 0);

	}
	else{
		randBytes(keyMaterial, 64);
	}
	memcpy(K->hmacKey, keyMaterial, 32);
	memcpy(K->aesKey, keyMaterial+32, 32);
	memset(keyMaterial, 0, 64);
	
	return 0;
}

size_t ske_getOutputLen(size_t inputLen)
{
	return AES_BLOCK_SIZE + inputLen + HM_LEN;
}
size_t ske_encrypt(unsigned char* outBuf, unsigned char* inBuf, size_t len,
		SKE_KEY* K, unsigned char* IV)
{	
	//if no IV given, make a random one
	if (!IV){ 

	 	IV = malloc(16);
	 	randBytes(IV, 16);
	}
	//first 16 of outBuf (ciphertext) is our IV!
	memcpy(outBuf, IV, 16);
 	//encrypt!
 	//set up context
 	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
 	//initialize encryption using aes256 scheme
 	if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(),0, K->aesKey, IV)){
 		ERR_print_errors_fp(stderr);
 	}
 	//ciphertext lenght
 	int nWritten;
 	//actual encryption. ciphertext stored in outBuf+16.
 	if(1!= EVP_EncryptUpdate(ctx, outBuf+16, &nWritten, inBuf, len)){
 		ERR_print_errors_fp(stderr);
 	}
 	
 	unsigned char* hBuf = malloc(HM_LEN);
 	HMAC(EVP_sha256(), K->hmacKey, HM_LEN, outBuf, nWritten+16, hBuf, NULL);

 	//copies hmac buffer to the end of our IV + ciphertext buffer

 	memcpy(&outBuf[nWritten+16], hBuf, HM_LEN);
 	
 	free(IV);
 	
 	return (nWritten + 16 + HM_LEN); //IV + ciphertext_Len + HM_LEN


	/* TODO: finish writing this.  Look at ctr_example() in aes-example.c
	 * for a hint.  Also, be sure to setup a random IV if none was given.
	 * You can assume outBuf has enough space for the result. */
	 /* TODO: should return number of bytes written, which
	             hopefully matches ske_getOutputLen(...). */
}
size_t ske_encrypt_file(const char* fnout, const char* fnin,
		SKE_KEY* K, unsigned char* IV, size_t offset_out)
{
	/* TODO: write this.  Hint: mmap. */

	int fdin = open(fnin, O_RDONLY);
	int fdout = open(fnout, O_CREAT | O_RDWR, S_IRWXU);
	//check if files opened properly! 
	if (( fdin == -1) || (fdout == -1)) {
		printf("Failed to open files!!!!\n");
		return -1;
	}

	struct stat statusBuff;
	//check if buffer is bad
	if ((fstat(fdin, &statusBuff) == -1) || (statusBuff.st_size == 0)) {
		printf("Status of buffer is badddd!!!\n");
		return -1;
	}

	char *mapping;
	//create virtual mapping of file and address in memory. yay!
	mapping = mmap(NULL, statusBuff.st_size, PROT_READ, MAP_PRIVATE, fdin, 0);
	if (mapping == MAP_FAILED) {
		printf("Mapping failed!!\n");
		return -1;
	}

	size_t fdinLength = strlen(mapping);
	size_t ciphertextLength = ske_getOutputLen(fdinLength);
	unsigned char* ciphertext = malloc(ciphertextLength);

	ssize_t encryptLength = ske_encrypt(ciphertext, (unsigned char*)mapping, fdinLength, K, IV);

	//chekcs if encryption works and validates that encrypt returns proper ciphertext length!
	if ((encryptLength == -1) || (encryptLength != ciphertextLength)){
		printf("Failed to encrypt!!\n");
		return -1;
	}

	lseek(fdout, offset_out, SEEK_SET);
	ssize_t writtenBits = write(fdout, ciphertext, encryptLength);

	if (writtenBits == -1){
		printf("Writting Failed!\n");
		return -1;
	}

	if (!munmap(mapping, statusBuff.st_size)){
		printf("Unmapping failed!\n");
		return -1;
	}

	free(ciphertext);
	
	if(!close(fdin) || !close(fdout)){
		printf("Closing files failed or whatever!!!\n");
		return -1;
	}

	return 0;
}
size_t ske_decrypt(unsigned char* outBuf, unsigned char* inBuf, size_t len,
		SKE_KEY* K)
{	

	//copy first 16 elements of inBuf (IV) into iv to use for decryption
	unsigned char iv[16];
	memcpy(iv, inBuf, 16);

	int nWritten = 0;
	
	unsigned char hBuf[HM_LEN];
	HMAC(EVP_sha256(), K->hmacKey, HM_LEN, inBuf, len - HM_LEN, hBuf, NULL);

	//Check that ciphertext is valid. 
	//Check that each elelment of hBuf is same as hBuf that was a part of our outBuf in encryption
	for(int i = 0; i <HM_LEN; i++){
		if(hBuf[i] != inBuf[len-HM_LEN+i]) {
			return -1; 
		}
	}

	//set up cipher context
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	//initialize decryption using 
	

	if (1!=EVP_DecryptInit_ex(ctx,EVP_aes_256_ctr(),0,K->aesKey, iv)){
		ERR_print_errors_fp(stderr);
	}
	if (1!=EVP_DecryptUpdate(ctx,outBuf,&nWritten,inBuf+16,len-16-HM_LEN)) {
		ERR_print_errors_fp(stderr);
	}

	return nWritten; 

	/* TODO: write this.  Make sure you check the mac before decypting!
	 * Oh, and also, return -1 if the ciphertext is found invalid.
	 * Otherwise, return the number of bytes written.  See aes-example.c
	 * for how to do basic decryption. */
	

}


size_t ske_decrypt_file(const char* fnout, const char* fnin,
		SKE_KEY* K, size_t offset_in)
{
	/* TODO: write this. */
	return 0;
}
