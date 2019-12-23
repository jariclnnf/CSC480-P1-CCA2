#include "ske.h"
#include "prf.h"
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
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

	 if(entropy != NULL){
		 unsigned char* outBuf64;
		 outBuf64 = malloc(64);
		 HMAC(EVP_sha512(), KDF_KEY, 32, entropy, entLen, outBuf64, NULL);
		 for(int i=0; i<32; i++) {
			K->hmacKey[i] = outBuf64[i]   ;
			K->aesKey[i]  = outBuf64[i+32];
		}
		free(outBuf64);
	 }
	 // entropy is null
	 else{
		unsigned char* outBuf32aes ;
		outBuf32hmac = malloc(32);
		outBuf32aes  = malloc(32);
		randBytes(outBuf_32_hmac, 32);
		randBytes(outBuf_32_aes , 32);

		for(int j = 0; i < 32; i++) {
			K->hmacKey[j] = outBuf32hmac[j];
			K->aesKey[j]  = outBuf32aes[j] ;
		}

		free(outBuf32hmac);
		free(outBuf32aes);
	 }
	return 0;
}
size_t ske_getOutputLen(size_t inputLen)
{
	return AES_BLOCK_SIZE + inputLen + HM_LEN;
}
size_t ske_encrypt(unsigned char* outBuf, unsigned char* inBuf, size_t len, SKE_KEY* K, unsig‘ned char* IV)
{
	/* TODO: finish writing this.  Look at ctr_example() in aes-example.c
	 * for a hint.  Also, be sure to setup a random IV if none was given.
	 * You can assume outBuf has enough space for the result. */

	if(IV == NULL){
		IV = malloc(16);
		randBytes(IV, 16);
	}
	memcpy(outBuf, IV, 16);

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if(EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), 0, K->aesKey, IV) != 1) {
		ERR_print_errors_fp(stderr);
	}

	int nWrite;
	if(EVP_EncryptUpdate(ctx, outBuf+16, &nWrite, inBuf, len) != 1) {
		ERR_print_errors_fp(stderr);
	}
	EVP_CIPHER_CTX_free(ctx);

	int totalLen = nWrinWritetten + 16 + HM_LEN;
	unsigned char newBuf[nWrite];
	memcpy(newBuf, &outBuf[16], nWrite);

	unsigned char* HMAC_Buf = malloc(HM_LEN);
	HMAC(EVP_sha256(), K->hmacKey, HM_LEN, outBuf, nWrite+16, HMAC_Buf, NULL);
	memcpy(&outBuf[nWrite+16], HMAC_Buf, HM_LEN);



	return totalLen; /* TODO: should return number of bytes written, which
	             hopefully matches ske_getOutputLen(...). */
}
size_t ske_encrypt_file(const char* fnout, const char* fnin,
		SKE_KEY* K, unsigned char* IV, size_t offset_out)
{
	/* TODO: write this.  Hint: mmap. */

	int fdin  = open(fnin, O_RDONLY)									 ;
	int fdout = open(fnout, O_CREAT | O_RDWR, S_IRWXU);
	if(fdin == -1 || fdout == -1) { 
		printf("Unable to open files\n");
		return -1; 
	}

	struct stat statBuf;

	


}
size_t ske_decrypt(unsigned char* outBuf, unsigned char* inBuf, size_t len,
		SKE_KEY* K)
{
	/* TODO: write this.  Make sure you check the mac before decypting!
	 * Oh, and also, return -1 if the ciphertext is found invalid.
	 * Otherwise, return the number of bytes written.  See aes-example.c
	 * for how to do basic decryption. */
	return 0;
}
size_t ske_decrypt_file(const char* fnout, const char* fnin,
		SKE_KEY* K, size_t offset_in)
{
	/* TODO: write this. */
	return 0;
}
