/*----------------------------------------------------------------------------
Final PA: Enhanced Needham-Schroeder Protocol Implementation

Written By: 
     1- Matt Ladany
Submitted on: December 3, 2017
----------------------------------------------------------------------------*/

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <string.h>

/* OpenSSL headers */
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/rand.h>

/* Macros */
#define CIPHER_LEN_MAX 1024
#define PLAINTEXT_LEN_MAX 1008
#define LEN_MAX 1024

void   handleErrors( char *msg) ;

int encrypt(unsigned char* plaintext, int plaintext_len, unsigned char* key,
            unsigned char* iv, unsigned char* ciphertext);
// encrypt() function taken from:
//  https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption.
 
int decrypt(unsigned char* ciphertext, int ciphertext_len, unsigned char* key,
            unsigned char* iv, unsigned char* plaintext);
// decrypt() function taken from:
//  https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption.

void encryptFile( int fd_in, int fd_out, unsigned char* key, unsigned char* iv );

void decryptFile( int fd_in, int fd_out, unsigned char* key, unsigned char* iv );
