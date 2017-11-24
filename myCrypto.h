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

void   handleErrors( char *msg) ;
RSA    *getRSAfromFile(char * filename, int public) ;
size_t fileDigest( int fd_in , uint8_t *digest , int fd_save) ;
int BN_write_fd( const BIGNUM *bn , int fd_out) ;
// Sends the #of bytes , then the bytes themselves of a BIGNUM to file descriptor fd_out
// Returns 1 on success, 0 on failure

BIGNUM * BN_read_fd( int fd_in ) ;
// Read the #of bytes , then the bytes themselves of a BIGNUM from file descriptor fd_in
// Returns: a newly-created BIGNUM, which should be freed later by the caller
// NULL on failure

BIGNUM * BN_myRandom( const BIGNUM *p ) ;
// Returns a newly-created BIGNUM such that: 1 < BN < (p-1)

void elgamalSign( const uint8_t *digest , int len ,
                  const BIGNUM *q , const BIGNUM *gen , const BIGNUM *x ,
                  BIGNUM *r , BIGNUM *s , BN_CTX *ctx) ;
// Use the prime 'q', the primitive root 'gen', and the private 'x'
// to compute the Elgamal signature (r,s) on the 'len'-byte long 'digest'

int elgamalValidate( const uint8_t *digest , int len ,
                     const BIGNUM *q , const BIGNUM *gen , const BIGNUM *y ,
                     BIGNUM *r , BIGNUM *s , BN_CTX *ctx ) ;
// Use the prime 'q', the primitive root 'gen', and the public 'y'
// to validate the Elgamal signature (r,s) on the 'len'-byte long 'digest'
// Return 1 if valid, 0 otherswise

int encrypt(unsigned char* plaintext, int plaintext_len, unsigned char* key,
            unsigned char* iv, unsigned char* ciphertext);
// encrypt() function taken from:
//  https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption.
 
int decrypt(unsigned char* ciphertext, int ciphertext_len, unsigned char* key,
            unsigned char* iv, unsigned char* plaintext);
// decrypt() function taken from:
//  https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption.

