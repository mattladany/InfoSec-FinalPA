/*----------------------------------------------------------------------------
Final PA: Enhanced Needham-Shroeder Protocol Implementation
FILE:   myCrypto.c
Written By: 
     Matt Ladany
     
Submitted on: December 3, 2017
----------------------------------------------------------------------------*/
#include "myCrypto.h"

void handleErrors( char *msg)
{
    fprintf( stderr , "%s\n" , msg ) ;
    ERR_print_errors_fp(stderr);
    abort();
}

//-----------------------------------------------------------------------------
#define INPUT_CHUNK   16384

//-----------------------------------------------------------------------------
int encrypt(unsigned char* plaintext, int plaintext_len, unsigned char* key,
            unsigned char* iv, unsigned char* ciphertext) {

    EVP_CIPHER_CTX* ctx;
    int len;
    int ciphertext_len;

    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors("Context creation failed.");

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors("Context initialization failed.");

    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors("EncryptUpdate failed.");

    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext+len, &len))
        handleErrors("EncryptFinal failed.");

    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

//-----------------------------------------------------------------------------
int decrypt(unsigned char* ciphertext, int ciphertext_len, unsigned char* key,
            unsigned char* iv, unsigned char* plaintext) {

    EVP_CIPHER_CTX* ctx;
    int len;
    int plaintext_len;

    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors("Context creation failed.");

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors("Context initialization failed.");

    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors("EncryptUpdate failed.");
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext+len, &len))
        handleErrors("EncryptFinal failed.");
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

//-----------------------------------------------------------------------------


void encryptFile( int fd_in , int fd_out, unsigned char* key, unsigned char* iv )
// Read all the incoming data from 'fd_in' file descriptor
// Compute the SHA256 hash value of this incoming data into the array 'digest'
// If the file descriptor 'fd_save' is > 0, store a copy of the incoming data to 'fd_save'
// Returns actual size in bytes of the computed hash value
//  printf(stderr, "%d\n", *size);
{
    char buffer[PLAINTEXT_LEN_MAX];
    char ciphertext[CIPHER_LEN_MAX];
    EVP_CIPHER_CTX *ctx;
    size_t bytes;
    unsigned int  len = 0;
    
    if ( ! (ctx = EVP_CIPHER_CTX_new() ) )
        handleErrors("EVP_CIPHER_CTX_new failed");

    if( EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1 )
        handleErrors("EVP_EncryptInit failed");

    
    while(1)
    {
        bytes = read(fd_in, buffer, PLAINTEXT_LEN_MAX);

        if(bytes <= 0)
            break;

        if (EVP_EncryptUpdate( ctx, ciphertext, &len, buffer, bytes ) != 1) 
            handleErrors("EVP_DigestUpdate failed");            

        write(fd_out, ciphertext, len);
    }

    if ( 1 != EVP_EncryptFinal_ex(ctx, ciphertext, &len) ) 
        handleErrors("EVP_DigestFinal failed");

    write(fd_out, ciphertext, len);

    EVP_CIPHER_CTX_free(ctx);

}

// Function taken from PA01.
void decryptFile( int fd_in , int fd_out, unsigned char* key, unsigned char* iv )
{
    char buffer[LEN_MAX];
    char plaintext[LEN_MAX];
    EVP_CIPHER_CTX *ctx;
    size_t bytes;
    unsigned int  len = 0;
    
    if ( ! (ctx = EVP_CIPHER_CTX_new() ) )
        handleErrors("EVP_CIPHER_CTX_create failed");

    if( EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1 )
        handleErrors("EVP_EncryptInit failed");

    
    while(1)
    {
        bytes = read(fd_in, buffer, sizeof(buffer));

        if(bytes <= 0)
            break;

        if (EVP_DecryptUpdate( ctx, plaintext, &len, buffer, bytes ) != 1) 
            handleErrors("EVP_DigestUpdate failed");            

        write(fd_out, plaintext, len);
    }

    if ( 1 != EVP_DecryptFinal_ex(ctx, plaintext, &len) ) 
        handleErrors("EVP_DigestFinal failed");

    write(fd_out, plaintext, len);

    EVP_CIPHER_CTX_free(ctx);

}
