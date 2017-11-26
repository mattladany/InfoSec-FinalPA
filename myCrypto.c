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
// Function taken from PA01.
void encryptFile( int fd_in, int fd_out, unsigned char* key, unsigned char* iv ) {
    EVP_CIPHER_CTX* ctx;
    int len;

    char ciphertext[CIPHER_LEN_MAX];
    char buffer[PLAINTEXT_LEN_MAX];

    /* Create and initialize the context */
    if( !(ctx = EVP_CIPHER_CTX_new()) )
        handleErrors("Context creation error");

    /* Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if( 1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) )
        handleErrors("Context initialization error");

    int bytes_read;

    while ((bytes_read = read (fd_in, buffer, PLAINTEXT_LEN_MAX)) > 0) {


        /* Provide the message to be encrypted, and obtain the encrypted output.
         * EVP_EncryptUpdate can be called multiple times if necessary 
         */
        if( 1 != EVP_EncryptUpdate(ctx, ciphertext, &len, buffer, bytes_read) )
            handleErrors("EncrypteUpdate error");

        write (fd_out, ciphertext, len);

    }



    /* Finalize the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if( 1 != EVP_EncryptFinal_ex(ctx, ciphertext , &len) )
       handleErrors("EncrypteFinal error");

    write(fd_out, ciphertext, len);

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
}

//-----------------------------------------------------------------------------
// Function taken from PA01.
void decryptFile(int fd_in, int fd_out, unsigned char* key, unsigned char* iv) {
    EVP_CIPHER_CTX *ctx;
    int len;
    /* Create and initialise the context */
    if( !(ctx = EVP_CIPHER_CTX_new()) )
    handleErrors("Context creation error");

    /* Initialise the decryption operation. IMPORTANT - ensure you use a key
    * and IV size appropriate for your cipher
    * In this example we are using 256 bit AES (i.e. a 256 bit key). The
    * IV size for *most* modes is the same as the block size. For AES this
    * is 128 bits */
    if( 1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) )
        handleErrors("Context initialization error");


    char plaintext[LEN_MAX];
    char ciphertext[LEN_MAX];
    int bytes_read;

    while ((bytes_read = read(fd_in, ciphertext, sizeof(ciphertext))) > 0) {

        /* Provide the message to be decrypted, and obtain the plaintext output.
        * EVP_DecryptUpdate can be called multiple times if necessary
         */
        if( 1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, bytes_read))
            handleErrors("DecryptUpdate error");

        write (fd_out, plaintext, len);
    }

    /* Finalise the decryption. Further plaintext bytes may be written at
    * this stage.
    */
    if( 1 != EVP_DecryptFinal_ex(ctx, plaintext, &len) )
        handleErrors("DecryptFinal error");

    write(fd_out, plaintext, len);

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

}
