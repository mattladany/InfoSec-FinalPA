/*----------------------------------------------------------------------------
PA-02: Messaage Digest & Signature using Pipes
FILE:   myCrypto.c
Written By: 
     1- Matt Ladany
     2- Matt Bowles
     
Submitted on: November 12, 2017
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

size_t fileDigest( int fd_in , uint8_t *digest , int fd_save )
// Read all the incoming data from 'fd_in' file descriptor
// Compute the SHA256 hash value of this incoming data into the array 'digest'
// If the file descriptor 'fd_save' is > 0, store a copy of the incoming data to 'fd_save'
// Returns actual size in bytes of the computed hash value
//  printf(stderr, "%d\n", *size);
{
    uint8_t buffer[INPUT_CHUNK];
    EVP_MD_CTX *md_ctx;
    size_t bytes;
    unsigned int  mdLen = 0;
    
    if ( ! (md_ctx = EVP_MD_CTX_create() ) )
        handleErrors("EVP_MD_CTX_create failed");

    if( EVP_DigestInit(md_ctx, EVP_sha256()) != 1 )
        handleErrors("EVP_DigestInit failed");

    
    while(1)
    {
        bytes = read(fd_in, buffer, INPUT_CHUNK);

        if(bytes <= 0)
            break;

        if (EVP_DigestUpdate( md_ctx, buffer, bytes ) != 1) 
            handleErrors("EVP_DigestUpdate failed");            

        if ( fd_save > 0 )
            write(fd_save, buffer, bytes);
    }

    if ( 1 != EVP_DigestFinal_ex(md_ctx, digest, &mdLen) ) 
        handleErrors("EVP_DigestFinal failed");

    EVP_MD_CTX_destroy(md_ctx);

    return mdLen ;
}

//-----------------------------------------------------------------------------
int BN_write_fd(const BIGNUM *bn, int fd_out) {

    unsigned char buffer[64];
    int size = BN_bn2bin(bn, buffer);

    // Checking validity of BN_bn2bin
    if (size == -1) return 0;

    // Writing the size, and the value
    write(fd_out, &size, sizeof(int)); write(fd_out, buffer, size);
    return 1;
}


//-----------------------------------------------------------------------------
BIGNUM* BN_read_fd(int fd_in) {
    
    int size;
    int bytes_read = read(fd_in, &size, sizeof(int));

    // Asserting that something was read.
    if (bytes_read < 0) return NULL;

    char buffer[size];

    int bytes_read2 = read(fd_in, buffer, size);
    
    // Asserting that something was read.
    if (bytes_read2 == 0) return NULL;

    return BN_bin2bn(buffer, size, NULL);
}

//-----------------------------------------------------------------------------
BIGNUM* BN_myRandom(const BIGNUM* p) {

    // Big number to be randomly generated.
    BIGNUM* rand = BN_new();

    //Looping to generate the random number.
    do {
        BN_rand_range(rand, p);
    } while(BN_is_one(rand) || BN_is_zero(rand));

    return rand;
}


//-----------------------------------------------------------------------------
void elgamalSign(const uint8_t* digest, int len, const BIGNUM* q,
                 const BIGNUM* gen, const BIGNUM* x, BIGNUM* r, BIGNUM* s,
                 BN_CTX* ctx) {

    BIGNUM* bn = BN_new();
    if (!BN_mod_exp(bn, gen, x, q, ctx)) {
        fprintf(stderr, "The modular expression failed\n");
    }

    // Initializing new BIGNUM structs.
    BIGNUM* gcd = BN_new(); BIGNUM* qq = BN_new(); BIGNUM* k = BN_new();

    BN_sub(qq, q, BN_value_one());

    do {
        k = BN_myRandom(q);
        BN_gcd(gcd, k, qq, ctx);
    } while(!BN_is_one(gcd));

    BN_mod_exp(r, gen, k, q, ctx);
    BIGNUM* inv = BN_new();
    BN_mod_inverse(inv, k, qq, ctx);
    BN_mod_mul(s, x, r, qq, ctx);
    BN_set_negative(s, 3);
    BN_add_word(s, *digest);
    BN_mod_mul(s, inv, s, qq, ctx);
}

//-----------------------------------------------------------------------------
int elgamalValidate(const uint8_t* digest, int len, const BIGNUM* q,
                 const BIGNUM* gen, const BIGNUM* y, BIGNUM* r, BIGNUM* s,
                 BN_CTX* ctx) {

    BIGNUM* minus_one = BN_new();
    BN_sub(minus_one, q, BN_value_one());
    if (BN_cmp(r, minus_one) > -1 || BN_cmp(BN_value_one(), r) > -1) return 0;

    BIGNUM* mb = BN_new();
    BN_set_word(mb, *digest);
    BIGNUM* v1 = BN_new();
    BN_mod_exp(v1, gen, mb, q, ctx);
    
    BIGNUM* v2 = BN_new(); BIGNUM* t1 = BN_new(); BIGNUM* t2 = BN_new(); BIGNUM* t3 = BN_new();

    BN_mod_exp(v2, y, r, q, ctx);
    BN_mod_exp(t1, r, s, q, ctx);
    BN_mod_mul(v2, v2, t1, q, ctx);

    if (BN_cmp(v1, v2) == 0) return 1;

    return 0;
}

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
