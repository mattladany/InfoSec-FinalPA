/*
Generate master keys and save to binary files
*/

#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

/* OpenSSL headers */
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
void main()
{
    uint8_t key[32] ;
    unsigned key_len = 32 ;
    int fd_key ;

    fd_key = open("amal_master_key.bin", O_WRONLY|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR) ;
    if( fd_key == -1 )
    {
        fprintf(stderr, "Unable to open file for key\n");
        exit(-1) ;
    }

    // Genrate the random amal master key
    RAND_bytes( key , key_len );
    write( fd_key , key , key_len );

    fd_key = open("basim_master_key.bin", O_WRONLY|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR) ;
    if( fd_key == -1 )
    {
        fprintf(stderr, "Unable to open file for key\n");
        exit(-1) ;
    }

    // Genrate the random basim master key
    RAND_bytes( key , key_len );
    write( fd_key, key, key_len );

    close( fd_key ) ;
}
