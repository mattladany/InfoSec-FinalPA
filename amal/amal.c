/*----------------------------------------------------------------------------
Final PA: Enhanced Needham-Shroeder Protocol Implementation

FILE:   amal.c

Written By:
     Matt Ladany

Submitted on: December 3, 2017
----------------------------------------------------------------------------*/


#include "../myCrypto.h"

int main ( int argc , char * argv[] )
{

    /* Initialise the crypto library */
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);

    if( argc < 6 )
    {
        printf("Missing command-line arguments: %s <ctrlFD> <dataFD>\n" , argv[0]) ;
        exit(-1) ;
    }
    int fd_write_kdc = atoi( argv[1] ) ;
    int fd_read_kdc = atoi( argv[2] );
    int fd_write_basim = atoi( argv[3] );
    int fd_read_basim = atoi( argv[4] );
    int fd_data = atoi( argv[5] ) ;

    FILE* log = fopen("amal/logAmal.txt" , "w" );
    if( ! log )
    {
        fprintf( stderr , "This is Amal. Could not create log file\n");
        exit(-1) ;
    }
    fprintf( log , "This is Amal. Will send write_kdc to FD %d, read_kdc from FD %d, send write_basim to FD %d, read_basim from FD %d, Data to FD %d\n",
                   fd_write_kdc, fd_read_kdc, fd_write_basim, fd_read_basim , fd_data );

    // Send ID of Amal, ID of Basim, and Nonce to KDC



    // Receive encrypted message from KDC, that holds the generated session
    //  key, as well as the message to send to Basim.



    // Send encrypted message from KDC, with another Nonce, to Basim



    // Receive message from Basim, encrypted by the session key



    // Send nonce recieved from Basim, back to him, after applying a function on it.




    EVP_cleanup();
    ERR_free_strings();

    close(fd_read_kdc);
    close(fd_write_kdc);
    close(fd_read_basim);
    close(fd_write_basim);
    close(fd_data);
    fclose( log ) ;

    return 0 ;
}

