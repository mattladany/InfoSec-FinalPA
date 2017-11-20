/*----------------------------------------------------------------------------
Final PA: Enhanced Needham-Shroeder Protocol Implementation

FILE:   basim.c

Written By:
     1- Matt Ladany
Submitted on: November 12, 2017
----------------------------------------------------------------------------*/

#include "../myCrypto.h"


int main ( int argc , char * argv[] )
{

    /* Initialise the crypto library */
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);

    if( argc < 4 )
    {
        printf("Missing command-line arguments: %s <ctrlFD> <dataFD>\n" , argv[0]) ;
        exit(-1) ;
    }
    int fd_read_ctrl = atoi( argv[1] ) ;
    int fd_write_ctrl = atoi( argv[2] ) ;
    int fd_data = atoi( argv[3] ) ;

    FILE* log = fopen("basim/logBasim.txt" , "w" );
    if( ! log )
    {
        fprintf( stderr , "This is Basim. Could not create log file\n");
        exit(-1) ;
    }
    fprintf( log , "This is Basim. Will receive read_ctrl from FD %d, write_ctrl to FD %d, data from FD %d\n" ,
                    fd_read_ctrl , fd_write_ctrl , fd_data );

    int fd_out = open("basim/bunny.mp4" , O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR ) ;
    if( fd_out == -1 )
    {
        fprintf( stderr , "This is Basim. Could not open output file\n");
        exit(-1) ;
    }



    EVP_cleanup();
    ERR_free_strings();

    fclose( log ) ;
    close( fd_write_ctrl ) ;
    close( fd_read_ctrl  ) ;
    close( fd_data ) ;

    return 0 ;

}
