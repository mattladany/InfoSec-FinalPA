/*-----------------------------------------------------------------------------
Final PA: Enhanced Needham-Shroeder Protocol Implementation

File:   kdc.c

Written By:
    Matt Ladany

Submitted on: December 3. 2017
-----------------------------------------------------------------------------*/

#include "../myCrypto.h"

int main(int argc, char* argv[]) {

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);

    if( argc < 3 )
    {
        printf("Missing command-line arguments: %s <ctrlFD> <dataFD>\n" , argv[0]) ;
        exit(-1);
    }
    
    int fd_read = atoi(argv[1]);
    int fd_write = atoi(argv[2]);

    FILE* log = fopen("kdc/logKDC.txt", "w");
    if(!log) {
        fprintf(stderr, "This is the KDC. Could not create log file\n");
        exit(-1);
    }
    fprintf(log, "This is the KDC. Will send to FD %d, and will read from FD %d\n",
                  fd_write, fd_read);


    // Receive message from Amal, encrypted by Amal's master key.



    // Send encrypted message to Amal, with the new session key.


    EVP_cleanup();
    ERR_free_strings();

    close(fd_read);
    close(fd_write);
    fclose(log);

    return 0;
}
