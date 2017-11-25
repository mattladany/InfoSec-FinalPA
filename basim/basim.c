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

    FILE* log = fopen("basim/basim.log" , "w" );
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

    char database_item[] = "amal";

    // Receive message 3 from Amal

    fprintf(log, "Starting to receive message 3...\n");
    fflush(log);

    uint32_t message3_total_len;
    read(fd_read_ctrl, &message3_total_len, sizeof(uint32_t));
    uint32_t message3_iv_len;
    read(fd_read_ctrl,&message3_iv_len, sizeof(uint32_t));
    char message3_iv[message3_iv_len];
    read(fd_read_ctrl, message3_iv, message3_iv_len);


    uint32_t message3_encrypted_len;
    read(fd_read_ctrl, &message3_encrypted_len, sizeof(uint32_t));
    char message3_encrypted[message3_encrypted_len];
    read(fd_read_ctrl, message3_encrypted, message3_encrypted_len);
    uint32_t nonce_a2_len;
    read(fd_read_ctrl, &nonce_a2_len, sizeof(uint32_t));
    char nonce_a2[nonce_a2_len];
    read(fd_read_ctrl, nonce_a2, nonce_a2_len);

    fprintf(log, "Message 3 received.\n");
    
    // Opening up Basim's master key

    int basim_master_fd;
    char basim_master_key[32];
    basim_master_fd = open("basim_master_key.bin", O_RDONLY);
    read(basim_master_fd, basim_master_key, 32);
    close(basim_master_fd);

    // Decrypt the encrypted message

    fprintf(log, "Decrypting message 3.\n");

    char message3_decrypted[message3_encrypted_len];
    uint32_t message3_decrypted_len = decrypt(message3_encrypted, message3_encrypted_len, basim_master_key, message3_iv, message3_decrypted);

    fprintf(log, "Message 3 has been decrypted.\n");

    // Getting the session key
    uint32_t session_key_len;
    uint8_t session_key_len_array[4];

    memcpy(session_key_len_array, message3_decrypted, sizeof(uint32_t));
    session_key_len = *(uint32_t*)session_key_len_array;

    char session_key[session_key_len];
    memcpy(session_key, message3_decrypted+4, session_key_len);

    fprintf(log, "\nSession key:\n");
    BIO_dump(BIO_new_fp(log, BIO_NOCLOSE), session_key, session_key_len);     

    // Getting the ID of the sender that was encrypted by Basim's master key by the KDC.
    uint32_t id_rec_len;
    uint8_t id_rec_len_array[4];

    memcpy(id_rec_len_array, message3_decrypted+4+session_key_len, sizeof(uint32_t));
    id_rec_len = *(uint32_t*)id_rec_len_array;

    char id_rec[id_rec_len];
    memcpy(id_rec, message3_decrypted+4+session_key_len+4, id_rec_len);

    // Verifying the ID
    if (strncmp(database_item, id_rec, strlen(database_item)) != 0) {
        fprintf(log, "ID is not Amal. Exiting...\n");
        exit(-1);
    }

    fprintf(log, "\nID has been verified.\nStarting to construct message 4.\n");

    /***** Constructing Message 4. *****/
    // Generating Nonce_b
    uint32_t nonce_b_len = 32;
    uint8_t nonce_b[nonce_b_len];
    RAND_bytes(nonce_b, nonce_b_len);

    // TODO: Apply function on nonce_a2
    uint32_t f_nonce_a2_len = nonce_a2_len;
    char f_nonce_a2[f_nonce_a2_len];
    memcpy(f_nonce_a2, nonce_a2, f_nonce_a2_len);

    // Concatinating data and their sizes, together, to be encrypted.
    uint32_t message4_plain_len = 4 + f_nonce_a2_len + 4 + nonce_b_len;
    char message4_plain[message4_plain_len];
    memcpy(message4_plain, &f_nonce_a2_len, sizeof(uint32_t));
    memcpy(message4_plain+4, f_nonce_a2, f_nonce_a2_len);
    memcpy(message4_plain+4+f_nonce_a2_len, &nonce_b_len, sizeof(uint32_t));
    memcpy(message4_plain+4+f_nonce_a2_len+4, nonce_b, nonce_b_len);

    // Generate the IV to use for encrypting message4.
    uint32_t message4_iv_len = EVP_MAX_IV_LENGTH;
    uint8_t message4_iv[message4_iv_len];
    RAND_bytes(message4_iv, message4_iv_len);

    // Encrypt the plaintext for message 4 with the newly aquired session key.
    char message4_ciphertext[65536];
    uint32_t message4_ciphertext_len = encrypt(message4_plain, message4_plain_len,
        session_key, message4_iv, message4_ciphertext);

    fprintf(log, "Message 4 has been encrypted.\n");

    // Constructing Message 4.
    uint32_t message4_len = message4_ciphertext_len;
    char* message4 = calloc(1, message4_len);
    memcpy(message4, &message4_len, sizeof(uint32_t));
    memcpy(message4+4, message4, message4_len);

    // Send message 4 to Amal

    fprintf(log, "Sending message 4 to Amal...\n");
    fflush(log);
    write(fd_write_ctrl, message4, message4_len);
    fprintf(log, "Message 4 sent.\n");

    // Receive message 5 from Amal


    

    EVP_cleanup();
    ERR_free_strings();

    fclose( log ) ;
    close( fd_write_ctrl ) ;
    close( fd_read_ctrl  ) ;
    close( fd_data ) ;

    return 0 ;

}
