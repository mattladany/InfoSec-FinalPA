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
    int fd_read_iv = atoi( argv[3] ) ;
    int fd_data = atoi( argv[4] ) ;

    FILE* log = fopen("basim/basim.log" , "w" );
    if( ! log )
    {
        fprintf( stderr , "This is Basim. Could not create log file\n");
        exit(-1) ;
    }
    fprintf( log , "This is Basim. Will receive read_ctrl from FD %d, write_ctrl to FD %d, read_iv from FD %d, data from FD %d\n" ,
                    fd_read_ctrl , fd_write_ctrl , fd_read_iv , fd_data );

    int fd_out = open("basim/bunny.mp4" , O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR ) ;
    if( fd_out == -1 )
    {
        fprintf( stderr , "This is Basim. Could not open output file\n");
        exit(-1) ;
    }

    BIO* bio_fp = BIO_new_fp(log, BIO_NOCLOSE);

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

    fprintf(log, "Message 3 received. IV for encrypted chunk:\n");
    BIO_dump(bio_fp, message3_iv, message3_iv_len);
    fprintf(log, "Message 3 encrypted chunck:\n");
    BIO_dump(bio_fp, message3_encrypted, message3_encrypted_len);
    fprintf(log, "Nonce received in message 3:\n");
    BIO_dump(bio_fp, nonce_a2, nonce_a2_len);

    // Opening up Basim's master key

    int basim_master_fd;
    char basim_master_key[32];
    basim_master_fd = open("basim_master_key.bin", O_RDONLY);
    read(basim_master_fd, basim_master_key, 32);
    close(basim_master_fd);

    // Decrypt the encrypted message

    fprintf(log, "\nDecrypting message 3.\n");

    char message3_decrypted[message3_encrypted_len];
    uint32_t message3_decrypted_len = decrypt(message3_encrypted, message3_encrypted_len, basim_master_key, message3_iv, message3_decrypted);

    fprintf(log, "Message 3 has been decrypted:\n");
    BIO_dump(bio_fp, message3_decrypted, message3_decrypted_len);

    // Getting the session key
    uint32_t session_key_len;
    uint8_t session_key_len_array[4];

    memcpy(session_key_len_array, message3_decrypted, sizeof(uint32_t));
    session_key_len = *(uint32_t*)session_key_len_array;

    char session_key[session_key_len];
    memcpy(session_key, message3_decrypted+4, session_key_len);

    fprintf(log, "\nSession key:\n");
    BIO_dump(bio_fp, session_key, session_key_len);     

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
    fprintf(log, "---------------------------------------------------------\n");

    /***** Constructing Message 4. *****/
    // Generating Nonce_b

    BIGNUM* nonce_b_bn = BN_new();
    BN_rand(nonce_b_bn, 256, -1, 0);
    uint32_t nonce_b_len = BN_num_bytes(nonce_b_bn);
    char nonce_b[nonce_b_len];
    BN_bn2bin(nonce_b_bn, nonce_b);
 
    // Apply function on nonce_a2

    BIGNUM* nonce_a2_bn = BN_new();
    BN_bin2bn(nonce_a2, nonce_a2_len, nonce_a2_bn);
    BIGNUM* one = BN_new();
    BN_one(one);
    BN_add(nonce_a2_bn, nonce_a2_bn, one);


    uint32_t f_nonce_a2_len = BN_num_bytes(nonce_a2_bn);
    char f_nonce_a2[f_nonce_a2_len];
    //memcpy(f_nonce_a2, nonce_a2, f_nonce_a2_len);

    BN_bn2bin(nonce_a2_bn, f_nonce_a2);


    // Concatinating data and their sizes, together, to be encrypted.
    uint32_t message4_plain_len = 4 + f_nonce_a2_len + 4 + nonce_b_len;
    char message4_plain[message4_plain_len];
    memcpy(message4_plain, &f_nonce_a2_len, sizeof(uint32_t));
    memcpy(message4_plain+4, f_nonce_a2, f_nonce_a2_len);
    memcpy(message4_plain+4+f_nonce_a2_len, &nonce_b_len, sizeof(uint32_t));
    memcpy(message4_plain+4+f_nonce_a2_len+4, nonce_b, nonce_b_len);

    fprintf(log, "Message 4 unencrypted:\n");
    BIO_dump(bio_fp, message4_plain, message4_plain_len);

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
    uint32_t message4_len = 4+message4_iv_len+4+message4_ciphertext_len;
    char message4[message4_len];
    memcpy(message4, &message4_iv_len, sizeof(uint32_t));
    memcpy(message4+4, message4_iv, message4_iv_len);
    memcpy(message4+4+message4_iv_len, &message4_ciphertext_len, sizeof(uint32_t));
    memcpy(message4+4+message4_iv_len+4, message4_ciphertext, message4_len);

    // Send message 4 to Amal

    fprintf(log, "Sending message 4 to Amal...\n");
    fflush(log);
    write(fd_write_ctrl, message4, message4_len);
    fprintf(log, "Message 4 sent.\n");
    fprintf(log, "---------------------------------------------------------\n");

    // Receive message 5 from Amal
    uint32_t m5_iv_len;
    read(fd_read_ctrl, &m5_iv_len, sizeof(uint32_t));
    char m5_iv[m5_iv_len];
    read(fd_read_ctrl, m5_iv, m5_iv_len);

    uint32_t message5_ciphertext_len;
    read(fd_read_ctrl, &message5_ciphertext_len, sizeof(uint32_t));
    char message5_ciphertext[message5_ciphertext_len];
    read(fd_read_ctrl, message5_ciphertext, message5_ciphertext_len);

    fprintf(log, "Message 5 received.\n");

    // Decrypting the ciphertext received in message 5.
    char message5_plain[message5_ciphertext_len];
    uint32_t message5_plain_len = decrypt(message5_ciphertext, message5_ciphertext_len,
        session_key, m5_iv, message5_plain);

    fprintf(log, "Message 5 decrypted:\n");
    BIO_dump(bio_fp, message5_plain, message5_plain_len);

    // Getting f_nonce_b_rec from message 5.
    uint32_t f_nonce_b_rec_len;
    uint8_t f_nonce_b_rec_len_array[4];

    memcpy(f_nonce_b_rec_len_array, message5_plain, sizeof(uint32_t));
    f_nonce_b_rec_len = *(uint32_t*)f_nonce_b_rec_len_array;

    char f_nonce_b_rec[f_nonce_b_rec_len];
    memcpy(f_nonce_b_rec, message5_plain+4, f_nonce_b_rec_len);

    // Reversing the applied function on f_nonce_b_rec

    BIGNUM* nonce_b_rec_bn = BN_new();
    BN_bin2bn(f_nonce_b_rec, f_nonce_b_rec_len, nonce_b_rec_bn);
    BN_sub(nonce_b_rec_bn, nonce_b_rec_bn, one);

    // Verifying that nonce_b_rec is equivalent to nonce_b
    if(BN_cmp(nonce_b_bn, nonce_b_rec_bn) != 0) {
        fprintf(log, "Nonce received is not equivalent to the original nonce. Exiting...\n");
        exit(-1);
    }

    fprintf(log, "Nonce_b has been verified.\n");
    fprintf(log, "Amal has now been authenticated.\n");
    fprintf(log, "Secure, authenticated communication can now exist between Amal and Basim\n");
    fprintf(log, "---------------------------------------------------------\n");

    // Receiving the IV from Amal for the encrypted bunny.mp4 file.
    fprintf(log, "Receiving the IV from Amal for the encrypted bunny.mp4 file.\n");
    uint32_t iv_data_len;
    read(fd_read_iv, &iv_data_len, sizeof(uint32_t));
    char iv_data[iv_data_len];
    read(fd_read_iv, iv_data, iv_data_len);
    fprintf(log, "IV received.\n");

    // Getting and decrypting the file.
    decryptFile(fd_data, fd_out, session_key, iv_data);

    fprintf(log, "File Decrypted\n");
    EVP_cleanup();
    ERR_free_strings();

    fclose( log ) ;
    close( fd_write_ctrl ) ;
    close( fd_read_ctrl  ) ;
    close( fd_read_iv ) ;
    close( fd_data ) ;

    return 0 ;

}
