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
    int fd_write_iv = atoi( argv[5] );
    int fd_data = atoi( argv[6] ) ;

    FILE* log = fopen("amal/amal.log" , "w" );
    if( ! log )
    {
        fprintf( stderr , "This is Amal. Could not create log file\n");
        exit(-1) ;
    }
    fprintf( log , "This is Amal. Will send write_kdc to FD %d, read_kdc from FD %d, send write_basim to FD %d, read_basim from FD %d, write_iv to FD %d, data to FD %d\n",
                   fd_write_kdc, fd_read_kdc, fd_write_basim, fd_read_basim , fd_write_iv , fd_data );

    // Send ID of Amal, ID of Basim, and Nonce to KDC

    char amal_name[] = "amal\0";
    uint32_t amal_name_size = strlen(amal_name) + 1;
    char basim_name[] = "basim\0";
    uint32_t basim_name_size = strlen(basim_name) + 1;

    const int INT_SIZE = 4;

    uint8_t nonce_a[32];
    unsigned nonce_a_len = 32;

    uint32_t message1_len = INT_SIZE+amal_name_size + INT_SIZE+basim_name_size + INT_SIZE+nonce_a_len;
    char message1[message1_len];

    // Generating random bytes to for the nonce
    RAND_bytes(nonce_a, nonce_a_len);

    memcpy(message1, &amal_name_size, sizeof(uint32_t));
    memcpy(message1+INT_SIZE, amal_name, amal_name_size);
    memcpy(message1+INT_SIZE+amal_name_size, &basim_name_size, sizeof(uint32_t));
    memcpy(message1+INT_SIZE+amal_name_size+INT_SIZE, basim_name, basim_name_size);
    memcpy(message1+INT_SIZE+amal_name_size+INT_SIZE+basim_name_size, &nonce_a_len, INT_SIZE);
    memcpy(message1+INT_SIZE+amal_name_size+INT_SIZE+basim_name_size+INT_SIZE, nonce_a, nonce_a_len);
 
    fprintf(log, "Sending session key generation request to the KDC...\n");
    write(fd_write_kdc, message1, message1_len);

    fprintf(log, "-----------------------------------\n");

    // Receive encrypted message from KDC, that holds the generated session
    //  key, as well as the message to send to Basim.

    uint32_t iv1_len;
    read(fd_read_kdc, &iv1_len, sizeof(uint32_t));
    char iv1[iv1_len];
    read(fd_read_kdc, iv1, iv1_len);
    uint32_t message2_encrypted_len;
    read(fd_read_kdc, &message2_encrypted_len, sizeof(uint32_t));
    char message2_encrypted[message2_encrypted_len];
    read(fd_read_kdc, message2_encrypted, message2_encrypted_len);

    fprintf(log, "Message 2 received from the KDC\n");

    // Getting up amal's master key
    int amal_master_fd;
    amal_master_fd = open("amal_master_key.bin", O_RDONLY);
    
    char amal_master_key[32];
    read(amal_master_fd, amal_master_key, 32);

    close(amal_master_fd);

    // Decrypting the message received
    char message2_decrypted[message2_encrypted_len];
    uint32_t message2_decrypted_len = decrypt(message2_encrypted, message2_encrypted_len,
        amal_master_key, iv1, message2_decrypted);

    fprintf(log, "Message 2 decrypted.\n");

    /*****  Reading the decrypted message *****/
    // Getting the session key
    uint32_t session_key_len;
    uint8_t session_key_len_array[4];

    memcpy(session_key_len_array, message2_decrypted, sizeof(uint32_t));
    session_key_len = *(uint32_t*)session_key_len_array;

    char session_key[session_key_len];
    memcpy(session_key, message2_decrypted+4, session_key_len);

    fprintf(log, "\nSession Key:\n");
    BIO_dump(BIO_new_fp(log, BIO_NOCLOSE), session_key, session_key_len);

    // Getting the ID back
    uint32_t id_rec_len;
    uint8_t id_rec_len_array[4];

    memcpy(id_rec_len_array, message2_decrypted+4+session_key_len, sizeof(uint32_t));
    id_rec_len = *(uint32_t*)id_rec_len_array;

    char id_rec[id_rec_len];
    memcpy(id_rec, message2_decrypted+4+session_key_len+4, id_rec_len);

    // Verifying the ID matches the sender of Message 1...
    if (strncmp(amal_name, id_rec, amal_name_size) != 0) {
        fprintf(log, "ID recieved from the KDC is not Amal. Exiting...\n");
        exit(-1);
    }

    fprintf(log, "\nID verified.\n");

    // Getting the Nonce back
    uint32_t nonce_a_rec_len;
    uint8_t nonce_a_rec_len_array[4];

    memcpy(nonce_a_rec_len_array, message2_decrypted+4+session_key_len+4+id_rec_len, sizeof(uint32_t));
    nonce_a_rec_len = *(uint32_t*)nonce_a_rec_len_array;

    char nonce_a_rec[nonce_a_rec_len];
    memcpy(nonce_a_rec, message2_decrypted+4+session_key_len+4+id_rec_len+4, nonce_a_rec_len);

    // Verifying nonce_a matches the received nonce from the KDC...
    size_t i;
    for (i = 0; i < nonce_a_len; i++) {
        if (strncmp(nonce_a+i, nonce_a_rec+i, 1) != 0) {
            fprintf(log, "Nonce received is not equivalent to the original Nonce. Exiting...\n");
            exit(-1);
        }
    }

    fprintf(log, "Nonce received from KDC verified.\n");

    // Getting the encryption section in Message 2 to send to Basim.
    uint32_t message3_data_len;
    uint8_t message3_data_len_array[4];

    memcpy(message3_data_len_array,
        message2_decrypted+4+session_key_len+4+id_rec_len+4+nonce_a_rec_len,
        sizeof(uint32_t));
    message3_data_len = *(uint32_t*)message3_data_len_array;

    char message3_data[message3_data_len];
    memcpy(message3_data,
        message2_decrypted+4+session_key_len+4+id_rec_len+4+nonce_a_rec_len+4,
        message3_data_len);

    // Generating another nonce, to be sent to Basim
    uint32_t nonce_a2_len = 32;
    char nonce_a2[nonce_a2_len];

    RAND_bytes(nonce_a2, nonce_a2_len);

    fprintf(log, "Nonce_a2 generated.\n");
    fflush(log);

    // Constructing message 3
    uint32_t message3_len = 4+message3_data_len+4+nonce_a2_len;
    char* message3 = calloc(1, message3_len);

    memcpy(message3, &message3_data_len, sizeof(uint32_t));
    memcpy(message3+4, message3_data, message3_data_len);
    memcpy(message3+4+message3_data_len, &nonce_a2_len, sizeof(uint32_t));
    memcpy(message3+4+message3_data_len+4, nonce_a2, nonce_a2_len);

    // Send encrypted message from KDC, with another Nonce, to Basim

    fprintf(log, "Sending message 3 to Basim...\n");
    write(fd_write_basim, message3, message3_len);
    fprintf(log, "Message 3 sent.\n");

    fprintf(log, "-----------------------------------\n");
    fflush(log);
    // Receive message from Basim, encrypted by the session key


    uint32_t message4_iv_len;
    read(fd_read_basim, &message4_iv_len, sizeof(uint32_t));
    uint8_t message4_iv[message4_iv_len];
    read(fd_read_basim, message4_iv, message4_iv_len);
    uint32_t message4_ciphertext_len;
    read(fd_read_basim, &message4_ciphertext_len, sizeof(uint32_t));
    char message4_ciphertext[message4_ciphertext_len];
    read(fd_read_basim, message4_ciphertext, message4_ciphertext_len);

    fprintf(log, "Message 4 received.\n");

    // Decrypting message 4.
    char message4_plain[message4_ciphertext_len];
    uint32_t message4_plain_len = decrypt(message4_ciphertext, message4_ciphertext_len, session_key, message4_iv, message4_plain);

    fprintf(log, "Message 4 decrypted.\n");

    // Getting nonce_a2 with the applied function
    uint32_t f_nonce_a2_rec_len;
    uint8_t f_nonce_a2_rec_len_array[4];

    memcpy(f_nonce_a2_rec_len_array, message4_plain, sizeof(uint32_t));
    f_nonce_a2_rec_len = *(uint32_t*)f_nonce_a2_rec_len_array;

    char f_nonce_a2_rec[f_nonce_a2_rec_len];
    memcpy(f_nonce_a2_rec, message4_plain+4, f_nonce_a2_rec_len);

    // TODO: Reverse the function applied, to get the original nonce.

    uint32_t nonce_a2_rec_len = f_nonce_a2_rec_len;
    uint8_t nonce_a2_rec[nonce_a2_rec_len];
    memcpy(nonce_a2_rec, f_nonce_a2_rec, nonce_a2_rec_len);

    // Verify nonce_a2 is the same as nonce_a2_rec
    for (i = 0; i < nonce_a2_len; i++) {
        if (strncmp(nonce_a2+i, nonce_a2_rec+i, 1) != 0) {
            fprintf(log, "Nonce received is not equivalent to the original Nonce. Exiting...\n");
            exit(-1);
        }
    }

    fprintf(log, "Nonce_a2 has been verified.\nBasim has now been authenticated.\nStarting to construct message 5.\n");

    // Getting nonce_b sent by Basim.
    uint32_t nonce_b_rec_len;
    uint8_t nonce_b_rec_len_array[4];

    memcpy(nonce_b_rec_len_array, message4_plain+4+f_nonce_a2_rec_len, sizeof(uint32_t));
    nonce_b_rec_len = *(uint32_t*)nonce_b_rec_len_array;

    char nonce_b_rec[nonce_b_rec_len];
    memcpy(nonce_b_rec, message4_plain+4+f_nonce_a2_rec_len+4, nonce_b_rec_len);

    // TODO: Apply function on nonce_b
    uint32_t f_nonce_b_len = nonce_b_rec_len;
    char f_nonce_b[f_nonce_b_len];
    memcpy(f_nonce_b, nonce_b_rec, f_nonce_b_len);

    // Constructing the plaintext for message 5, to be encrypted.
    uint32_t message5_plain_len = 4+f_nonce_b_len;
    char message5_plain[message5_plain_len];
    memcpy(message5_plain, &f_nonce_b_len, sizeof(uint32_t));
    memcpy(message5_plain+4, f_nonce_b, f_nonce_b_len);

    // Generating IV for encrypting message 5.
    uint32_t m5_iv_len = EVP_MAX_IV_LENGTH;
    char m5_iv[m5_iv_len];
    RAND_bytes(m5_iv, m5_iv_len);

    // Encrypting the message 5 plaintext.
    char message5_ciphertext[65536];
    uint32_t message5_ciphertext_len = encrypt(message5_plain, message5_plain_len,
        session_key, m5_iv, message5_ciphertext);

    // Constructing message 5.
    uint32_t message5_len = 4+m5_iv_len+4+message5_ciphertext_len;
    char* message5 = calloc(1, message5_len);

    memcpy(message5, &m5_iv_len, sizeof(uint32_t));
    memcpy(message5+4, m5_iv, m5_iv_len);
    memcpy(message5+4+m5_iv_len, &message5_ciphertext_len, sizeof(uint32_t));
    memcpy(message5+4+m5_iv_len+4, message5_ciphertext, message5_ciphertext_len);

    // Send nonce recieved from Basim, back to him, after applying a function on it.

    fprintf(log, "Sending message 5 to Basim...\n");
    write(fd_write_basim, message5, message5_len);
    fprintf(log, "Message 5 sent.\n");

    // Opening up the bunny.mp4 file
    int fd_in = open("amal/bunny.mp4", O_RDONLY, S_IRUSR | S_IWUSR);
    if (fd_in == -1) {
        fprintf(log, "Could not open the bunny.mp4 file.\n");
        exit(-1);
    }

    fprintf(log, "-----------------------------------\n");

    // Generating the IV for the bunny.mp4 encryption
    uint32_t data_iv_len = EVP_MAX_IV_LENGTH;
    char data_iv[data_iv_len];
    RAND_bytes(data_iv, data_iv_len);

    uint32_t iv_message_len = 4+data_iv_len;
    char* iv_message = calloc(1, iv_message_len);
    memcpy(iv_message, &data_iv_len, sizeof(uint32_t));
    memcpy(iv_message+4, data_iv, data_iv_len);

    fprintf(log, "Sending IV for bunny.mp4 encryption, to Basim.\n");
    write(fd_write_iv, iv_message, iv_message_len);
    fprintf(log, "IV sent.\n");
 
    // Sending encrypted bunny.mp4 file to Basim
//    fprintf(log, "Sending bunny.mp4 to Basim, encrypted by the session key.\n");
//    fflush(log);
//    encryptFile(fd_in, fd_data, session_key, data_iv);
//    fprintf(log, "Bunny file sent.\n");

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

