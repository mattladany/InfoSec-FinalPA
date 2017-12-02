/*-----------------------------------------------------------------------------
Final PA: Enhanced Needham-Shroeder Protocol Implementation

File:   kdc.c

Written By:
    Matt Ladany

Submitted on: December 3, 2017
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

    FILE* log = fopen("kdc/kdc.log", "w");
    if(!log) {
        fprintf(stderr, "This is the KDC. Could not create log file\n");
        exit(-1);
    }
    fprintf(log, "This is the KDC. Will send to FD %d, and will read from FD %d\n",
                  fd_write, fd_read);

    BIO* bio_fp = BIO_new_fp(log, BIO_NOCLOSE);

    char database_item1[] = "amal\0";
    char database_item2[] = "basim\0";


    // Receive message from Amal

    uint32_t id1_len;
    read(fd_read, &id1_len, sizeof(uint32_t));
    char id1[id1_len];
    read(fd_read, id1, id1_len);

    uint32_t id2_len;
    read(fd_read, &id2_len, sizeof(uint32_t));
    char id2[id2_len];
    read(fd_read, id2, id2_len);

    uint32_t nonce_a_len;
    read(fd_read, &nonce_a_len, sizeof(uint32_t));
    char nonce_a[nonce_a_len];
    read(fd_read, nonce_a, nonce_a_len);

    fprintf(log, "Message received from Amal.\n");
    fprintf(log, "ID1:\n");
    BIO_dump(bio_fp, id1, id1_len);
    fprintf(log, "ID2:\n");
    BIO_dump(bio_fp, id2, id2_len);
    fprintf(log, "Nonce_a:\n");
    BIO_dump(bio_fp, nonce_a, nonce_a_len);

    // Verify ID's
    if(strncmp(database_item1, id1, strlen(database_item1)) != 0) {
        fprintf(log, "ID1 is INVALID\n");
        exit(-1);
    }
    if(strncmp(database_item2, id2, strlen(database_item2)) != 0) {
        fprintf(log, "ID2 is INVALID\n");
        exit(-1);
    }

    fprintf(log, "\nID's have been validated. Generating symmetric key...\n");
    
    // Generating session key
    uint8_t session_key[32];
    unsigned session_key_len = 32;

    RAND_bytes(session_key, session_key_len);
    
    fprintf(log, "Session key generated. Value is:\n");
    BIO_dump(bio_fp, (const char*)session_key, session_key_len);
    

    // Generating the IV for the basim_master_key encryption
    char basim_iv[EVP_MAX_IV_LENGTH];
    unsigned basim_iv_len = EVP_MAX_IV_LENGTH;
    RAND_bytes(basim_iv, basim_iv_len);
    
    // Getting Basim's master key
    int basim_key_fd;
    char basim_master_key[32];

    basim_key_fd = open("basim_master_key.bin", O_RDONLY);
    if (basim_key_fd == -1) {
        fprintf(log, "Basim's master key could not be opened.\n");
        exit(-1);
    }

    read(basim_key_fd, basim_master_key, 32);
    close(basim_key_fd);

    // Constructing the partial message to be encrypted by Basim's master key
    uint32_t second_half_plain_size = 4+session_key_len+4+id1_len; 
    char second_half_plain[second_half_plain_size];
    memcpy(second_half_plain, &session_key_len, sizeof(uint32_t));
    memcpy(second_half_plain+4, session_key, session_key_len);
    memcpy(second_half_plain+4+session_key_len, &id1_len, sizeof(uint32_t));
    memcpy(second_half_plain+4+session_key_len+4, id1, id1_len);

    fprintf(log, "\nKs || IDa with their lengths:\n");
    BIO_dump(bio_fp, second_half_plain, second_half_plain_size);

    // Encrypting the second half with Basim's master key 
    char second_half_ciphertext[65536];
    uint32_t second_half_ciphertext_len = encrypt(second_half_plain, second_half_plain_size,
        basim_master_key, basim_iv, second_half_ciphertext);

    // Creating the second half of the message, with the IV and Ciphertext to be sent
    //  to Basim after decryption by Amal.
    uint32_t second_half_total_len = 4+EVP_MAX_IV_LENGTH+4+second_half_ciphertext_len;
    char second_half_total [second_half_total_len];
    memcpy(second_half_total, &basim_iv_len, sizeof(uint32_t));
    memcpy(second_half_total+4, basim_iv, basim_iv_len );
    memcpy(second_half_total+4+basim_iv_len, &second_half_ciphertext_len, sizeof(uint32_t));
    memcpy(second_half_total+4+basim_iv_len+4, second_half_ciphertext, second_half_ciphertext_len);


    // Getting Amal's master key
    int  amal_key_fd;
    char amal_master_key[32];

    amal_key_fd = open("amal_master_key.bin", O_RDONLY);
    if (amal_key_fd == -1) {
        fprintf(log, "Amal's master key could not be opened.\n");
        exit(-1);
    }

    read(amal_key_fd, amal_master_key, 32);
    close(amal_key_fd);

    // Generating the IV for the amal_master_key encryption.
    char amal_iv[EVP_MAX_IV_LENGTH];
    unsigned amal_iv_len = EVP_MAX_IV_LENGTH;
    RAND_bytes(amal_iv, amal_iv_len);


    // Constructing the entire message to be encrypted by Amal's master key.
    uint32_t message2_plain_len = 4+session_key_len+4+id2_len+4+nonce_a_len+4+second_half_total_len;
    char message2_plain[message2_plain_len];

    memcpy(message2_plain, &session_key_len, sizeof(uint32_t));
    memcpy(message2_plain+4, session_key, session_key_len);
    memcpy(message2_plain+4+session_key_len, &id1_len, sizeof(uint32_t));
    memcpy(message2_plain+4+session_key_len+4, id1, id1_len);
    memcpy(message2_plain+4+session_key_len+4+id1_len, &nonce_a_len, sizeof(uint32_t));
    memcpy(message2_plain+4+session_key_len+4+id1_len+4, nonce_a, nonce_a_len);
    memcpy(message2_plain+4+session_key_len+4+id1_len+4+nonce_a_len, &second_half_total_len, sizeof(uint32_t));
    memcpy(message2_plain+4+session_key_len+4+id1_len+4+nonce_a_len+4, second_half_total, second_half_total_len);

    fprintf(log, "\nMessage2 unencrypted:\n");
    BIO_dump(bio_fp, message2_plain, message2_plain_len);

    // Encrypting the full message.
    char full_ciphertext[65536];
    uint32_t full_ciphertext_len = encrypt(message2_plain, message2_plain_len, amal_master_key, amal_iv, full_ciphertext);

    // Constructing the message to be sent to Amal, with the IV and lengths of args, included.
    uint32_t message2_len = 4+amal_iv_len+4+full_ciphertext_len;
    char* message2 = calloc(1, message2_len);

    memcpy(message2, &amal_iv_len, sizeof(uint32_t));
    memcpy(message2+4, amal_iv, amal_iv_len);
    memcpy(message2+4+amal_iv_len, &full_ciphertext_len, sizeof(uint32_t));
    memcpy(message2+4+amal_iv_len+4, full_ciphertext, full_ciphertext_len);

    // Send encrypted message to Amal, with the new session key.
    
    fprintf(log, "Sending message 2 to Amal...\n");
    write(fd_write, message2, message2_len);
    fprintf(log, "Message sent. KDC Exiting...\n");

    EVP_cleanup();
    ERR_free_strings();

    close(fd_read);
    close(fd_write);
    fclose(log);

    return 0;
}
