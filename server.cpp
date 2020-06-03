#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <errno.h>
#include <sys/time.h>
#include <iostream>
#define ERROR(fmt) printf("%s:%d: \n" fmt, __FILE__, __LINE__);
char datetime[100];
char datetime2[100];
time_t t = time(NULL);
struct timeval tv;

#define AES_256_KEY_SIZE 32
#define AES_BLOCK_SIZE 16

#define UPDATE_REQUEST 0
#define THMASTER_REQUEST 1
#define THCURRENT_PUBKEY 2
#define ADMINCURRENT_PUBKEY 3
#define FW_UPDATE 4

using namespace std;

char *getDateTime()
{
    strftime(datetime, sizeof(datetime), "%Y-%m-%d %H:%M:%S", localtime(&t));
    gettimeofday(&tv, NULL);
    snprintf(datetime2, 100, "%s.%06ld", datetime, tv.tv_usec);

    return datetime2;
}
class socket_admin
{
private:
    socklen_t clilen;
    char buffer[256];
    struct sockaddr_in serv_addr, cli_addr;
    int sockfd, newsockfd, portno;

public:
    void init(long ip, long port)
    {
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0)
        {
            ERROR("ERROR opening socket");
            exit(1);
        }
        int temp_en = 1;
        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &temp_en, sizeof(int)) < 0)
            ERROR("setsockopt(SO_REUSEADDR) failed");

        bzero((char *)&serv_addr, sizeof(serv_addr));

        serv_addr.sin_family = AF_INET;
        serv_addr.sin_addr.s_addr = ip;
        serv_addr.sin_port = htons(port);

        if (bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
        {
            ERROR("ERROR on binding");
            exit(1);
        }

        listen(sockfd, 5);
        clilen = sizeof(cli_addr);
        newsockfd = accept(sockfd, (struct sockaddr *)&cli_addr, &clilen);

        if (newsockfd < 0)
        {
            ERROR("ERROR on accepting");
            exit(1);
        }
    }

    int read_str(unsigned char *str, int size)
    {
        bzero(str, size);
        int n = read(newsockfd, str, size);
        if (n < 0)
        {
            ERROR("ERROR reading from socket");
            exit(1);
        }
        //printf("Message received: %s\n", str);
        return n;
    }

    int write_str(unsigned char *str, int size)
    {
        /*

        int n = write(newsockfd, str, size);
        if (n < 0)
        {
            ERROR("ERROR writing to socket");
            exit(1);
        }
        return n;
*/
        int total_bytes_written = 0;
        while (total_bytes_written != size)
        {
            int bytes_written = write(newsockfd,
                                      str + total_bytes_written,
                                      size - total_bytes_written);
            if (bytes_written == -1)
            {
                ERROR("ERROR writing to socket");
                cout << strerror(errno);
                exit(1);
            }
            total_bytes_written += bytes_written;
        }
        return total_bytes_written;
    }
    void encapsulate_and_write(unsigned char *str, int len, int messagetype)
    {

        int outlen = 5 + len;
        unsigned char *payload = (unsigned char *)malloc(outlen);
        payload[0] = messagetype;
        if (len > 4294967290)
        {
            ERROR("Message too big to send");
            exit(1);
        }
        for (int i = 4; i >= 1; i--)
        {
            payload[i] = len % 256;
            len = len / 256;
        }

        memcpy(payload + 5, str, outlen - 5);

        if (write_str(payload, outlen) != outlen)
        {
            ERROR("Error writing to socket");
        }
        free(payload);
    }

    unsigned char *read_and_decapsulate(int &len, int &ret)
    {

        unsigned char *payload = (unsigned char *)malloc(5);
        read_str(payload, 5);
        ret = payload[0];
        len = payload[4] + 256 * payload[3] + 65536 * payload[2] + 16777216 * payload[1];
        free(payload);
        unsigned char *data = (unsigned char *)malloc(len);
        read_str(data, len);

        if (data == NULL)
        {
            ERROR("Could not read data");
            exit(1);
        }
        return data;
    }

    void close_tcp()
    {

        close(newsockfd);
        close(sockfd);
    }
};

class crypto_admin
{
    RSA *masterRSA = NULL, *THmasterRSA = NULL, *currentRSA = NULL, *THcurrentRSA = NULL;
    unsigned char aes_key[AES_256_KEY_SIZE];
    unsigned char aes_iv[AES_BLOCK_SIZE];
    unsigned char *keyexchange_nonce = NULL, *update_nonce = NULL;
    unsigned long exp = RSA_F4; //65537
    int keybits = 2048;

public:
    void load_masterkey()
    {
        FILE *fp = fopen("ADMINMaster_pub.pem", "r");

        if (fp != NULL)
        {
            cout << getDateTime() << "> Keys found on disk, loading." << endl;
            masterRSA = PEM_read_RSAPublicKey(fp, NULL, NULL, NULL);
            fclose(fp);
            fp = fopen("ADMINMaster_prv.pem", "r");
            if (fp == NULL)
            {
                ERROR("Private key missing on disk.");
                exit(1);
            }
            masterRSA = PEM_read_RSAPrivateKey(fp, &masterRSA, NULL, NULL);
            fclose(fp);

            // RSA_print_fp(stdout, masterRSA, 0);
        }
        else
        {
            gen_masterkey();
        }
    }

    void gen_masterkey()
    {
        BIO *pub_bio = NULL, *prv_bio = NULL;
        BIGNUM *bn;
        bn = BN_new();
        if (BN_set_word(bn, exp) != 1)
        {
            ERROR("BigNum Error");
            exit(1);
        }

        masterRSA = RSA_new();
        if (RSA_generate_key_ex(masterRSA, keybits, bn, NULL) != 1)
        {
            ERROR("RSA key gen error");
            exit(1);
        }

        pub_bio = BIO_new_file("ADMINMaster_pub.pem", "w");
        if (PEM_write_bio_RSAPublicKey(pub_bio, masterRSA) != 1)
        {
            ERROR("BIO Error");
            exit(1);
        }

        prv_bio = BIO_new_file("ADMINMaster_prv.pem", "w");
        if (PEM_write_bio_RSAPrivateKey(prv_bio, masterRSA, NULL, NULL, 0, NULL, NULL) != 1)
        {
            ERROR("BIO Error");
            exit(1);
        }
        cout << getDateTime() << "> Generated new Admin Master key. Please ensure that the file ADMINMaster_pub.pem is copied to root directory of the client" << endl;

        // RSA_print_fp(stdout, masterRSA, 0);

        BIO_free_all(pub_bio);
        BIO_free_all(prv_bio);
        BN_free(bn);
    }

    void load_THMasterkey()
    {
        FILE *fp = fopen("THMaster_pub.pem", "r");

        if (fp == NULL)
        {
            ERROR("Could not load the TH master public key. This file should be in the same directory as server executable");
            exit(1);
        }
        THmasterRSA = PEM_read_RSAPublicKey(fp, NULL, NULL, NULL);
        if (THmasterRSA == NULL)
        {
            ERROR("Error reading THmasterkey");
            exit(1);
        }
        fclose(fp);
    }

    void gen_currentkey()
    {

        BIGNUM *bn;
        bn = BN_new();
        if (BN_set_word(bn, exp) != 1)
        {
            ERROR("BigNum Error");
            exit(1);
        }

        currentRSA = RSA_new();
        if (RSA_generate_key_ex(currentRSA, keybits, bn, NULL) != 1)
        {
            ERROR("RSA key gen error");
            exit(1);
        }
        BN_free(bn);
    }
    unsigned char *sign_and_encrypt_nonce(int &sgd_enc_nonce_len)
    {
        keyexchange_nonce = (unsigned char *)malloc(16);
        if (RAND_bytes(keyexchange_nonce, 16) != 1)
        {
            ERROR("PRNG Error");
            exit(1);
        } //May fail if PRNG is not seeded properly

        unsigned char *hash = (unsigned char *)malloc(SHA256_DIGEST_LENGTH);
        if (SHA256(keyexchange_nonce, 16, hash) == NULL)
        {
            ERROR("Hashing Error");
            exit(1);
        }
        unsigned char *sigret = (unsigned char *)malloc(RSA_size(masterRSA));
        unsigned int siglen;
        if (RSA_sign(NID_sha256, hash, SHA256_DIGEST_LENGTH, sigret, &siglen, masterRSA) != 1)
        {
            ERROR("RSA signing error");
            exit(1);
        }
        if (RSA_verify(NID_sha256, hash, SHA256_DIGEST_LENGTH, sigret, siglen, masterRSA) != 1)
        {
            ERROR("Invalid signature created");
            exit(1);
        }

        unsigned char *enc_nonce = (unsigned char *)malloc(RSA_size(THmasterRSA));

        if (RSA_public_encrypt(16, keyexchange_nonce, enc_nonce, THmasterRSA, RSA_PKCS1_PADDING) == -1)
        {
            unsigned long errorTrack = ERR_get_error();
            char *errorChar = new char[256];
            errorChar = ERR_error_string(errorTrack, errorChar);
            cout << errorChar << endl;
            ERROR("RSA encrypt error");
            exit(1);
        }

        sgd_enc_nonce_len = RSA_size(THmasterRSA) + siglen;
        unsigned char *sgd_enc_nonce = (unsigned char *)malloc(sgd_enc_nonce_len);
        memcpy(sgd_enc_nonce, enc_nonce, RSA_size(THmasterRSA));
        memcpy(sgd_enc_nonce + RSA_size(THmasterRSA), sigret, siglen);

        free(enc_nonce);
        free(sigret);
        free(hash);
        return sgd_enc_nonce;
    }

    void verify_gen_currentkey(unsigned char *payload, int payloadlen)
    {
        int size = payload[1] + payload[0] * 256;

        unsigned char *dec_nonce = (unsigned char *)malloc(16);

        if (RSA_private_decrypt(RSA_size(masterRSA), payload + 2, dec_nonce, masterRSA, RSA_PKCS1_PADDING) == -1)
        {
            unsigned long errorTrack = ERR_get_error();
            char *errorChar = new char[256];
            errorChar = ERR_error_string(errorTrack, errorChar);
            cout << errorChar << endl;
            ERROR("RSA decrypt error");
            exit(1);
        }

        if (memcmp(dec_nonce, keyexchange_nonce, 16) != 0)
        {
            ERROR("Nonce mismatch. Possible MITM");
            exit(1);
        }
        unsigned char *for_hashing = (unsigned char *)malloc(16 + size);
        memcpy(for_hashing, dec_nonce, 16);
        memcpy(for_hashing + 16, payload + 2 + RSA_size(masterRSA), size);
        unsigned char *hash = (unsigned char *)malloc(SHA256_DIGEST_LENGTH);

        if (SHA256(for_hashing, 16 + size, hash) == NULL)
        {
            ERROR("Hashing Error");
            exit(1);
        }

        if (RSA_verify(NID_sha256, hash, SHA256_DIGEST_LENGTH, payload + 2 + RSA_size(masterRSA) + size, payloadlen - (2 + RSA_size(masterRSA) + size), THmasterRSA) != 1)
        {
            ERROR("Invalid signature.");
            exit(1);
        }

        BIO *bio = BIO_new_mem_buf((void *)(payload + 2 + RSA_size(masterRSA)), size);
        PEM_read_bio_RSAPublicKey(bio, &THcurrentRSA, 0, NULL);

        if (THcurrentRSA == NULL)
        {
            ERROR("Error loading THcurrent key");
            exit(1);
        }

        gen_currentkey();

        BIO_free_all(bio);
        free(for_hashing);
        free(hash);
        free(dec_nonce);
    }

    unsigned char *send_Admincurrentkey(int &payloadlen)
    {

        BIO *bio = BIO_new(BIO_s_mem());
        if (PEM_write_bio_RSAPublicKey(bio, currentRSA) != 1)
        {
            ERROR("PEM_write_bio_RSAPublicKey fail");
            exit(1);
        }
        unsigned char *pkey_pem;
        int size = BIO_get_mem_data(bio, &pkey_pem);

        if (size <= 0)
        {
            ERROR("Error getting public key");
            exit(1);
        }

        unsigned char *for_hashing = (unsigned char *)malloc(16 + size);

        memcpy(for_hashing, keyexchange_nonce, 16);
        memcpy(for_hashing + 16, pkey_pem, size);

        unsigned char *hash = (unsigned char *)malloc(SHA256_DIGEST_LENGTH);

        if (SHA256(for_hashing, 16 + size, hash) == NULL)
        {
            ERROR("Hashing Error");
            exit(1);
        }

        unsigned char *sigret = (unsigned char *)malloc(RSA_size(masterRSA));
        unsigned int siglen;
        if (RSA_sign(NID_sha256, hash, SHA256_DIGEST_LENGTH, sigret, &siglen, masterRSA) != 1)
        {
            ERROR("RSA signing error");
            exit(1);
        }
        if (RSA_verify(NID_sha256, hash, SHA256_DIGEST_LENGTH, sigret, siglen, masterRSA) != 1)
        {
            ERROR("Invalid signature created");
            exit(1);
        }

        unsigned char *enc_nonce = (unsigned char *)malloc(RSA_size(THcurrentRSA));

        if (RSA_public_encrypt(16, keyexchange_nonce, enc_nonce, THcurrentRSA, RSA_PKCS1_PADDING) == -1)
        {
            unsigned long errorTrack = ERR_get_error();
            char *errorChar = new char[256];
            errorChar = ERR_error_string(errorTrack, errorChar);
            cout << errorChar << endl;
            ERROR("RSA encrypt error");
            exit(1);
        }

        int outsize = RSA_size(THcurrentRSA) + size + siglen;
        unsigned char *payload = (unsigned char *)malloc(outsize + 2);
        assert(size < 256 * 256);
        payload[1] = size % 256;
        payload[0] = size / 256;
        memcpy(payload + 2, enc_nonce, RSA_size(THcurrentRSA));
        memcpy(payload + 2 + RSA_size(THcurrentRSA), pkey_pem, size);
        memcpy(payload + 2 + RSA_size(THcurrentRSA) + size, sigret, siglen);

        payloadlen = outsize + 2;

        free(enc_nonce);
        free(sigret);
        free(hash);
        free(for_hashing);
        free(pkey_pem);
        BIO_free_all(bio);
        return payload;
    }

    unsigned char *prepare_update(char *filename, int &payloadlen)
    {
        update_nonce = (unsigned char *)malloc(16);
        if (RAND_bytes(update_nonce, 16) != 1)
        {
            ERROR("PRNG Error");
            exit(1);
        } //May fail if PRNG is not seeded properly

        FILE *fp = fopen(filename, "rb");
        if (fp == NULL)
        {
            ERROR("Error opening update binary");
            exit(1);
        }

        unsigned char *contents;
        int filesize;
        std::fseek(fp, 0, SEEK_END);
        filesize = ftell(fp);
        contents = (unsigned char *)malloc(filesize + 16);
        rewind(fp);
        fread(&contents[0], sizeof(unsigned char), filesize, fp);
        fclose(fp);

        memcpy(contents + filesize, update_nonce, 16);

        unsigned char *hash = (unsigned char *)malloc(SHA256_DIGEST_LENGTH);

        if (SHA256(contents, 16 + filesize, hash) == NULL)
        {
            ERROR("Hashing Error");
            exit(1);
        }

        unsigned char *sigret = (unsigned char *)malloc(RSA_size(currentRSA));
        unsigned int siglen;
        if (RSA_sign(NID_sha256, hash, SHA256_DIGEST_LENGTH, sigret, &siglen, currentRSA) != 1)
        {
            ERROR("RSA signing error");
            exit(1);
        }

        if (RSA_verify(NID_sha256, hash, SHA256_DIGEST_LENGTH, sigret, siglen, currentRSA) != 1)
        {
            ERROR("Invalid signature created");
            exit(1);
        }

        unsigned char *for_aes = (unsigned char *)malloc(16 + filesize + siglen + 4);

        int fs = filesize;
        for (int i = 3; i >= 0; i--)
        {
            for_aes[i] = fs % 256;
            fs = fs / 256;
        }

        memcpy(for_aes + 4, contents, 16 + filesize);
        memcpy(for_aes + 16 + filesize + 4, sigret, siglen);
        free(contents);

        int fw_enc_len;
        unsigned char *fw_enc = AES_encrypt(for_aes, 16 + filesize + siglen + 4, fw_enc_len);

        unsigned char *enc_aes_key = (unsigned char *)malloc(RSA_size(THcurrentRSA));

        if (RSA_public_encrypt(AES_256_KEY_SIZE, aes_key, enc_aes_key, THcurrentRSA, RSA_PKCS1_PADDING) == -1)
        {
            unsigned long errorTrack = ERR_get_error();
            char *errorChar = new char[256];
            errorChar = ERR_error_string(errorTrack, errorChar);
            cout << errorChar << endl;
            ERROR("RSA encrypt error");
            exit(1);
        }

        payloadlen = fw_enc_len + RSA_size(THcurrentRSA) + AES_BLOCK_SIZE;
        cout << getDateTime() << "> AES Encrypting " << 16 + filesize + siglen + 4 << " bytes\n";
        unsigned char *payload = (unsigned char *)malloc(fw_enc_len + RSA_size(THcurrentRSA) + AES_BLOCK_SIZE);
        memcpy(payload, fw_enc, fw_enc_len);
        memcpy(payload + fw_enc_len, enc_aes_key, RSA_size(THcurrentRSA));
        memcpy(payload + fw_enc_len + RSA_size(THcurrentRSA), aes_iv, AES_BLOCK_SIZE);
        free(enc_aes_key);
        free(fw_enc);
        free(sigret);
        free(for_aes);
        free(hash);

        return payload;
    }

    unsigned char *AES_encrypt(unsigned char *for_aes, int for_aes_len, int &fw_enc_len)
    {

        unsigned char *fw_enc = (unsigned char *)malloc(for_aes_len + AES_BLOCK_SIZE);
        EVP_CIPHER_CTX *ctx;
        ctx = EVP_CIPHER_CTX_new();

        if (ctx == NULL)
        {
            ERROR("Error creating context");
            exit(1);
        }
        /*
        if (!EVP_CipherInit_ex(ctx, EVP_aes_256_cbc(), NULL, NULL, NULL, 1))
        {
            ERROR("Error initializing context");
            exit(1);
        }*/

        if (!RAND_bytes(aes_key, sizeof(aes_key)) || !RAND_bytes(aes_iv, sizeof(aes_iv)))
        {
            ERROR("RNG Error");
            exit(1);
        }

        if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, aes_iv))
        {
            ERROR("CTX error");
            exit(1);
        }

        assert(EVP_CIPHER_CTX_key_length(ctx) == AES_256_KEY_SIZE);
        assert(EVP_CIPHER_CTX_iv_length(ctx) == AES_BLOCK_SIZE);

        int len2;
        if (!EVP_EncryptUpdate(ctx, fw_enc, &len2, for_aes, for_aes_len))
        {
            ERROR("Error encrypting");
            exit(1);
        }
        fw_enc_len = len2;
        if (!EVP_EncryptFinal_ex(ctx, fw_enc + len2, &len2))
        {
            ERROR("EVP final error");
            exit(1);
        }

        fw_enc_len += len2;

        return fw_enc;
    }
};

class FW_update_server
{
public:
    void update_sequence(socket_admin &sock, crypto_admin &crypto)
    {
        TCP_wait_for_update_req(sock);
        cout << getDateTime() << "> Received. Sending encrypted request for client's current public key." << endl;
        TCP_send_currentkey_request(sock, crypto);
        int payloadlen;
        cout << getDateTime() << "> Waiting for client's current public key" << endl;
        unsigned char *payload = TCP_wait_for_currentkey(sock, payloadlen);
        cout << getDateTime() << "> Received. Verifying digital signature." << endl;
        crypto.verify_gen_currentkey(payload, payloadlen);
        cout << getDateTime() << "> Signature is valid." << endl;
        free(payload);
        payload = NULL;
        cout << getDateTime() << "> Sending server's current public key." << endl;
        payload = crypto.send_Admincurrentkey(payloadlen);
        TCP_send_Admincurrentkey(sock, payload, payloadlen);
        free(payload);
        char filename[] = "fw.bin";
        cout << getDateTime() << "> Preparing encrypted firmware update package." << endl;
        payload = crypto.prepare_update(filename, payloadlen);
        cout << getDateTime() << "> Sending the update package to client." << endl;
        TCP_send_update(sock, payload, payloadlen);
        free(payload);
    }

    void TCP_wait_for_update_req(socket_admin &sock)
    {

        cout << getDateTime() << "> Ready. Waiting for plaintext update request from client." << endl;
        unsigned char *payload = (unsigned char *)malloc(5);
        int psize = sock.read_str(payload, 5);
        if (psize != 5)
        {
            ERROR("Invalid header received");
            cout << psize;
            exit(1);
        }

        if (payload[0] == UPDATE_REQUEST)
        {

            free(payload);
            return;
        }
        else
        {
            ERROR("Out of sequence message");
            free(payload);
            exit(1);
        }
    }

    void TCP_send_currentkey_request(socket_admin &sock, crypto_admin &crypto)
    {
        //Call crypto to generate nonce, sign with Adminmaster private key, append the signature and encrypt with THmaster public key
        //Send this to TH and return
        crypto.load_THMasterkey();
        unsigned char *sgd_enc_nonce = NULL;
        int sgd_enc_nonce_len;
        sgd_enc_nonce = crypto.sign_and_encrypt_nonce(sgd_enc_nonce_len);

        sock.encapsulate_and_write(sgd_enc_nonce, sgd_enc_nonce_len, THMASTER_REQUEST);

        free(sgd_enc_nonce);
    }

    unsigned char *TCP_wait_for_currentkey(socket_admin &sock, int &payloadlen)
    {
        int payloadcode;
        unsigned char *payload = sock.read_and_decapsulate(payloadlen, payloadcode);
        if (payloadcode != THCURRENT_PUBKEY)
        {
            ERROR("Invalid data");
            exit(1);
        }

        return payload;
    }

    void TCP_send_Admincurrentkey(socket_admin &sock, unsigned char *payload, int payloadlen)
    {
        sock.encapsulate_and_write(payload, payloadlen, ADMINCURRENT_PUBKEY);
    }

    void TCP_send_update(socket_admin &sock, unsigned char *payload, int payloadlen)
    {

        sock.encapsulate_and_write(payload, payloadlen, FW_UPDATE);
    }
};
int main(int argc, char *argv[])
{

    if (argc < 2)
    {
        ERROR("Port not entered")
        exit(1);
    }

    while (1)
    {
        crypto_admin crypto;
        crypto.load_masterkey();
        FW_update_server update;
        socket_admin sock;
        sock.init(INADDR_ANY, atoi(argv[1]));

        update.update_sequence(sock, crypto);
        sock.close_tcp();
    }

    return 0;
}