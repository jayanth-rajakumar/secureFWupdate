#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#include <iostream>
#define ERROR(fmt) printf("%s:%d: \n" fmt, __FILE__, __LINE__);

#define UPDATE_REQUEST 0
#define THMASTER_REQUEST 1
#define THCURRENT_PUBKEY 2

using namespace std;

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

        int n = write(newsockfd, str, size);
        if (n < 0)
        {
            ERROR("ERROR writing to socket");
            exit(1);
        }
        return n;
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

    unsigned char *keyexchange_nonce = NULL, *update_nonce = NULL;
    unsigned long exp = RSA_F4; //65537
    int keybits = 2048;

public:
    void load_masterkey()
    {
        FILE *fp = fopen("ADMINMaster_pub.pem", "r");

        if (fp != NULL)
        {
            cout << "Keys found on disk, loading." << endl;
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

    }

    unsigned char * send_Admincurrentkey(int& payloadlen)
    {
        return NULL;
    }
};

class FW_update_server
{
public:
    void update_sequence(socket_admin &sock, crypto_admin &crypto)
    {
        TCP_wait_for_update_req(sock);
        TCP_send_currentkey_request(sock, crypto);
        int payloadlen;
        unsigned char *payload = TCP_wait_for_currentkey(sock, payloadlen);
        crypto.verify_gen_currentkey(payload, payloadlen);
        free(payload);
        payload=NULL;
        payload=crypto.send_Admincurrentkey(payloadlen);

        
    }

    void TCP_wait_for_update_req(socket_admin &sock)
    {
        unsigned char *payload = (unsigned char *)malloc(5);
        int psize = sock.read_str(payload, 5);
        if (psize != 5)
        {
            ERROR("Invalid header received");
            exit(1);
        }

        if (payload[0] == UPDATE_REQUEST)
        {
            cout << "Update Request received." << endl;
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
};
int main(int argc, char *argv[])
{

    if (argc < 2)
    {
        ERROR("Port not entered")
        exit(1);
    }
    crypto_admin crypto;
    crypto.load_masterkey();

    socket_admin sock;
    sock.init(INADDR_ANY, atoi(argv[1]));

    FW_update_server update;
    update.update_sequence(sock, crypto);

    sock.close_tcp();
    return 0;
}