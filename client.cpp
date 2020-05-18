#include <stdio.h>
#include <iostream>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <assert.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#define UPDATE_REQUEST 0
#define THMASTER_REQUEST 1
#define THCURRENT_PUBKEY 2
#define ADMINCURRENT_PUBKEY 3
#define FW_UPDATE 4
using namespace std;
#define ERROR(fmt) printf("%s:%d: \n" fmt, __FILE__, __LINE__);

class client_socket
{
    int sockfd;
    struct sockaddr_in serv_addr;
    struct hostent *server;

    char buffer[256];

public:
    void connect_tcp(char *ip, char *port)
    {

        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0)
            ERROR("ERROR opening socket");
        server = gethostbyname(ip);
        if (server == NULL)
        {
            ERROR("ERROR, no such host\n");
            exit(1);
        }

        bzero((char *)&serv_addr, sizeof(serv_addr));
        serv_addr.sin_family = AF_INET;
        bcopy((char *)server->h_addr, (char *)&serv_addr.sin_addr.s_addr, server->h_length);
        serv_addr.sin_port = htons(atoi(port));
        if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
        {
            ERROR("ERROR connecting");
            exit(1);
        }
    }

    int read_str(unsigned char *str, int size)
    {
        bzero(str, size);
        int bytes_read = 0;
        while (bytes_read != size)
        {
            int n = read(sockfd, str+bytes_read, size-bytes_read);
            if (n < 0)
            {
                ERROR("ERROR reading from socket");
                exit(1);
            }
            bytes_read+=n;
        }
        //printf("Message received: %s\n", str);
        return bytes_read;
    }

    int write_str(unsigned char *str, int size)
    {

        int n = write(sockfd, str, size);
        if (n < 0)
        {
            ERROR("ERROR writing to socket");
            exit(1);
        }
        return n;
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

    void close_tcp()
    {
        close(sockfd);
    }
};

class crypto_TH
{
    RSA *masterRSA = NULL, *AdminmasterRSA = NULL, *currentRSA = NULL, *AdmincurrentRSA = NULL;
    unsigned char *keyexchange_nonce;
    unsigned long exp = RSA_F4; //65537
    int keybits = 2048;

public:
    void load_masterkey()
    {
        FILE *fp = fopen("THMaster_pub.pem", "r");

        if (fp != NULL)
        {
            cout << "Keys found on disk, loading." << endl;
            masterRSA = PEM_read_RSAPublicKey(fp, NULL, NULL, NULL);
            fclose(fp);
            fp = fopen("THMaster_prv.pem", "r");
            if (fp == NULL)
            {
                ERROR("Private key missing on disk.");
                exit(1);
            }
            masterRSA = PEM_read_RSAPrivateKey(fp, &masterRSA, NULL, NULL);
            fclose(fp);

            //RSA_print_fp(stdout, masterRSA, 0);
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

        pub_bio = BIO_new_file("THMaster_pub.pem", "w");
        if (PEM_write_bio_RSAPublicKey(pub_bio, masterRSA) != 1)
        {
            ERROR("BIO Error");
            exit(1);
        }

        prv_bio = BIO_new_file("THMaster_prv.pem", "w");
        if (PEM_write_bio_RSAPrivateKey(prv_bio, masterRSA, NULL, NULL, 0, NULL, NULL) != 1)
        {
            ERROR("BIO Error");
            exit(1);
        }

        //RSA_print_fp(stdout, masterRSA, 0);

        BIO_free_all(pub_bio);
        BIO_free_all(prv_bio);
        BN_free(bn);
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

    void load_AdminMasterkey()
    {
        FILE *fp = fopen("ADMINMaster_pub.pem", "r");

        if (fp == NULL)
        {
            ERROR("Could not load the Admin master public key. This file should be in the same directory as the client executable");
            exit(1);
        }
        AdminmasterRSA = PEM_read_RSAPublicKey(fp, NULL, NULL, NULL);
        if (AdminmasterRSA == NULL)
        {
            ERROR("Error reading THmasterkey");
            exit(1);
        }
        fclose(fp);
    }

    void verify_THMasterkey_request(client_socket &sock, unsigned char *THMasterkey_request, int msgsize)
    {
        unsigned char *dec_nonce = (unsigned char *)malloc(16);

        if (RSA_private_decrypt(RSA_size(masterRSA), THMasterkey_request, dec_nonce, masterRSA, RSA_PKCS1_PADDING) == -1)
        {
            unsigned long errorTrack = ERR_get_error();
            char *errorChar = new char[256];
            errorChar = ERR_error_string(errorTrack, errorChar);
            cout << errorChar << endl;
            ERROR("RSA decrypt error");
            exit(1);
        }

        unsigned char *hash = (unsigned char *)malloc(SHA256_DIGEST_LENGTH);
        if (SHA256(dec_nonce, 16, hash) == NULL)
        {
            ERROR("Hashing Error");
            exit(1);
        }
        load_AdminMasterkey();
        if (RSA_verify(NID_sha256, hash, SHA256_DIGEST_LENGTH, THMasterkey_request + RSA_size(AdminmasterRSA), msgsize - RSA_size(AdminmasterRSA), AdminmasterRSA) != 1)
        {
            ERROR("Invalid signature created");
            exit(1);
        }
        cout << "Request received and verified\n";
        free(hash);
        keyexchange_nonce = dec_nonce;
    }

    unsigned char *send_THcurrentkey(client_socket &sock, int &payloadlen)
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

        unsigned char *enc_nonce = (unsigned char *)malloc(RSA_size(AdminmasterRSA));

        if (RSA_public_encrypt(16, keyexchange_nonce, enc_nonce, AdminmasterRSA, RSA_PKCS1_PADDING) == -1)
        {
            unsigned long errorTrack = ERR_get_error();
            char *errorChar = new char[256];
            errorChar = ERR_error_string(errorTrack, errorChar);
            cout << errorChar << endl;
            ERROR("RSA encrypt error");
            exit(1);
        }

        int outsize = RSA_size(AdminmasterRSA) + size + siglen;
        unsigned char *payload = (unsigned char *)malloc(outsize + 2);
        assert(size < 256 * 256);
        payload[1] = size % 256;
        payload[0] = size / 256;
        memcpy(payload + 2, enc_nonce, RSA_size(AdminmasterRSA));
        memcpy(payload + 2 + RSA_size(AdminmasterRSA), pkey_pem, size);
        memcpy(payload + 2 + RSA_size(AdminmasterRSA) + size, sigret, siglen);

        payloadlen = outsize + 2;

        free(enc_nonce);
        free(sigret);
        free(hash);
        free(for_hashing);
        free(pkey_pem);
        BIO_free_all(bio);
        return payload;
    }
    void verify_load_admincurrentkey(unsigned char *payload, int payloadlen)
    {
        int size = payload[1] + payload[0] * 256;

        unsigned char *dec_nonce = (unsigned char *)malloc(16);

        if (RSA_private_decrypt(RSA_size(currentRSA), payload + 2, dec_nonce, currentRSA, RSA_PKCS1_PADDING) == -1)
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
        memcpy(for_hashing + 16, payload + 2 + RSA_size(currentRSA), size);
        unsigned char *hash = (unsigned char *)malloc(SHA256_DIGEST_LENGTH);

        if (SHA256(for_hashing, 16 + size, hash) == NULL)
        {
            ERROR("Hashing Error");
            exit(1);
        }

        if (RSA_verify(NID_sha256, hash, SHA256_DIGEST_LENGTH, payload + 2 + RSA_size(currentRSA) + size, payloadlen - (2 + RSA_size(currentRSA) + size), AdminmasterRSA) != 1)
        {
            ERROR("Invalid signature.");
            exit(1);
        }

        BIO *bio = BIO_new_mem_buf((void *)(payload + 2 + RSA_size(currentRSA)), size);
        PEM_read_bio_RSAPublicKey(bio, &AdmincurrentRSA, 0, NULL);

        if (AdmincurrentRSA == NULL)
        {
            ERROR("Error loading THcurrent key");
            exit(1);
        }

        BIO_free_all(bio);
        free(for_hashing);
        free(hash);
        free(dec_nonce);
    }

    unsigned char *decrypt_update(unsigned char *payload, int payloadlen, int &updatelen)
    {
        cout << "Received update package of " << payloadlen << " bytes";
        return NULL;
    }
};

class FW_update_client
{

public:
    void update_sequence(crypto_TH &crypto, client_socket &sock)
    {
        TCP_send_update_request(sock);
        unsigned char *THMasterkey_request = NULL;
        int msgsize;
        THMasterkey_request = TCP_wait_for_THMasterkey_request(sock, msgsize);

        crypto.verify_THMasterkey_request(sock, THMasterkey_request, msgsize);
        crypto.gen_currentkey();
        int payloadlen;
        unsigned char *payload = crypto.send_THcurrentkey(sock, payloadlen);
        TCP_send_THcurrentkey(sock, payload, payloadlen);
        free(payload);
        payload = TCP_wait_for_currentkey(sock, payloadlen);
        crypto.verify_load_admincurrentkey(payload, payloadlen);
        free(payload);
        payload = TCP_receive_update_package(sock, payloadlen);
        int update_bin_len;
        unsigned char *update_bin = crypto.decrypt_update(payload, payloadlen, update_bin_len);
        free(payload);
    }

private:
    void TCP_send_update_request(client_socket &sock)
    {
        unsigned char *payload = (unsigned char *)malloc(5); //One byte for message type and four for message length.
        payload[0] = UPDATE_REQUEST;
        for (int i = 1; i <= 4; i++)
            payload[i] = 0;
        sock.write_str(payload, 5);
        free(payload);
    }
    unsigned char *TCP_wait_for_THMasterkey_request(client_socket &sock, int &payloadlen)
    {

        int ret;
        unsigned char *THMasterkey_request = sock.read_and_decapsulate(payloadlen, ret);
        if (ret != THMASTER_REQUEST)
        {
            ERROR("Invalid message received");
            exit(1);
        }
        if (THMasterkey_request == NULL)
        {
            ERROR("data null");
            exit(1);
        }
        return THMasterkey_request;
    }
    void TCP_send_THcurrentkey(client_socket &sock, unsigned char *payload, int payloadlen)
    {
        sock.encapsulate_and_write(payload, payloadlen, THCURRENT_PUBKEY);
    }
    unsigned char *TCP_wait_for_currentkey(client_socket &sock, int &payloadlen)
    {
        int payloadcode;
        unsigned char *payload = sock.read_and_decapsulate(payloadlen, payloadcode);
        if (payloadcode != ADMINCURRENT_PUBKEY)
        {
            ERROR("Invalid data");
            exit(1);
        }

        return payload;
    }

    unsigned char *TCP_receive_update_package(client_socket &sock, int &payloadlen)
    {
        int payloadcode;
        unsigned char *payload = sock.read_and_decapsulate(payloadlen, payloadcode);
        if (payloadcode != FW_UPDATE)
        {
            ERROR("Invalid data");
            exit(1);
        }

        return payload;
    }
};

int main(int argc, char *argv[])
{

    if (argc < 3)
    {
        fprintf(stderr, "usage %s hostname port\n", argv[0]);
        exit(0);
    }

    client_socket sock;
    sock.connect_tcp(argv[1], argv[2]);

    crypto_TH crypto;
    crypto.load_masterkey();

    FW_update_client update;
    update.update_sequence(crypto, sock);

    sock.close_tcp();
    return 0;
}