#include <stdio.h>
#include <iostream>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

#define UPDATE_REQUEST 0
#define THMASTER_REQUEST 1

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
        int n = read(sockfd, str, size);
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

        int n = write(sockfd, str, size);
        if (n < 0)
        {
            ERROR("ERROR writing to socket");
            exit(1);
        }
        return n;
    }

    int read_and_decapsulate(unsigned char *data, int &len)
    {

        unsigned char *payload = (unsigned char *)malloc(5);
        read_str(payload, 5);
        int ret = payload[0];
        len = payload[4] + 256 * payload[3] + 65536 * payload[2] + 16777216 * payload[1];
        free(payload);
        data = (unsigned char *)malloc(len);
        read_str(data, len);

        return ret;
    }

    void close_tcp()
    {
        close(sockfd);
    }
};

class crypto_TH
{
    RSA *masterRSA = NULL;
    unsigned long exp = RSA_F4; //65537
    int keybits = 2048;

public:
    int load_masterkey()
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
};

class FW_update_client
{

public:
    void update_sequence(crypto_TH &crypto, client_socket &sock)
    {
        TCP_send_update_request(sock);
        TCP_wait_for_THMasterkey_request(sock);
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
    void TCP_wait_for_THMasterkey_request(client_socket &sock)
    {
        unsigned char *payload = NULL;
        int payloadlen;
        if (sock.read_and_decapsulate(payload, payloadlen) != THMASTER_REQUEST)
        {
            ERROR("Invalid message received");
            exit(1);
        }

        cout << "Received THMasterkey request";
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