//
//  tls-client.c
//  TestCliServWolfSSL
//
//  Created by Mac on 01.07.16.
//  Copyright © 2016 justmml. All rights reserved.
//


#include    <stdio.h>
#include    <string.h>
#include    <stdlib.h>
#include    <errno.h>
#include    <arpa/inet.h>

//including wolfssl library
#include    <wolfssl/ssl.h>

//4096 maximum available data
#define MAXDATASIZE  4096

//setting default port to 11111
#define SERV_PORT    11111

const char* cert = "/Users/mac/Downloads/wolfssl-examples-master/certs/ca-cert.pem";

/*
 * clients initial contact with server. (socket to connect, security layer)
 */
int ClientGreet(int sock, WOLFSSL* ssl)
{
    
//setting data sending to server & receiving from server
    char    send_buffer[MAXDATASIZE], receive_buffer[MAXDATASIZE] = {0};
    int     ret = 0;                /* variable for error checking */
    
    printf("Message for server:\t");
    fgets(send_buffer, MAXDATASIZE, stdin);
    
    if (wolfSSL_write(ssl, send_buffer, strlen(send_buffer)) != strlen(send_buffer)) {

//if message cannot be sent
        ret = wolfSSL_get_error(ssl, 0);
        printf("Write error: Error: %i\n", ret);
        return EXIT_FAILURE;
    }
    
    if (wolfSSL_read(ssl, receive_buffer, MAXDATASIZE) < 0) {

//if server answer failure
        ret = wolfSSL_get_error(ssl, 0);
        printf("Read error. Error: %i\n", ret);
        return EXIT_FAILURE;
    }
    printf("Recieved: \t%s\n", receive_buffer);
    
    return ret;
}


//applying TLS v1.2
int Security(int socket)
{
//initializing ctx pointer
    WOLFSSL_CTX* ctx;
    
//creating wolfssl obj
    WOLFSSL*     ssl;
    int         ret = 0;
    
    wolfSSL_Init();
    
//wolfssl_ctx structure
    if ((ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method())) == NULL) {
        printf("SSL_CTX_new error.\n");
        return EXIT_FAILURE;
    }
    
//loading CA certificates to check server
    if (wolfSSL_CTX_load_verify_locations(ctx, cert, 0) != SSL_SUCCESS) {
        printf("Error loading %s. Please check the file.\n", cert);
        return EXIT_FAILURE;
    }
    if ((ssl = wolfSSL_new(ctx)) == NULL) {
        printf("wolfSSL_new error.\n");
        return EXIT_FAILURE;
    }
    wolfSSL_set_fd(ssl, socket);
    
    ret = wolfSSL_connect(ssl);
    if (ret == SSL_SUCCESS) {
        ret = ClientGreet(socket, ssl);
    }
    
//free all data (just not to receive overflow trouble)
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    
    return ret;
}

/*
 * Command line argumentCount and argumentValues
 */
int main(int argc, char** argv)
{
    int     sockfd;                         /* socket file descriptor */
    struct  sockaddr_in servAddr;           /* struct for server address */
    int     ret = 0;                        /* variable for error checking */
    
    if (argc != 2) {
        
//if the number of arguments is not two, error
        printf("usage: ./client-tcp  <IP address>\n");
        return EXIT_FAILURE;
    }
    
//internet address family, stream based tcp, default protocol
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    
    if (sockfd < 0) {
        printf("Socket creation failure. Error: %i\n", errno);
        return EXIT_FAILURE;
    }
    
    memset(&servAddr, 0, sizeof(servAddr)); /* clears memory block for use */
    servAddr.sin_family = AF_INET;          /* sets addressfamily to internet*/
    servAddr.sin_port = htons(SERV_PORT);   /* sets port to defined port */
    
//looking for the server at the entered address (ip in the command line)
    if (inet_pton(AF_INET, argv[1], &servAddr.sin_addr) < 1) {
        /* checks validity of address */
        ret = errno;
        printf("Invalid Address. Error: %i\n", ret);
        return EXIT_FAILURE;
    }
    
    if (connect(sockfd, (struct sockaddr *) &servAddr, sizeof(servAddr)) < 0) {
//if appears socket connection to the server failure
        ret = errno;
        printf("Connect error. Error: %i\n", ret);
        return EXIT_FAILURE;
    }
    Security(sockfd);
    
    return ret;
}
