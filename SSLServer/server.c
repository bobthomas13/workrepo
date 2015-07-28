/*
 * server.c
 *
 *  Created on: Jul 9, 2014
 *      Author: Bob Thomas
 * 
 * Reference :	https://www.cs.utah.edu/~swalton/listings/articles/ssl_server.c 
 */

#include <stdio.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define FAIL    -1

#define PUBLIC_KEY_PATH		"server.crt"
#define PRIVATE_KEY_PATH	"server.key"

#define SSL_PORT	5006

/*---------------------------------------------------------------------*/
/*--- OpenListener - create server socket                           ---*/
/*---------------------------------------------------------------------*/
int OpenListener(int port)
{   int sd;
    struct sockaddr_in addr;

    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    if ( bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
        perror("can't bind port");
        abort();
    }
    if ( listen(sd, 10) != 0 )
    {
        perror("Can't configure listening port");
        abort();
    }
    return sd;
}

/*---------------------------------------------------------------------*/
/*--- InitServerCTX - initialize SSL server  and create context     ---*/
/*---------------------------------------------------------------------*/
SSL_CTX* InitServerCTX(void)
{
    SSL_CTX *ctx;

    SSL_library_init();
    OpenSSL_add_all_algorithms();		/* load & register all cryptos, etc. */
    SSL_load_error_strings();			/* load all error messages */
    ctx = SSL_CTX_new(TLSv1_server_method());			/* create new context from method */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

/*---------------------------------------------------------------------*/
/*--- LoadCertificates - load from files.                           ---*/
/*---------------------------------------------------------------------*/
void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
	/* set the local certificate from CertFile */
    if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* set the private key from KeyFile (may be the same as CertFile)*/
    if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }

    if ( !SSL_CTX_check_private_key(ctx) )
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }

}

/*---------------------------------------------------------------------*/
/*--- ShowCerts - print out certificates.                           ---*/
/*---------------------------------------------------------------------*/
void ShowCerts(SSL* ssl)
{   X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl);	/* Get certificates (if available) */
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);
        X509_free(cert);
    }
    else
        printf("No certificates.\n");
}

/*---------------------------------------------------------------------*/
/*--- Servlet - SSL servlet (contexts can be shared)                ---*/
/*---------------------------------------------------------------------*/
void Servlet(SSL* ssl)	/* Serve the connection -- threadable */
{   char buf[1024];
    char reply[1024];
    int sd, bytes,retcode;
    const char* serverMessage="Server Says HI !!!!!!";

    if ( SSL_accept(ssl) == FAIL )					/* do SSL-protocol accept */
    {
    	printf("SSL_accept() failed\n");
        ERR_print_errors_fp(stderr);
    }
    else
    {
        ShowCerts(ssl);								/* get any certificates */

    	bytes = SSL_read(ssl, buf, sizeof(buf));	/* get request */
    	if ( bytes > 0 )
        {
            buf[bytes] = 0;
            printf("Client msg: \"%s\"\n", buf);
            sprintf(reply, serverMessage, buf);		/* construct reply */
           SSL_write(ssl, reply, strlen(reply));	/* send reply */
        }
        else{
            printf("SSL_read() failed\n");
            ERR_print_errors_fp(stderr);
        }
    }

    sd = SSL_get_fd(ssl);							/* get socket connection */
    SSL_free(ssl);									/* release SSL state */
    close(sd);										/* close connection */
}

/*---------------------------------------------------------------------*/
/*--- main - create SSL socket server.                              ---*/
/*---------------------------------------------------------------------*/
int main(int count, char *strings[])
{   SSL_CTX *ctx;
    int server;
    ctx = InitServerCTX();								/* initialize SSL */
    LoadCertificates(ctx, PUBLIC_KEY_PATH,PRIVATE_KEY_PATH );	/* load certs */
    server = OpenListener(SSL_PORT);				/* create server socket */

    while (1)
    {   struct sockaddr_in addr;
    	socklen_t len;
        SSL *ssl;

        int client = accept(server, (struct sockaddr*)&addr, &len);		/* accept connection as usual */
        printf("Connection: %s:%d\n",  	inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
        ssl = SSL_new(ctx);         					/* get new SSL state with context */
        SSL_set_fd(ssl, client);						/* set connection socket to SSL state */
        Servlet(ssl);									/* service connection */
    }
    close(server);										/* close server socket */
    SSL_CTX_free(ctx);									/* release context */
}
