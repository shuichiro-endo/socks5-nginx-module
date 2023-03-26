/*
 * Title:  socks5 server (nginx filter module)
 * Author: Shuichiro Endo
 */

//#define _DEBUG

#include <stdio.h>
#include <strings.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include "socks5.h"
#include "ngx_http_socks5_module.h"
#include "serverkey.h"

#define HTTP_REQUEST_HEADER_SOCKS5_KEY "socks5"
#define HTTP_REQUEST_HEADER_SOCKS5_VALUE "socks5"
#define HTTP_REQUEST_HEADER_TLS_KEY "tls"
#define HTTP_REQUEST_HEADER_TLS_VALUE1 "off"	// Socks5
#define HTTP_REQUEST_HEADER_TLS_VALUE2 "on"	// Socks5 over TLS
#define HTTP_REQUEST_HEADER_TVSEC_KEY "sec"	// tv_sec
#define HTTP_REQUEST_HEADER_TVUSEC_KEY "usec"	// tv_usec

static char authenticationMethod = 0x0;	// 0x0:No Authentication Required	0x2:Username/Password Authentication
static char username[256] = "socks5user";
static char password[256] = "supersecretpassword";

char cipherSuiteTLS1_2[1000] = "AESGCM+ECDSA:CHACHA20+ECDSA:+AES256";	// TLS1.2
char cipherSuiteTLS1_3[1000] = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256";	// TLS1.3


static ngx_http_output_header_filter_pt ngx_http_next_header_filter;

static ngx_http_output_body_filter_pt ngx_http_next_body_filter;

static ngx_http_module_t ngx_http_socks5_module_ctx = {
	NULL,					/* preconfiguration */
	ngx_http_socks5_init,		/* postconfiguration */
	NULL,					/* create main configuration */
	NULL,					/* init main configuration */
	NULL,					/* create server configuration */
	NULL,					/* marge server configuration */
	NULL,					/* create location configuration */
	NULL					/* merge location configuration */
};

ngx_module_t ngx_http_socks5_module = {
	NGX_MODULE_V1,
	&ngx_http_socks5_module_ctx,	/* module context */
	NULL,					/* module directives */
	NGX_HTTP_MODULE,			/* module type */
	NULL,					/* init master */
	NULL,					/* init module */
	NULL,					/* init process */
	NULL,					/* init thread */
	NULL,					/* exit thread */
	NULL,					/* exit process */
	NULL,					/* exit master */
	NGX_MODULE_V1_PADDING
};


int recvData(ngx_http_request_t *r, int sock, void *buffer, int length, long tv_sec, long tv_usec)
{
	int rec = 0;
	fd_set readfds;
	int nfds = -1;
	struct timeval tv;
	bzero(buffer, length+1);
	
	while(1){
		FD_ZERO(&readfds);
		FD_SET(sock, &readfds);
		nfds = sock + 1;
		tv.tv_sec = tv_sec;
		tv.tv_usec = tv_usec;
		
		if(select(nfds, &readfds, NULL, NULL, &tv) == 0){
#ifdef _DEBUG
			printf("[I] recvData timeout.\n");
			ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[I] recvData timeout.");
#endif
			break;
		}
		
		if(FD_ISSET(sock, &readfds)){
			rec = recv(sock, buffer, length, 0);
			if(rec <= 0){
				if(errno == EINTR){
					continue;
				}else if(errno == EAGAIN){
					usleep(5000);
					continue;
				}else{
					return -1;
				}
			}else{
				break;
			}
		}
	}
	
	return rec;
}


int recvDataTls(ngx_http_request_t *r, int sock, SSL *ssl ,void *buffer, int length, long tv_sec, long tv_usec)
{
	int rec = 0;
	int err = 0;
	fd_set readfds;
	int nfds = -1;
	struct timeval tv;
	bzero(buffer, length+1);

	while(1){
		FD_ZERO(&readfds);
		FD_SET(sock, &readfds);
		nfds = sock + 1;
		tv.tv_sec = tv_sec;
		tv.tv_usec = tv_usec;
		
		if(select(nfds, &readfds, NULL, NULL, &tv) == 0){
#ifdef _DEBUG
			printf("[I] recvDataTls timeout.\n");
			ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[I] recvData timeout.");
#endif
			break;
		}
		
		if(FD_ISSET(sock, &readfds)){
			rec = SSL_read(ssl, buffer, length);
			err = SSL_get_error(ssl, rec);
			
			if(err == SSL_ERROR_NONE){
				break;
			}else if(err == SSL_ERROR_ZERO_RETURN){
				break;
			}else if(err == SSL_ERROR_WANT_READ){
				usleep(5000);
			}else if(err == SSL_ERROR_WANT_WRITE){
				usleep(5000);
			}else{
#ifdef _DEBUG
				printf("[E] SSL_read error:%d:%s.\n", err, ERR_error_string(ERR_peek_last_error(), NULL));
				ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[E] SSL_read error:%d:%s.", err, ERR_error_string(ERR_peek_last_error(), NULL));
#endif
				return -2;
			}
		}
	}
	
	return rec;
}


int sendData(ngx_http_request_t *r, int sock, void *buffer, int length, long tv_sec, long tv_usec)
{
	int sen = 0;
	int sendLength = 0;
	int len = length;
	fd_set writefds;
	int nfds = -1;
	struct timeval tv;
	
	while(len > 0){
		FD_ZERO(&writefds);
		FD_SET(sock, &writefds);
		nfds = sock + 1;
		tv.tv_sec = tv_sec;
		tv.tv_usec = tv_usec;
		
		if(select(nfds, NULL, &writefds, NULL, &tv) == 0){
#ifdef _DEBUG
			printf("[I] sendData timeout.\n");
			ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[I] sendData timeout.");
#endif
			break;
		}
		
		if(FD_ISSET(sock, &writefds)){
			sen = send(sock, (char *)buffer+sendLength, len, 0);
			if(sen <= 0){
				if(errno == EINTR){
					continue;
				}else if(errno == EAGAIN){
					usleep(5000);
					continue;
				}else{
					return -1;
				}
			}
			sendLength += sen;
			len -= sen;
		}
	}
	
	return sendLength;
}


int sendDataTls(ngx_http_request_t *r, int sock, SSL *ssl, void *buffer, int length, long tv_sec, long tv_usec)
{
	int sen = 0;
	int err = 0;
	fd_set writefds;
	int nfds = -1;
	struct timeval tv;

	while(1){
		FD_ZERO(&writefds);
		FD_SET(sock, &writefds);
		nfds = sock + 1;
		tv.tv_sec = tv_sec;
		tv.tv_usec = tv_usec;
		
		if(select(nfds, NULL, &writefds, NULL, &tv) == 0){
#ifdef _DEBUG
			printf("[I] sendDataTls timeout.\n");
			ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[I] sendDataTls timeout.");
#endif
			break;
		}
		
		if(FD_ISSET(sock, &writefds)){
			sen = SSL_write(ssl, buffer, length);
			err = SSL_get_error(ssl, sen);
			
			if(err == SSL_ERROR_NONE){
				break;
			}else if(err == SSL_ERROR_WANT_WRITE){
				usleep(5000);
			}else if(err == SSL_ERROR_WANT_READ){
				usleep(5000);
			}else{
#ifdef _DEBUG
				printf("[E] SSL_write error:%d:%s.\n", err, ERR_error_string(ERR_peek_last_error(), NULL));
				ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[E] SSL_write error:%d:%s.", err, ERR_error_string(ERR_peek_last_error(), NULL));
#endif
				return -2;
			}
		}
	}
		
	return sen;
}


int forwarder(ngx_http_request_t *r, int clientSock, int targetSock, long tv_sec, long tv_usec)
{
	int rec, sen;
	fd_set readfds;
	int nfds = -1;
	struct timeval tv;
	char buffer[BUFSIZ+1];
	bzero(buffer, BUFSIZ+1);
	
	while(1){
		FD_ZERO(&readfds);
		FD_SET(clientSock, &readfds);
		FD_SET(targetSock, &readfds);
		nfds = (clientSock > targetSock ? clientSock : targetSock) + 1;
		tv.tv_sec = tv_sec;
		tv.tv_usec = tv_usec;
		
		if(select(nfds, &readfds, NULL, NULL, &tv) == 0){
#ifdef _DEBUG
			printf("[I] Forwarder timeout.\n");
			ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[I] Forwarder timeout.");
#endif
			break;
		}
						
		if(FD_ISSET(clientSock, &readfds)){	
			if((rec = read(clientSock, buffer, BUFSIZ)) > 0){
				sen = write(targetSock, buffer, rec);
				if(sen <= 0){
					break;
				}
			}else{
				break;
			}
		}
		
		if(FD_ISSET(targetSock, &readfds)){
			if((rec = read(targetSock, buffer, BUFSIZ)) > 0){
				sen = write(clientSock, buffer, rec);
				if(sen <= 0){
					break;
				}
			}else{
				break;
			}
		}
	}
	
	return 0;
}


int forwarderTls(ngx_http_request_t *r, int clientSock, int targetSock, SSL *clientSslSocks5, long tv_sec, long tv_usec)
{
	int rec, sen;
	fd_set readfds;
	int nfds = -1;
	struct timeval tv;
	char buffer[BUFSIZ+1];
	bzero(buffer, BUFSIZ+1);
	int err = 0;
	
	while(1){
		FD_ZERO(&readfds);
		FD_SET(clientSock, &readfds);
		FD_SET(targetSock, &readfds);
		nfds = (clientSock > targetSock ? clientSock : targetSock) + 1;
		tv.tv_sec = tv_sec;
		tv.tv_usec = tv_usec;
		
		if(select(nfds, &readfds, NULL, NULL, &tv) == 0){
#ifdef _DEBUG
			printf("[I] Forwarder timeout.\n");
			ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[I] Forwarder timeout.");
#endif
			break;
		}
		
		if(FD_ISSET(clientSock, &readfds)){
			rec = SSL_read(clientSslSocks5, buffer, BUFSIZ);
			err = SSL_get_error(clientSslSocks5, rec);
			
			if(err == SSL_ERROR_NONE){
				sen = write(targetSock, buffer, rec);
				if(sen <= 0){
					break;
				}
			}else if(err == SSL_ERROR_ZERO_RETURN){
				break;
			}else if(err == SSL_ERROR_WANT_READ){
				usleep(5000);
			}else if(err == SSL_ERROR_WANT_WRITE){
				usleep(5000);
			}else{
#ifdef _DEBUG
				printf("[E] SSL_read error:%d:%s.\n", err, ERR_error_string(ERR_peek_last_error(), NULL));
				ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[E] SSL_read error:%d:%s.", err, ERR_error_string(ERR_peek_last_error(), NULL));
#endif
				return -2;
			}
		}
		
		if(FD_ISSET(targetSock, &readfds)){
			if((rec = read(targetSock, buffer, BUFSIZ)) > 0){
				while(1){
					sen = SSL_write(clientSslSocks5, buffer, rec);
					err = SSL_get_error(clientSslSocks5, sen);

					if(err == SSL_ERROR_NONE){
						break;
					}else if(err == SSL_ERROR_WANT_WRITE){
						usleep(5000);
					}else if(err == SSL_ERROR_WANT_READ){
						usleep(5000);
					}else{
#ifdef _DEBUG
						printf("[E] SSL_write error:%d:%s.\n", err, ERR_error_string(ERR_peek_last_error(), NULL));
						ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[E] SSL_write error:%d:%s.", err, ERR_error_string(ERR_peek_last_error(), NULL));
#endif
						return -2;
					}
				}
			}else{
				break;
			}
		}
	}
	
	return 0;
}


int sendSocksResponseIpv4(ngx_http_request_t *r, int clientSock, char ver, char req, char rsv, char atyp, long tv_sec, long tv_usec)
{
	int sen;
	pSOCKS_RESPONSE_IPV4 pSocksResponseIpv4 = (pSOCKS_RESPONSE_IPV4)malloc(sizeof(SOCKS_RESPONSE_IPV4));
		
	pSocksResponseIpv4->ver = ver;		// protocol version
	pSocksResponseIpv4->req = req;		// Connection refused
	pSocksResponseIpv4->rsv = rsv;		// RESERVED
	pSocksResponseIpv4->atyp = atyp;	// IPv4
	bzero(pSocksResponseIpv4->bndAddr, 4);	// BND.ADDR
	bzero(pSocksResponseIpv4->bndPort, 2);	// BND.PORT

	sen = sendData(r, clientSock, pSocksResponseIpv4, sizeof(SOCKS_RESPONSE_IPV4), tv_sec, tv_usec);

	free(pSocksResponseIpv4);

	return sen;
}


int sendSocksResponseIpv4Tls(ngx_http_request_t *r, int clientSock, SSL *clientSsl, char ver, char req, char rsv, char atyp, long tv_sec, long tv_usec)
{
	int sen;
	pSOCKS_RESPONSE_IPV4 pSocksResponseIpv4 = (pSOCKS_RESPONSE_IPV4)malloc(sizeof(SOCKS_RESPONSE_IPV4));
	
	pSocksResponseIpv4->ver = ver;		// protocol version
	pSocksResponseIpv4->req = req;		// Connection refused
	pSocksResponseIpv4->rsv = rsv;		// RESERVED
	pSocksResponseIpv4->atyp = atyp;	// IPv4
	bzero(pSocksResponseIpv4->bndAddr, 4);	// BND.ADDR
	bzero(pSocksResponseIpv4->bndPort, 2);	// BND.PORT

	sen = sendDataTls(r, clientSock, clientSsl, pSocksResponseIpv4, sizeof(SOCKS_RESPONSE_IPV4), tv_sec, tv_usec);

	free(pSocksResponseIpv4);

	return sen;
}


int sendSocksResponseIpv6(ngx_http_request_t *r, int clientSock, char ver, char req, char rsv, char atyp, long tv_sec, long tv_usec)
{
	int sen;
	pSOCKS_RESPONSE_IPV6 pSocksResponseIpv6 = (pSOCKS_RESPONSE_IPV6)malloc(sizeof(SOCKS_RESPONSE_IPV6));
	
	pSocksResponseIpv6->ver = ver;		// protocol version
	pSocksResponseIpv6->req = req;		// Connection refused
	pSocksResponseIpv6->rsv = rsv;		// RESERVED
	pSocksResponseIpv6->atyp = atyp;	// IPv6
	bzero(pSocksResponseIpv6->bndAddr, 16);	// BND.ADDR
	bzero(pSocksResponseIpv6->bndPort, 2);	// BND.PORT
	
	sen = sendData(r, clientSock, pSocksResponseIpv6, sizeof(SOCKS_RESPONSE_IPV6), tv_sec, tv_usec);
	
	free(pSocksResponseIpv6);

	return sen;
}


int sendSocksResponseIpv6Tls(ngx_http_request_t *r, int clientSock, SSL *clientSsl, char ver, char req, char rsv, char atyp, long tv_sec, long tv_usec)
{
	int sen;
	pSOCKS_RESPONSE_IPV6 pSocksResponseIpv6 = (pSOCKS_RESPONSE_IPV6)malloc(sizeof(SOCKS_RESPONSE_IPV6));
	
	pSocksResponseIpv6->ver = ver;		// protocol version
	pSocksResponseIpv6->req = req;		// Connection refused
	pSocksResponseIpv6->rsv = rsv;		// RESERVED
	pSocksResponseIpv6->atyp = atyp;	// IPv6
	bzero(pSocksResponseIpv6->bndAddr, 16);	// BND.ADDR
	bzero(pSocksResponseIpv6->bndPort, 2);	// BND.PORT
	
	sen = sendDataTls(r, clientSock, clientSsl, pSocksResponseIpv6, sizeof(SOCKS_RESPONSE_IPV6), tv_sec, tv_usec);
	
	free(pSocksResponseIpv6);

	return sen;
}


int worker(ngx_http_request_t *r, void *ptr)
{
	pPARAM pParam = (pPARAM)ptr;
	int clientSock = pParam->clientSock;
	SSL *clientSslSocks5 = pParam->clientSslSocks5;
	int socks5OverTlsFlag = pParam->socks5OverTlsFlag;	// 0:socks5 1:socks5 over tls
	long tv_sec = pParam->tv_sec;
	long tv_usec = pParam->tv_usec;
	
	char buffer[BUFSIZ+1];
	bzero(buffer, BUFSIZ+1);
	int sen = 0;
	int rec = sen;
	int err = 0;
	
	
	// socks SELECTION_REQUEST
#ifdef _DEBUG
	printf("[I] Recieving selection request.\n");
	ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[I] Recieving selection request.");
#endif
	if(socks5OverTlsFlag == 0){	// Socks5
		rec = recvData(r, clientSock, buffer, BUFSIZ, tv_sec, tv_usec);
	}else{	// Socks5 over TLS
		rec = recvDataTls(r, clientSock, clientSslSocks5, buffer, BUFSIZ, tv_sec, tv_usec);
	}
	if(rec <= 0){
#ifdef _DEBUG
		printf("[E] Recieving selection request error.\n");
		ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[E] Recieving selection request error.");
#endif
		return -1;
	}
#ifdef _DEBUG
	printf("[I] Recieive selection request:%d bytes.\n", rec);
	ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[I] Recieive selection request:%d bytes.", rec);
#endif
	pSELECTION_REQUEST pSelectionRequest = (pSELECTION_REQUEST)buffer;
	unsigned char method = 0xFF;
	for(int i=0; i<pSelectionRequest->nmethods; i++){
		if(pSelectionRequest->methods[i] == 0x0 || pSelectionRequest->methods[i] == 0x2){	// NO AUTHENTICATION REQUIRED or USERNAME/PASSWORD
			method = pSelectionRequest->methods[i];
			break;
		}
	}
	if(method == 0xFF){
#ifdef _DEBUG
		printf("[E] Selection request method error.\n");
		ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[E] Selection request method error.");
#endif
	}


	// socks SELECTION_RESPONSE
	pSELECTION_RESPONSE pSelectionResponse = (pSELECTION_RESPONSE)malloc(sizeof(SELECTION_RESPONSE));
	pSelectionResponse->ver = 0x5;		// socks version 5
	pSelectionResponse->method = method;	// no authentication required or username/password 
	if(pSelectionRequest->ver != 0x5 || authenticationMethod != method){
		pSelectionResponse->method = 0xFF;
	}
	if(socks5OverTlsFlag == 0){	// Socks5
		sen = sendData(r, clientSock, pSelectionResponse, sizeof(SELECTION_RESPONSE), tv_sec, tv_usec);
	}else{	// Socks5 over TLS
		sen = sendDataTls(r, clientSock, clientSslSocks5, pSelectionResponse, sizeof(SELECTION_RESPONSE), tv_sec, tv_usec);
	}
	free(pSelectionResponse);
#ifdef _DEBUG
	printf("[I] Send selection response:%d bytes.\n", sen);
	ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[I] Send selection response:%d bytes.", sen);
#endif
	
	if(authenticationMethod != method){
#ifdef _DEBUG
		printf("[E] Authentication method error. server:0x%x client:0x%x\n", authenticationMethod, method);
		ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[E] Authentication method error. server:0x%x client:0x%x", authenticationMethod, method);
#endif
		return -1;
	}


	// socks USERNAME_PASSWORD_AUTHENTICATION
	unsigned char ulen = 0;
	unsigned char plen = 0;
	char uname[256] = {0};
	char passwd[256] = {0};
	if(method == 0x2){
		// socks USERNAME_PASSWORD_AUTHENTICATION_REQUEST
#ifdef _DEBUG
		printf("[I] Recieving username password authentication request.\n");
		ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[I] Recieving username password authentication request.");
#endif
		if(socks5OverTlsFlag == 0){	// Socks5
			rec = recvData(r, clientSock, buffer, BUFSIZ, tv_sec, tv_usec);
		}else{	// Socks5 over TLS
			rec = recvDataTls(r, clientSock, clientSslSocks5, buffer, BUFSIZ, tv_sec, tv_usec);
		}
		if(rec <= 0){
#ifdef _DEBUG
			printf("[E] Recieving username password authentication request error.\n");
			ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[E] Recieving username password authentication request error.");
#endif
			return -1;
		}
#ifdef _DEBUG
		printf("[I] Receive username password authentication request:%d bytes.\n", rec);
		ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[I] Receive username password authentication request:%d bytes.", rec);
#endif
		pUSERNAME_PASSWORD_AUTHENTICATION_REQUEST_TMP pUsernamePasswordAuthenticationRequest = (pUSERNAME_PASSWORD_AUTHENTICATION_REQUEST_TMP)buffer;

		ulen = pUsernamePasswordAuthenticationRequest->ulen;
		memcpy(uname, &pUsernamePasswordAuthenticationRequest->uname, ulen);
		memcpy(&plen, &pUsernamePasswordAuthenticationRequest->uname + ulen, 1);
		memcpy(passwd, &pUsernamePasswordAuthenticationRequest->uname + ulen + 1, plen);
#ifdef _DEBUG
		printf("uname:%s, ulen:%d, passwd:%s, plen:%d\n", uname, ulen, passwd, plen);
		ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "uname:%s, ulen:%d, passwd:%s, plen:%d", uname, ulen, passwd, plen);
#endif


		// socks USERNAME_PASSWORD_AUTHENTICATION_RESPONSE
		pUSERNAME_PASSWORD_AUTHENTICATION_RESPONSE pUsernamePasswordAuthenticationResponse = (pUSERNAME_PASSWORD_AUTHENTICATION_RESPONSE)malloc(sizeof(USERNAME_PASSWORD_AUTHENTICATION_RESPONSE));
		pUsernamePasswordAuthenticationResponse->ver = 0x1;
		
		if(pUsernamePasswordAuthenticationRequest->ver == 0x1 && !strncmp(uname, username, sizeof(username)) && !strncmp(passwd, password, sizeof(password))){
#ifdef _DEBUG
			printf("[I] Succeed username password authentication.\n");
			ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[I] Succeed username password authentication.");
#endif
			pUsernamePasswordAuthenticationResponse->status = 0x0;
			
			if(socks5OverTlsFlag == 0){	// Socks5
				sen = sendData(r, clientSock, pUsernamePasswordAuthenticationResponse, sizeof(USERNAME_PASSWORD_AUTHENTICATION_RESPONSE), tv_sec, tv_usec);
			}else{	// Socks5 over TLS
				sen = sendDataTls(r, clientSock, clientSslSocks5, pUsernamePasswordAuthenticationResponse, sizeof(USERNAME_PASSWORD_AUTHENTICATION_RESPONSE), tv_sec, tv_usec);
			}
#ifdef _DEBUG
			printf("[I] Send selection response:%d bytes.\n", sen);
			ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[I] Send selection response:%d bytes.", sen);
#endif
			
			free(pUsernamePasswordAuthenticationResponse);
		}else{
#ifdef _DEBUG
			printf("[E] Fail username password authentication.\n");
			ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[E] Fail username password authentication.");
#endif
			pUsernamePasswordAuthenticationResponse->status = 0xFF;
			
			if(socks5OverTlsFlag == 0){	// Socks5
				sen = sendData(r, clientSock, pUsernamePasswordAuthenticationResponse, sizeof(USERNAME_PASSWORD_AUTHENTICATION_RESPONSE), tv_sec, tv_usec);
			}else{	// Socks5 over TLS
				sen = sendDataTls(r, clientSock, clientSslSocks5, pUsernamePasswordAuthenticationResponse, sizeof(USERNAME_PASSWORD_AUTHENTICATION_RESPONSE), tv_sec, tv_usec);
			}
#ifdef _DEBUG
			printf("[I] Send selection response:%d bytes.\n", sen);
			ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[I] Send selection response:%d bytes.", sen);
#endif
			
			free(pUsernamePasswordAuthenticationResponse);
			return -1;
		}
	}
	
	
	// socks SOCKS_REQUEST
#ifdef _DEBUG
	printf("[I] Receiving socks request.\n");
	ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[I] Receiving socks request.");
#endif
	bzero(buffer, BUFSIZ+1);
	if(socks5OverTlsFlag == 0){	// Socks5
		rec = recvData(r, clientSock, buffer, BUFSIZ, tv_sec, tv_usec);
	}else{	// Socks5 over TLS
		rec = recvDataTls(r, clientSock, clientSslSocks5, buffer, BUFSIZ, tv_sec, tv_usec);
	}
	if(rec <= 0){
#ifdef _DEBUG
		printf("[E] Receiving socks request error.\n");
		ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[E] Receiving socks request error.");
#endif
		return -1;
	}
#ifdef _DEBUG
	printf("[I] Receive socks request:%d bytes.\n", rec);
	ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[I] Receive socks request:%d bytes.", rec);
#endif
	
	pSOCKS_REQUEST pSocksRequest = (pSOCKS_REQUEST)buffer;
	pSOCKS_REQUEST_IPV4 pSocksRequestIpv4;
	pSOCKS_REQUEST_DOMAINNAME pSocksRequestDomainname;
	pSOCKS_REQUEST_IPV6 pSocksRequestIpv6;
	
	char atyp = pSocksRequest->atyp;
	if(atyp != 0x1 && atyp != 0x3 && atyp != 0x4){
#ifdef _DEBUG
		printf("[E] Socks request atyp(%d) error.\n", atyp);
		ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[E] Socks request atyp(%d) error.", atyp);
		printf("[E] Not implemented.\n");
		ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[E] Not implemented.");
#endif

		// socks SOCKS_RESPONSE send error
		if(socks5OverTlsFlag == 0){	// Socks5
			sen = sendSocksResponseIpv4(r, clientSock, 0x5, 0x8, 0x0, 0x1, tv_sec, tv_usec);
		}else{	// Socks5 over TLS
			sen = sendSocksResponseIpv4Tls(r, clientSock, clientSslSocks5, 0x5, 0x8, 0x0, 0x1, tv_sec, tv_usec);
		}

		return -1;
	}
	
	char cmd = pSocksRequest->cmd;
	if(cmd != 0x1 && cmd != 0x3){
#ifdef _DEBUG
		printf("[E] Socks request cmd(%d) error.\n", cmd);
		ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[E] Socks request cmd(%d) error.", cmd);
		printf("[E] Not implemented.\n");
		ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[E] Not implemented.");
#endif
		
		// socks SOCKS_RESPONSE send error
		if(atyp == 0x1 || atyp == 0x3){	// IPv4
			if(socks5OverTlsFlag == 0){	// Socks5
				sen = sendSocksResponseIpv4(r, clientSock, 0x5, 0x7, 0x0, 0x1, tv_sec, tv_usec);
			}else{	// Socks5 over TLS
				sen = sendSocksResponseIpv4Tls(r, clientSock, clientSslSocks5, 0x5, 0x7, 0x0, 0x1, tv_sec, tv_usec);
			}
		}else{	// IPv6
			if(socks5OverTlsFlag == 0){	// Socks5
				sen = sendSocksResponseIpv6(r, clientSock, 0x5, 0x7, 0x0, 0x4, tv_sec, tv_usec);
			}else{	// Socks5 over TLS
				sen = sendSocksResponseIpv6Tls(r, clientSock, clientSslSocks5, 0x5, 0x7, 0x0, 0x4, tv_sec, tv_usec);
			}
		}
		
		return -1;
	}
		
	struct sockaddr_in targetAddr, *pTmpIpv4;		// IPv4
	memset(&targetAddr, 0, sizeof(struct sockaddr_in));
	
	struct sockaddr_in6 targetAddr6, *pTmpIpv6;	// IPv6
	memset(&targetAddr6, 0, sizeof(struct sockaddr_in6));
	
	struct addrinfo hints, *pTargetHost;
	memset(&hints, 0, sizeof(struct addrinfo));
	
	int family = 0;
	char domainname[256] = {0};
	u_short domainnameLength = 0;
	char *colon;
	
	if(pSocksRequest->atyp == 0x1){	// IPv4
		family = AF_INET;
		targetAddr.sin_family = AF_INET;
		pSocksRequestIpv4 = (pSOCKS_REQUEST_IPV4)buffer;
		memcpy(&targetAddr.sin_addr.s_addr, &pSocksRequestIpv4->dstAddr, 4);
		memcpy(&targetAddr.sin_port, &pSocksRequestIpv4->dstPort, 2);
	}else if(pSocksRequest->atyp == 0x3){	// domain name		
		pSocksRequestDomainname = (pSOCKS_REQUEST_DOMAINNAME)buffer;
		domainnameLength = pSocksRequestDomainname->dstAddrLen;
		memcpy(&domainname, &pSocksRequestDomainname->dstAddr, domainnameLength);
#ifdef _DEBUG
		printf("[I] Domainname:%s, Length:%d.\n", domainname, domainnameLength);
		ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[I] Domainname:%s, Length:%d.", domainname, domainnameLength);
#endif

		colon = strstr(domainname, ":");	// check ipv6 address
		if(colon == NULL){	// ipv4 address or domainname
			hints.ai_family = AF_INET;	// IPv4
			if(getaddrinfo(domainname, NULL, &hints, &pTargetHost) != 0){
				hints.ai_family = AF_INET6;	// IPv6
				if(getaddrinfo(domainname, NULL, &hints, &pTargetHost) != 0){
#ifdef _DEBUG
					printf("[E] Cannnot resolv the domain name:%s.\n", (char *)domainname);
					ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[E] Cannnot resolv the domain name:%s.", (char *)domainname);
#endif
					
					// socks SOCKS_RESPONSE send error
					if(socks5OverTlsFlag == 0){	// Socks5
						sen = sendSocksResponseIpv4(r, clientSock, 0x5, 0x5, 0x0, 0x1, tv_sec, tv_usec);
					}else{	// Socks5 over TLS
						sen = sendSocksResponseIpv4Tls(r, clientSock, clientSslSocks5, 0x5, 0x5, 0x0, 0x1, tv_sec, tv_usec);
					}
					
					return -1;
				}
			}
		}else{	// ipv6 address
			hints.ai_family = AF_INET6;	// IPv6
			if(getaddrinfo(domainname, NULL, &hints, &pTargetHost) != 0){
#ifdef _DEBUG
				printf("[E] Cannnot resolv the domain name:%s.\n", (char *)domainname);
				ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[E] Cannnot resolv the domain name:%s.", (char *)domainname);
#endif
				
				// socks SOCKS_RESPONSE send error
				if(socks5OverTlsFlag == 0){	// Socks5
					sen = sendSocksResponseIpv6(r, clientSock, 0x5, 0x5, 0x0, 0x4, tv_sec, tv_usec);
				}else{	// Socks5 over TLS
					sen = sendSocksResponseIpv6Tls(r, clientSock, clientSslSocks5, 0x5, 0x5, 0x0, 0x4, tv_sec, tv_usec);
				}

				return -1;
			}
		}
		
		if(pTargetHost->ai_family == AF_INET){
			family = AF_INET;
			targetAddr.sin_family = AF_INET;
			pTmpIpv4 = (struct sockaddr_in *)pTargetHost->ai_addr;
			memcpy(&targetAddr.sin_addr, &pTmpIpv4->sin_addr, sizeof(unsigned long));
			memcpy(&targetAddr.sin_port, &pSocksRequestDomainname->dstAddr[domainnameLength], 2);
			freeaddrinfo(pTargetHost);
		}else if(pTargetHost->ai_family == AF_INET6){
			family = AF_INET6;
			targetAddr6.sin6_family = AF_INET6;
			pTmpIpv6 = (struct sockaddr_in6 *)pTargetHost->ai_addr;
			memcpy(&targetAddr6.sin6_addr, &pTmpIpv6->sin6_addr, sizeof(struct in6_addr));
			memcpy(&targetAddr6.sin6_port, &pSocksRequestDomainname->dstAddr[domainnameLength], 2);			
			freeaddrinfo(pTargetHost);
		}else{
#ifdef _DEBUG
			printf("[E] Not implemented.\n");
			ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[E] Not implemented.");
#endif

			// socks SOCKS_RESPONSE send error
			if(socks5OverTlsFlag == 0){	// Socks5
				sen = sendSocksResponseIpv4(r, clientSock, 0x5, 0x1, 0x0, 0x1, tv_sec, tv_usec);
			}else{	// Socks5 over TLS
				sen = sendSocksResponseIpv4Tls(r, clientSock, clientSslSocks5, 0x1, 0x5, 0x0, 0x1, tv_sec, tv_usec);
			}
			
			freeaddrinfo(pTargetHost);
			return -1;
		}
	}else if(pSocksRequest->atyp == 0x4){	// IPv6
		family = AF_INET6;
		targetAddr6.sin6_family = AF_INET6;
		pSocksRequestIpv6 = (pSOCKS_REQUEST_IPV6)buffer;
		memcpy(&targetAddr6.sin6_addr, &pSocksRequestIpv6->dstAddr, 16);
		memcpy(&targetAddr6.sin6_port, &pSocksRequestIpv6->dstPort, 2);
	}else {
#ifdef _DEBUG
		printf("[E] Not implemented.\n");
		ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[E] Not implemented.");
#endif

		// socks SOCKS_RESPONSE send error
		if(socks5OverTlsFlag == 0){	// Socks5
			sen = sendSocksResponseIpv4(r, clientSock, 0x5, 0x1, 0x0, 0x1, tv_sec, tv_usec);
		}else{	// Socks5 over TLS
			sen = sendSocksResponseIpv4Tls(r, clientSock, clientSslSocks5, 0x1, 0x5, 0x0, 0x1, tv_sec, tv_usec);
		}
		
		return -1;
	}
	
	
	// socks SOCKS_RESPONSE	
	int targetSock;
	char targetAddr6String[INET6_ADDRSTRLEN+1] = {0};
	char *pTargetAddr6String = targetAddr6String;
	int flags = 0;
	
	if(atyp == 0x1){	// IPv4
#ifdef _DEBUG
		printf("[I] Connecting. ip:%s port:%d\n", inet_ntoa(targetAddr.sin_addr), ntohs(targetAddr.sin_port));
		ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[I] Connecting. ip:%s port:%d", inet_ntoa(targetAddr.sin_addr), ntohs(targetAddr.sin_port));
#endif

		if(cmd == 0x1){	// CONNECT
#ifdef _DEBUG
			printf("[I] SOCKS_RESPONSE cmd:CONNECT.\n");
			ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[I] SOCKS_RESPONSE cmd:CONNECT.");
#endif
			targetSock = socket(AF_INET, SOCK_STREAM, 0);
			
			flags = fcntl(targetSock, F_GETFL, 0);
			flags &= ~O_NONBLOCK;
			fcntl(targetSock, F_SETFL, flags);
			
			if((err = connect(targetSock, (struct sockaddr *)&targetAddr, sizeof(targetAddr))) < 0){
#ifdef _DEBUG
				printf("[E] Cannnot connect. errno:%d\n", err);
				ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[E] Cannnot connect. errno:%d", err);
#endif
				
				if(socks5OverTlsFlag == 0){	// Socks5
					sen = sendSocksResponseIpv4(r, clientSock, 0x5, 0x5, 0x0, 0x1, tv_sec, tv_usec);
				}else{	// Socks5 over TLS
					sen = sendSocksResponseIpv4Tls(r, clientSock, clientSslSocks5, 0x5, 0x5, 0x0, 0x1, tv_sec, tv_usec);
				}
#ifdef _DEBUG
				printf("[I] Socks Request:%d bytes, Socks Response:%d bytes.\n", rec, sen);
				ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[I] Socks Request:%d bytes, Socks Response:%d bytes.", rec, sen);
#endif
				
				close(targetSock);

				return -1;
			}

#ifdef _DEBUG
			printf("[I] Connected. ip:%s port:%d\n", inet_ntoa(targetAddr.sin_addr), ntohs(targetAddr.sin_port));
			ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[I] Connected. ip:%s port:%d", inet_ntoa(targetAddr.sin_addr), ntohs(targetAddr.sin_port));
#endif
			
			if(socks5OverTlsFlag == 0){	// Socks5
				sen = sendSocksResponseIpv4(r, clientSock, 0x5, 0x0, 0x0, 0x1, tv_sec, tv_usec);
			}else{	// Socks5 over TLS
				sen = sendSocksResponseIpv4Tls(r, clientSock, clientSslSocks5, 0x5, 0x0, 0x0, 0x1, tv_sec, tv_usec);
			}
#ifdef _DEBUG
			printf("[I] Socks Request:%d bytes, Socks Response:%d bytes.\n", rec, sen);
			ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[I] Socks Request:%d bytes, Socks Response:%d bytes.", rec, sen);
#endif
			
		}else if(cmd == 0x2){	// BIND
#ifdef _DEBUG
			printf("[I] SOCKS_RESPONSE cmd:BIND.\n");
			ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[I] SOCKS_RESPONSE cmd:BIND.");
			printf("[E] Not implemented.\n");
			ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[E] Not implemented.");
#endif
			
			if(socks5OverTlsFlag == 0){	// Socks5
				sen = sendSocksResponseIpv4(r, clientSock, 0x5, 0x7, 0x0, 0x1, tv_sec, tv_usec);
			}else{	// Socks5 over TLS
				sen = sendSocksResponseIpv4Tls(r, clientSock, clientSslSocks5, 0x5, 0x7, 0x0, 0x1, tv_sec, tv_usec);
			}
			
			return -1;
			
		}else if(cmd == 0x3){	// UDP ASSOCIATE
#ifdef _DEBUG
			printf("[I] SOCKS_RESPONSE cmd:UDP ASSOCIATE.\n");
			ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[I] SOCKS_RESPONSE cmd:UDP ASSOCIATE.");
#endif
			targetSock = socket(AF_INET, SOCK_DGRAM, 0);
			
			flags = fcntl(targetSock, F_GETFL, 0);
			flags &= ~O_NONBLOCK;
			fcntl(targetSock, F_SETFL, flags);
		
			if((err = connect(targetSock, (struct sockaddr *)&targetAddr, sizeof(targetAddr))) < 0){
#ifdef _DEBUG
				printf("[E] Cannnot connect. errno:%d\n", err);
				ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[E] Cannnot connect. errno:%d", err);
#endif
				
				if(socks5OverTlsFlag == 0){	// Socks5
					sen = sendSocksResponseIpv4(r, clientSock, 0x5, 0x5, 0x0, 0x1, tv_sec, tv_usec);
				}else{	// Socks5 over TLS
					sen = sendSocksResponseIpv4Tls(r, clientSock, clientSslSocks5, 0x5, 0x5, 0x0, 0x1, tv_sec, tv_usec);
				}
#ifdef _DEBUG
				printf("[I] Socks Request:%d bytes, Socks Response:%d bytes.\n", rec, sen);
				ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[I] Socks Request:%d bytes, Socks Response:%d bytes.", rec, sen);
#endif
				
				close(targetSock);

				return -1;
			}

#ifdef _DEBUG
			printf("[I] Connected. ip:%s port:%d\n", inet_ntoa(targetAddr.sin_addr), ntohs(targetAddr.sin_port));
			ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[I] Connected. ip:%s port:%d", inet_ntoa(targetAddr.sin_addr), ntohs(targetAddr.sin_port));
#endif
			
			if(socks5OverTlsFlag == 0){	// Socks5
				sen = sendSocksResponseIpv4(r, clientSock, 0x5, 0x0, 0x0, 0x1, tv_sec, tv_usec);
			}else{	// Socks5 over TLS
				sen = sendSocksResponseIpv4Tls(r, clientSock, clientSslSocks5, 0x5, 0x0, 0x0, 0x1, tv_sec, tv_usec);
			}
#ifdef _DEBUG
			printf("[I] Socks Request:%d bytes, Socks Response:%d bytes.\n", rec, sen);
			ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[I] Socks Request:%d bytes, Socks Response:%d bytes.", rec, sen);
#endif

		}else{
#ifdef _DEBUG
			printf("[E] Not implemented.\n");
			ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[E] Not implemented.");
#endif
			
			if(socks5OverTlsFlag == 0){	// Socks5
				sen = sendSocksResponseIpv4(r, clientSock, 0x5, 0x1, 0x0, 0x1, tv_sec, tv_usec);
			}else{	// Socks5 over TLS
				sen = sendSocksResponseIpv4Tls(r, clientSock, clientSslSocks5, 0x5, 0x1, 0x0, 0x1, tv_sec, tv_usec);
			}
			
			return -1;
		}
	}else if(atyp == 0x3){	// domain name
		if(family == AF_INET){	// IPv4
#ifdef _DEBUG
			printf("[I] Connecting. ip:%s port:%d\n", inet_ntoa(targetAddr.sin_addr), ntohs(targetAddr.sin_port));
			ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[I] Connecting. ip:%s port:%d", inet_ntoa(targetAddr.sin_addr), ntohs(targetAddr.sin_port));
#endif

			if(cmd == 0x1){	// CONNECT
#ifdef _DEBUG
				printf("[I] SOCKS_RESPONSE cmd:CONNECT.\n");
				ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[I] SOCKS_RESPONSE cmd:CONNECT.");
#endif
				targetSock = socket(AF_INET, SOCK_STREAM, 0);
				
				flags = fcntl(targetSock, F_GETFL, 0);
				flags &= ~O_NONBLOCK;
				fcntl(targetSock, F_SETFL, flags);
				
				if((err = connect(targetSock, (struct sockaddr *)&targetAddr, sizeof(targetAddr))) < 0){
#ifdef _DEBUG
					printf("[E] Cannnot connect. errno:%d\n", err);
					ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[E] Cannnot connect. errno:%d", err);
#endif
					
					if(socks5OverTlsFlag == 0){	// Socks5
						sen = sendSocksResponseIpv4(r, clientSock, 0x5, 0x5, 0x0, 0x1, tv_sec, tv_usec);
					}else{	// Socks5 over TLS
						sen = sendSocksResponseIpv4Tls(r, clientSock, clientSslSocks5, 0x5, 0x5, 0x0, 0x1, tv_sec, tv_usec);
					}
#ifdef _DEBUG
					printf("[I] Socks Request:%d bytes, Socks Response:%d bytes.\n", rec, sen);
					ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[I] Socks Request:%d bytes, Socks Response:%d bytes.", rec, sen);
#endif

					close(targetSock);
					
					return -1;
				}

#ifdef _DEBUG
				printf("[I] Connected. ip:%s port:%d\n", inet_ntoa(targetAddr.sin_addr), ntohs(targetAddr.sin_port));
				ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[I] Connected. ip:%s port:%d", inet_ntoa(targetAddr.sin_addr), ntohs(targetAddr.sin_port));
#endif
				
				if(socks5OverTlsFlag == 0){	// Socks5
					sen = sendSocksResponseIpv4(r, clientSock, 0x5, 0x0, 0x0, 0x1, tv_sec, tv_usec);
				}else{	// Socks5 over TLS
					sen = sendSocksResponseIpv4Tls(r, clientSock, clientSslSocks5, 0x5, 0x0, 0x0, 0x1, tv_sec, tv_usec);
				}
#ifdef _DEBUG
				printf("[I] Socks Request:%d bytes, Socks Response:%d bytes.\n", rec, sen);
				ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[I] Socks Request:%d bytes, Socks Response:%d bytes.", rec, sen);
#endif
				
			}else if(cmd == 0x2){	// BIND
#ifdef _DEBUG
				printf("[I] SOCKS_RESPONSE cmd:BIND.\n");
				ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[I] SOCKS_RESPONSE cmd:BIND.");
				printf("[E] Not implemented.\n");
				ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[E] Not implemented.");
#endif
				
				if(socks5OverTlsFlag == 0){	// Socks5
					sen = sendSocksResponseIpv4(r, clientSock, 0x5, 0x7, 0x0, 0x1, tv_sec, tv_usec);
				}else{	// Socks5 over TLS
					sen = sendSocksResponseIpv4Tls(r, clientSock, clientSslSocks5, 0x5, 0x7, 0x0, 0x1, tv_sec, tv_usec);
				}
				
				return -1;
			}else if(cmd == 0x3){	// UDP ASSOCIATE
#ifdef _DEBUG
				printf("[I] SOCKS_RESPONSE cmd:UDP ASSOCIATE.\n");
				ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[I] SOCKS_RESPONSE cmd:UDP ASSOCIATE.");
#endif
				targetSock = socket(AF_INET, SOCK_DGRAM, 0);
				
				flags = fcntl(targetSock, F_GETFL, 0);
				flags &= ~O_NONBLOCK;
				fcntl(targetSock, F_SETFL, flags);
			
				if((err = connect(targetSock, (struct sockaddr *)&targetAddr, sizeof(targetAddr))) < 0){
#ifdef _DEBUG
					printf("[E] Cannnot connect. errno:%d\n", err);
					ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[E] Cannnot connect. errno:%d", err);
#endif
					
					if(socks5OverTlsFlag == 0){	// Socks5
						sen = sendSocksResponseIpv4(r, clientSock, 0x5, 0x5, 0x0, 0x1, tv_sec, tv_usec);
					}else{	// Socks5 over TLS
						sen = sendSocksResponseIpv4Tls(r, clientSock, clientSslSocks5, 0x5, 0x5, 0x0, 0x1, tv_sec, tv_usec);
					}
#ifdef _DEBUG
					printf("[I] Socks Request:%d bytes, Socks Response:%d bytes.\n", rec, sen);
					ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[I] Socks Request:%d bytes, Socks Response:%d bytes.", rec, sen);
#endif

					close(targetSock);
					
					return -1;
				}

#ifdef _DEBUG
				printf("[I] Connected. ip:%s port:%d\n", inet_ntoa(targetAddr.sin_addr), ntohs(targetAddr.sin_port));
				ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[I] Connected. ip:%s port:%d", inet_ntoa(targetAddr.sin_addr), ntohs(targetAddr.sin_port));
#endif
				
				if(socks5OverTlsFlag == 0){	// Socks5
					sen = sendSocksResponseIpv4(r, clientSock, 0x5, 0x0, 0x0, 0x1, tv_sec, tv_usec);
				}else{	// Socks5 over TLS
					sen = sendSocksResponseIpv4Tls(r, clientSock, clientSslSocks5, 0x5, 0x0, 0x0, 0x1, tv_sec, tv_usec);
				}
#ifdef _DEBUG
				printf("[I] Socks Request:%d bytes, Socks Response:%d bytes.\n", rec, sen);
				ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[I] Socks Request:%d bytes, Socks Response:%d bytes.", rec, sen);
#endif
			
			}else{
#ifdef _DEBUG
				printf("[E] Not implemented.\n");
				ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[E] Not implemented.");
#endif
				
				if(socks5OverTlsFlag == 0){	// Socks5
					sen = sendSocksResponseIpv4(r, clientSock, 0x5, 0x1, 0x0, 0x1, tv_sec, tv_usec);
				}else{	// Socks5 over TLS
					sen = sendSocksResponseIpv4Tls(r, clientSock, clientSslSocks5, 0x5, 0x1, 0x0, 0x1, tv_sec, tv_usec);
				}
				
				return -1;
			}
		}else if(family == AF_INET6){	// IPv6
			inet_ntop(AF_INET6, &targetAddr6.sin6_addr, pTargetAddr6String, INET6_ADDRSTRLEN);
#ifdef _DEBUG
			printf("[I] Connecting. ip:%s port:%d\n", pTargetAddr6String, ntohs(targetAddr6.sin6_port));
			ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[I] Connecting. ip:%s port:%d", pTargetAddr6String, ntohs(targetAddr6.sin6_port));
#endif

			if(cmd == 0x1){	// CONNECT
#ifdef _DEBUG
				printf("[I] SOCKS_RESPONSE cmd:CONNECT.\n");
				ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[I] SOCKS_RESPONSE cmd:CONNECT.");
#endif
				targetSock = socket(AF_INET6, SOCK_STREAM, 0);

				flags = fcntl(targetSock, F_GETFL, 0);
				flags &= ~O_NONBLOCK;
				fcntl(targetSock, F_SETFL, flags);
			
				if((err = connect(targetSock, (struct sockaddr *)&targetAddr6, sizeof(targetAddr6))) < 0){
#ifdef _DEBUG
					printf("[E] Cannnot connect. errno:%d\n", err);
					ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[E] Cannnot connect. errno:%d", err);
#endif
					
					if(socks5OverTlsFlag == 0){	// Socks5
						sen = sendSocksResponseIpv6(r, clientSock, 0x5, 0x5, 0x0, 0x4, tv_sec, tv_usec);
					}else{	// Socks5 over TLS
						sen = sendSocksResponseIpv6Tls(r, clientSock, clientSslSocks5, 0x5, 0x5, 0x0, 0x4, tv_sec, tv_usec);
					}
#ifdef _DEBUG
					printf("[I] Socks Request:%d bytes, Socks Response:%d bytes.\n", rec, sen);
					ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[I] Socks Request:%d bytes, Socks Response:%d bytes.", rec, sen);
#endif

					close(targetSock);

					return -1;
				}

#ifdef _DEBUG
				printf("[I] Connected. ip:%s port:%d\n", pTargetAddr6String, ntohs(targetAddr6.sin6_port));
				ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[I] Connected. ip:%s port:%d", pTargetAddr6String, ntohs(targetAddr6.sin6_port));
#endif
				
				if(socks5OverTlsFlag == 0){	// Socks5
					sen = sendSocksResponseIpv6(r, clientSock, 0x5, 0x0, 0x0, 0x4, tv_sec, tv_usec);
				}else{	// Socks5 over TLS
					sen = sendSocksResponseIpv6Tls(r, clientSock, clientSslSocks5, 0x5, 0x0, 0x0, 0x4, tv_sec, tv_usec);
				}
#ifdef _DEBUG
				printf("[I] Socks Request:%d bytes, Socks Response:%d bytes.\n", rec, sen);
				ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[I] Socks Request:%d bytes, Socks Response:%d bytes.", rec, sen);
#endif
				
			}else if(cmd == 0x2){	// BIND
#ifdef _DEBUG
				printf("[I] SOCKS_RESPONSE cmd:BIND.\n");
				ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[I] SOCKS_RESPONSE cmd:BIND.");
				printf("[E] Not implemented.\n");
				ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[E] Not implemented.");
#endif
				
				if(socks5OverTlsFlag == 0){	// Socks5
					sen = sendSocksResponseIpv6(r, clientSock, 0x5, 0x7, 0x0, 0x4, tv_sec, tv_usec);
				}else{	// Socks5 over TLS
					sen = sendSocksResponseIpv6Tls(r, clientSock, clientSslSocks5, 0x5, 0x7, 0x0, 0x4, tv_sec, tv_usec);
				}
				
				return -1;
			}else if(cmd == 0x3){	// UDP ASSOCIATE
#ifdef _DEBUG
				printf("[I] SOCKS_RESPONSE cmd:UDP ASSOCIATE.\n");
				ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[I] SOCKS_RESPONSE cmd:UDP ASSOCIATE.");
#endif
				targetSock = socket(AF_INET6, SOCK_DGRAM, 0);
				
				flags = fcntl(targetSock, F_GETFL, 0);
				flags &= ~O_NONBLOCK;
				fcntl(targetSock, F_SETFL, flags);				
								
				if((err = connect(targetSock, (struct sockaddr *)&targetAddr6, sizeof(targetAddr6))) < 0){
#ifdef _DEBUG
					printf("[E] Cannnot connect. errno:%d\n", err);
					ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[E] Cannnot connect. errno:%d", err);
#endif
					
					if(socks5OverTlsFlag == 0){	// Socks5
						sen = sendSocksResponseIpv6(r, clientSock, 0x5, 0x5, 0x0, 0x4, tv_sec, tv_usec);
					}else{	// Socks5 over TLS
						sen = sendSocksResponseIpv6Tls(r, clientSock, clientSslSocks5, 0x5, 0x5, 0x0, 0x4, tv_sec, tv_usec);
					}
					
#ifdef _DEBUG
					printf("[I] Socks Request:%d bytes, Socks Response:%d bytes.\n", rec, sen);
					ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[I] Socks Request:%d bytes, Socks Response:%d bytes.", rec, sen);
#endif

					close(targetSock);

					return -1;
				}

#ifdef _DEBUG
				printf("[I] Connected. ip:%s port:%d\n", pTargetAddr6String, ntohs(targetAddr6.sin6_port));
				ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[I] Connected. ip:%s port:%d", pTargetAddr6String, ntohs(targetAddr6.sin6_port));
#endif
				
				if(socks5OverTlsFlag == 0){	// Socks5
					sen = sendSocksResponseIpv6(r, clientSock, 0x5, 0x0, 0x0, 0x4, tv_sec, tv_usec);
				}else{	// Socks5 over TLS
					sen = sendSocksResponseIpv6Tls(r, clientSock, clientSslSocks5, 0x5, 0x0, 0x0, 0x4, tv_sec, tv_usec);
				}
#ifdef _DEBUG
				printf("[I] Socks Request:%d bytes, Socks Response:%d bytes.\n", rec, sen);
				ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[I] Socks Request:%d bytes, Socks Response:%d bytes.", rec, sen);
#endif

			}else{
#ifdef _DEBUG
				printf("[E] Not implemented.\n");
				ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[E] Not implemented.");
#endif
				
				if(socks5OverTlsFlag == 0){	// Socks5
					sen = sendSocksResponseIpv4(r, clientSock, 0x5, 0x1, 0x0, 0x1, tv_sec, tv_usec);
				}else{	// Socks5 over TLS
					sen = sendSocksResponseIpv4Tls(r, clientSock, clientSslSocks5, 0x5, 0x1, 0x0, 0x1, tv_sec, tv_usec);
				}
				
				return -1;
			}		
		}else{
#ifdef _DEBUG
			printf("[E] Not implemented.\n");
			ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[E] Not implemented.");
#endif
			
			if(socks5OverTlsFlag == 0){	// Socks5
				sen = sendSocksResponseIpv4(r, clientSock, 0x5, 0x1, 0x0, 0x1, tv_sec, tv_usec);
			}else{	// Socks5 over TLS
				sen = sendSocksResponseIpv4Tls(r, clientSock, clientSslSocks5, 0x5, 0x1, 0x0, 0x1, tv_sec, tv_usec);
			}
			
			return -1;
		}
	}else if(atyp == 0x4){	// IPv6
		inet_ntop(AF_INET6, &targetAddr6.sin6_addr, pTargetAddr6String, INET6_ADDRSTRLEN);
#ifdef _DEBUG
		printf("[I] Connecting. ip:%s port:%d\n", pTargetAddr6String, ntohs(targetAddr6.sin6_port));
		ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[I] Connecting. ip:%s port:%d", pTargetAddr6String, ntohs(targetAddr6.sin6_port));
#endif

		if(cmd == 0x1){	// CONNECT
#ifdef _DEBUG
			printf("[I] SOCKS_RESPONSE cmd:CONNECT.\n");
			ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[I] SOCKS_RESPONSE cmd:CONNECT.");
#endif
			targetSock = socket(AF_INET6, SOCK_STREAM, 0);
			
			flags = fcntl(targetSock, F_GETFL, 0);
			flags &= ~O_NONBLOCK;
			fcntl(targetSock, F_SETFL, flags);
			
			if((err = connect(targetSock, (struct sockaddr *)&targetAddr6, sizeof(targetAddr6))) < 0){
#ifdef _DEBUG
				printf("[E] Cannnot connect. errno:%d\n", err);
				ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[E] Cannnot connect. errno:%d", err);
#endif
				
				if(socks5OverTlsFlag == 0){	// Socks5
					sen = sendSocksResponseIpv6(r, clientSock, 0x5, 0x5, 0x0, 0x4, tv_sec, tv_usec);
				}else{	// Socks5 over TLS
					sen = sendSocksResponseIpv6Tls(r, clientSock, clientSslSocks5, 0x5, 0x5, 0x0, 0x4, tv_sec, tv_usec);
				}
#ifdef _DEBUG
				printf("[I] Socks Request:%d bytes, Socks Response:%d bytes.\n", rec, sen);
				ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[I] Socks Request:%d bytes, Socks Response:%d bytes.", rec, sen);
#endif

				close(targetSock);

				return -1;
			}

#ifdef _DEBUG
			printf("[I] Connected. ip:%s port:%d\n", pTargetAddr6String, ntohs(targetAddr6.sin6_port));
			ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[I] Connected. ip:%s port:%d", pTargetAddr6String, ntohs(targetAddr6.sin6_port));
#endif
			
			if(socks5OverTlsFlag == 0){	// Socks5
				sen = sendSocksResponseIpv6(r, clientSock, 0x5, 0x0, 0x0, 0x4, tv_sec, tv_usec);
			}else{	// Socks5 over TLS
				sen = sendSocksResponseIpv6Tls(r, clientSock, clientSslSocks5, 0x5, 0x0, 0x0, 0x4, tv_sec, tv_usec);
			}
#ifdef _DEBUG
			printf("[I] Socks Request:%d bytes, Socks Response:%d bytes.\n", rec, sen);
			ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[I] Socks Request:%d bytes, Socks Response:%d bytes.", rec, sen);
#endif

		}else if(cmd == 0x2){	// BIND
#ifdef _DEBUG
			printf("[I] SOCKS_RESPONSE cmd:BIND.\n");
			ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[I] SOCKS_RESPONSE cmd:BIND.");
			printf("[E] Not implemented.\n");
			ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[E] Not implemented.");
#endif
			
			if(socks5OverTlsFlag == 0){	// Socks5
				sen = sendSocksResponseIpv6(r, clientSock, 0x5, 0x7, 0x0, 0x4, tv_sec, tv_usec);
			}else{	// Socks5 over TLS
				sen = sendSocksResponseIpv6Tls(r, clientSock, clientSslSocks5, 0x5, 0x7, 0x0, 0x4, tv_sec, tv_usec);
			}
			
			return -1;
		}else if(cmd == 0x3){	// UDP ASSOCIATE
#ifdef _DEBUG
			printf("[I] SOCKS_RESPONSE cmd:UDP ASSOCIATE.\n");
			ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[I] SOCKS_RESPONSE cmd:UDP ASSOCIATE.");
#endif
			targetSock = socket(AF_INET6, SOCK_DGRAM, 0);

			flags = fcntl(targetSock, F_GETFL, 0);
			flags &= ~O_NONBLOCK;
			fcntl(targetSock, F_SETFL, flags);
		
			if(connect(targetSock, (struct sockaddr *)&targetAddr6, sizeof(targetAddr6)) < 0){
#ifdef _DEBUG
				printf("[E] Cannnot connect. errno:%d\n", err);
				ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[E] Cannnot connect. errno:%d", err);
#endif
				
				if(socks5OverTlsFlag == 0){	// Socks5
					sen = sendSocksResponseIpv6(r, clientSock, 0x5, 0x5, 0x0, 0x4, tv_sec, tv_usec);
				}else{	// Socks5 over TLS
					sen = sendSocksResponseIpv6Tls(r, clientSock, clientSslSocks5, 0x5, 0x5, 0x0, 0x4, tv_sec, tv_usec);
				}
#ifdef _DEBUG
				printf("[I] Socks Request:%d bytes, Socks Response:%d bytes.\n", rec, sen);
				ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[I] Socks Request:%d bytes, Socks Response:%d bytes.", rec, sen);
#endif

				close(targetSock);

				return -1;
			}

#ifdef _DEBUG
			printf("[I] Connected. ip:%s port:%d\n", pTargetAddr6String, ntohs(targetAddr6.sin6_port));
			ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[I] Connected. ip:%s port:%d", pTargetAddr6String, ntohs(targetAddr6.sin6_port));
#endif
			
			if(socks5OverTlsFlag == 0){	// Socks5
				sen = sendSocksResponseIpv6(r, clientSock, 0x5, 0x0, 0x0, 0x4, tv_sec, tv_usec);
			}else{	// Socks5 over TLS
				sen = sendSocksResponseIpv6Tls(r, clientSock, clientSslSocks5, 0x5, 0x0, 0x0, 0x4, tv_sec, tv_usec);
			}
#ifdef _DEBUG
			printf("[I] Socks Request:%d bytes, Socks Response:%d bytes.\n", rec, sen);
			ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[I] Socks Request:%d bytes, Socks Response:%d bytes.", rec, sen);
#endif
			
		}else{
#ifdef _DEBUG
			printf("[E] Not implemented.\n");
			ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[E] Not implemented.");
#endif
			
			if(socks5OverTlsFlag == 0){	// Socks5
				sen = sendSocksResponseIpv6(r, clientSock, 0x5, 0x1, 0x0, 0x4, tv_sec, tv_usec);
			}else{	// Socks5 over TLS
				sen = sendSocksResponseIpv6Tls(r, clientSock, clientSslSocks5, 0x5, 0x1, 0x0, 0x4, tv_sec, tv_usec);
			}
			
			return -1;
		}
	}else{
#ifdef _DEBUG
		printf("[E] Not implemented.\n");
		ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[E] Not implemented.");
#endif
		
		if(socks5OverTlsFlag == 0){	// Socks5
			sen = sendSocksResponseIpv4(r, clientSock, 0x5, 0x1, 0x0, 0x1, tv_sec, tv_usec);
		}else{	// Socks5 over TLS
			sen = sendSocksResponseIpv4Tls(r, clientSock, clientSslSocks5, 0x5, 0x1, 0x0, 0x1, tv_sec, tv_usec);
		}
		
		return -1;
	}
	
	
	// forwarder
#ifdef _DEBUG
	printf("[I] Forwarder.\n");
	ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[I] Forwarder.");
#endif
	if(socks5OverTlsFlag == 0){	// Socks5
		err = forwarder(r, clientSock, targetSock, tv_sec, tv_usec);
	}else{	// Socks5 over TLS
		err = forwarderTls(r, clientSock, targetSock, clientSslSocks5, tv_sec, tv_usec);
	}
	
#ifdef _DEBUG
	printf("[I] Worker exit.\n");
	ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[I] Worker exit.");
#endif
	close(targetSock);
	
	return 0;
}


void finiSsl(pSSLPARAM pSslParam)
{
	// Socks5 over TLS
	if(pSslParam->clientSslSocks5 != NULL){
		SSL_shutdown(pSslParam->clientSslSocks5);
		SSL_free(pSslParam->clientSslSocks5);
	}
	if(pSslParam->clientCtxSocks5 != NULL){
		SSL_CTX_free(pSslParam->clientCtxSocks5);
	}

	return;
}


static ngx_table_elt_t *search_headers_in(ngx_http_request_t *r, u_char *name, size_t len)
{
	ngx_list_part_t *part;
	ngx_table_elt_t *h;
	ngx_uint_t i;
	
	part = &r->headers_in.headers.part;
	h = part->elts;
	
	for(i = 0; ; i++){
		if(i >= part->nelts){
			if(part->next == NULL){
				break;
			}
			
			part = part->next;
			h = part->elts;
			i = 0;
		}
		
		if(len != h[i].key.len || ngx_strcasecmp(name, h[i].key.data) != 0){
			continue;
		}
		
		return &h[i];
	}
	
	return NULL;
}


static ngx_int_t ngx_http_socks5_header_filter(ngx_http_request_t *r)
{
	ngx_table_elt_t *h;
	int flag = 0;
	int clientSock = r->connection->fd;
	int flags = 0;
	int ret = 0;
	int err = 0;
	int socks5OverTlsFlag = 0;	// 0:socks5 1:socks5 over tls
	
	SSL_CTX *clientCtxSocks5 = NULL;
	SSL *clientSslSocks5 = NULL;
	
	PARAM param;
	long tv_sec = 3;
	long tv_usec = 0;
	SSLPARAM sslParam;
	sslParam.clientCtxSocks5 = NULL;
	sslParam.clientSslSocks5 = NULL;

	BIO *bio = NULL;
	EVP_PKEY *sprivatekey = NULL;
	X509 *scert = NULL;
	

	// search header
	h = search_headers_in(r, (u_char *)HTTP_REQUEST_HEADER_SOCKS5_KEY, (size_t)(strlen(HTTP_REQUEST_HEADER_SOCKS5_KEY)));
	if(h != NULL &&  ngx_strcasecmp(h->value.data, (u_char *)HTTP_REQUEST_HEADER_SOCKS5_VALUE) == 0){	// socks5
		flag = 1;
	}
	
	h = search_headers_in(r, (u_char *)HTTP_REQUEST_HEADER_TLS_KEY, (size_t)(strlen(HTTP_REQUEST_HEADER_TLS_KEY)));
	if(h != NULL &&  ngx_strcasecmp(h->value.data, (u_char *)HTTP_REQUEST_HEADER_TLS_VALUE2) == 0){
		socks5OverTlsFlag = 1;	// socks5 over tls
	}else{
		socks5OverTlsFlag = 0;	// socks5
	}
	
	h = search_headers_in(r, (u_char *)HTTP_REQUEST_HEADER_TVSEC_KEY, (size_t)(strlen(HTTP_REQUEST_HEADER_TVSEC_KEY)));
	if(h != NULL){
		tv_sec =atol((char *)h->value.data);
	}
	
	h = search_headers_in(r, (u_char *)HTTP_REQUEST_HEADER_TVUSEC_KEY, (size_t)(strlen(HTTP_REQUEST_HEADER_TVUSEC_KEY)));
	if(h != NULL){
		tv_usec =atol((char *)h->value.data);
	}
	
	
	if(flag == 1){	// socks5
#ifdef _DEBUG
		printf("[I] Socks5 start.\n");
		ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[I] Socks5 start.");
#endif
		
		if(tv_sec < 0 || tv_sec > 300 || tv_usec < 0 || tv_usec > 1000000){
			tv_sec = 3;
			tv_usec = 0;
		}else if(tv_sec == 0 && tv_usec == 0){
			tv_sec = 3;
			tv_usec = 0;
		}
#ifdef _DEBUG
		printf("[I] Timeout tv_sec:%ld sec tv_usec:%ld microsec.\n", tv_sec, tv_usec);
		ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[I] Timeout tv_sec:%ld sec tv_usec:%ld microsec.", tv_sec, tv_usec);
#endif

		// non blocking
		flags = fcntl(clientSock, F_GETFL, 0);
		flags &= ~O_NONBLOCK;
		fcntl(clientSock, F_SETFL, flags);
		
		// send OK to client
		ret = sendData(r, clientSock, "OK", strlen("OK"), tv_sec, tv_usec);
#ifdef _DEBUG
		printf("[I] Send OK message.\n");
		ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[I] Send OK message.");
#endif
		
		if(socks5OverTlsFlag == 1){	// Socks5 over TLS
			// SSL Initialize
			OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS, NULL);
			
			// SSL TLS connection
			clientCtxSocks5 = SSL_CTX_new(TLS_server_method());
			if(clientCtxSocks5 == NULL){
#ifdef _DEBUG
				printf("[E] SSL_CTX_new error.\n");
				ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[E] SSL_CTX_new error.");
#endif
				return ngx_http_next_header_filter(r);
			}
			sslParam.clientCtxSocks5 = clientCtxSocks5;
			
			// server private key (Socks5 over TLS)
			bio = BIO_new(BIO_s_mem());
			BIO_write(bio, serverPrivateKey, strlen(serverPrivateKey));
			PEM_read_bio_PrivateKey(bio, &sprivatekey, NULL, NULL);
			BIO_free(bio);
			
			// server X509 certificate (Socks5 over TLS)
			bio = BIO_new(BIO_s_mem());
			BIO_write(bio, serverCertificate, strlen(serverCertificate));
			PEM_read_bio_X509(bio, &scert, NULL, NULL);
			BIO_free(bio);

			SSL_CTX_use_certificate(clientCtxSocks5, scert);
			SSL_CTX_use_PrivateKey(clientCtxSocks5, sprivatekey);
			err = SSL_CTX_check_private_key(clientCtxSocks5);
			if(err != 1){
#ifdef _DEBUG
				printf("[E] SSL_CTX_check_private_key error.\n");
				ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[E] SSL_CTX_check_private_key error.");
#endif
				finiSsl(&sslParam);
				return ngx_http_next_header_filter(r);
			}
			
			SSL_CTX_set_mode(clientCtxSocks5, SSL_MODE_AUTO_RETRY);
			
			if(SSL_CTX_set_min_proto_version(clientCtxSocks5, TLS1_2_VERSION) == 0){
#ifdef _DEBUG
				printf("[E] SSL_CTX_set_min_proto_version error.\n");
				ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[E] SSL_CTX_set_min_proto_version error.");
#endif
				finiSsl(&sslParam);
				return ngx_http_next_header_filter(r);
			}
			
			ret = SSL_CTX_set_cipher_list(clientCtxSocks5, cipherSuiteTLS1_2);
			if(ret == 0){
#ifdef _DEBUG
				printf("[E] SSL_CTX_set_cipher_list error.\n");
				ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[E] SSL_CTX_set_cipher_list error.");
#endif
				finiSsl(&sslParam);
				return ngx_http_next_header_filter(r);
			}
			
			ret = SSL_CTX_set_ciphersuites(clientCtxSocks5, cipherSuiteTLS1_3);
			if(ret == 0){
#ifdef _DEBUG
				printf("[E] SSL_CTX_set_ciphersuites error.\n");
				ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[E] SSL_CTX_set_ciphersuites error.");
#endif
				finiSsl(&sslParam);
				return ngx_http_next_header_filter(r);
			}
			
			clientSslSocks5 = SSL_new(clientCtxSocks5);
			if(clientSslSocks5 == NULL){
#ifdef _DEBUG
				printf("[E] SSL_new error.\n");
				ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[E] SSL_new error.");
#endif
				finiSsl(&sslParam);
				return ngx_http_next_header_filter(r);
			}
			sslParam.clientSslSocks5 = clientSslSocks5;
			
			if(SSL_set_fd(clientSslSocks5, clientSock) == 0){
#ifdef _DEBUG
				printf("[E] SSL_set_fd error.\n");
				ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[E] SSL_set_fd error.");
#endif
				finiSsl(&sslParam);
				return ngx_http_next_header_filter(r);
			}
			
			// accept
#ifdef _DEBUG
			printf("[I] Try Socks5 over TLS connection. (SSL_accept)\n");
			ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[I] Try Socks5 over TLS connection. (SSL_accept)");
#endif
			ret = SSL_accept(clientSslSocks5);
			if(ret <= 0){
				err = SSL_get_error(clientSslSocks5, ret);
#ifdef _DEBUG
				printf("[E] SSL_accept error:%d:%s.\n", err, ERR_error_string(ERR_peek_last_error(), NULL));
				ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[E] SSL_accept error:%d:%s.", err, ERR_error_string(ERR_peek_last_error(), NULL));
#endif
				finiSsl(&sslParam);
				return ngx_http_next_header_filter(r);
			}
#ifdef _DEBUG
			printf("[I] Succeed Socks5 over TLS connection. (SSL_accept)\n");
			ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[I] Succeed Socks5 over TLS connection. (SSL_accept)");
#endif
		}
		
		param.clientSock = clientSock;
		param.clientSslSocks5 = clientSslSocks5;
		param.socks5OverTlsFlag = socks5OverTlsFlag;
		param.tv_sec = tv_sec;
		param.tv_usec = tv_usec;
		
		ret = worker(r, &param);
		
		finiSsl(&sslParam);
	}

	return ngx_http_next_header_filter(r);
}


static ngx_int_t ngx_http_socks5_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
	return ngx_http_next_body_filter(r, in);
}


static ngx_int_t ngx_http_socks5_init(ngx_conf_t *cf)
{
	ngx_http_next_header_filter = ngx_http_top_header_filter;
	ngx_http_top_header_filter = ngx_http_socks5_header_filter;
	
	ngx_http_next_body_filter = ngx_http_top_body_filter;
	ngx_http_top_body_filter = ngx_http_socks5_body_filter;

	return NGX_OK;
}

