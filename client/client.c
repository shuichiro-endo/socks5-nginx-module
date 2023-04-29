/*
 * Title:  socks5 client (nginx module)
 * Author: Shuichiro Endo
 */

#define _DEBUG

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "socks5.h"
#include "client.h"

#define BUFFER_SIZE 8192

#define HTTP_REQUEST_HEADER_SOCKS5_KEY "socks5"
#define HTTP_REQUEST_HEADER_SOCKS5_VALUE "socks5"
#define HTTP_REQUEST_HEADER_AESKEY_KEY "aeskey"
#define HTTP_REQUEST_HEADER_AESIV_KEY "aesiv"
#define HTTP_REQUEST_HEADER_TLS_KEY "tls"
#define HTTP_REQUEST_HEADER_TLS_VALUE1 "off"	// Socks5 over AES
#define HTTP_REQUEST_HEADER_TLS_VALUE2 "on"	// Socks5 over TLS
#define HTTP_REQUEST_HEADER_TVSEC_KEY "sec"	// recv/send tv_sec
#define HTTP_REQUEST_HEADER_TVUSEC_KEY "usec"	// recv/send tv_usec
#define HTTP_REQUEST_HEADER_FORWARDER_TVSEC_KEY "forwardersec"		// forwarder tv_sec
#define HTTP_REQUEST_HEADER_FORWARDER_TVUSEC_KEY "forwarderusec"	// forwarder tv_usec

char *socks5ServerIp = NULL;
char *socks5ServerPort = NULL;
char *socks5TargetIp = NULL;
char *socks5TargetPort = NULL;
int httpsFlag = 0;		// 0:http 1:https
int socks5OverTlsFlag = 0;	// 0:socks5 over aes 1:socks5 over tls

char serverCertificateFilenameHttps[256] = "server_https.crt";	// server certificate file name (HTTPS)
char serverCertificateFileDirectoryPathHttps[256] = ".";	// server certificate file directory path (HTTPS)

char serverCertificateFilenameSocks5[256] = "server_socks5.crt";	// server certificate file name (Socks5 over TLS)
char serverCertificateFileDirectoryPathSocks5[256] = ".";	// server certificate file directory path (Socks5 over TLS)


int aesEncrypt(unsigned char *plaintext, int plaintext_length, unsigned char *aes_key, unsigned char *aes_iv, unsigned char *ciphertext)
{
	EVP_CIPHER_CTX *ctx;
	int length;
	int ciphertext_length;
	int ret;
	
	ctx = EVP_CIPHER_CTX_new();
	if(ctx == NULL){
#ifdef _DEBUG
//		printf("[E] EVP_CIPHER_CTX_new error.\n");
#endif
		return -1;
	}
	
	ret = EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, aes_iv);
	if(ret != 1){
#ifdef _DEBUG
//		printf("[E] EVP_EncryptInit_ex error.\n");
#endif
		return -1;
	}
	
	ret = EVP_EncryptUpdate(ctx, ciphertext, &length, plaintext, plaintext_length);
	if(ret != 1){
#ifdef _DEBUG
//		printf("[E] EVP_EncryptUpdate error.\n");
#endif
		return -1;
	}
	ciphertext_length = length;
	
	ret = EVP_EncryptFinal_ex(ctx, ciphertext+length, &length);
	if(ret != 1){
#ifdef _DEBUG
//		printf("[E] EVP_EncryptFinal_ex error.\n");
#endif
		return -1;
	}
	ciphertext_length += length;
	
	EVP_CIPHER_CTX_free(ctx);
	
	return ciphertext_length;
}


int aesDecrypt(unsigned char *ciphertext, int ciphertext_length, unsigned char *aes_key, unsigned char *aes_iv, unsigned char *plaintext)
{
	EVP_CIPHER_CTX *ctx;
	int length;
	int plaintext_length;
	int ret;
	
	ctx = EVP_CIPHER_CTX_new();
	if(ctx == NULL){
#ifdef _DEBUG
//		printf("[E] EVP_CIPHER_CTX_new error.\n");
#endif
		return -1;
	}
	
	ret = EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, aes_iv);
	if(ret != 1){
#ifdef _DEBUG
//		printf("[E] EVP_DecryptInit_ex error.\n");
#endif
		return -1;
	}
	
	ret = EVP_DecryptUpdate(ctx, plaintext, &length, ciphertext, ciphertext_length);
	if(ret != 1){
#ifdef _DEBUG
//		printf("[E] EVP_DecryptUpdate error.\n");
#endif
		return -1;
	}
	plaintext_length = length;
	
	ret = EVP_DecryptFinal_ex(ctx, plaintext+length, &length);
	if(ret != 1){
#ifdef _DEBUG
//		printf("[E] EVP_DecryptFinal_ex error.\n");
#endif
		return -1;
	}
	plaintext_length += length;
	
	EVP_CIPHER_CTX_free(ctx);
	
	return plaintext_length;
}


int recvData(int sock, void *buffer, int length, long tv_sec, long tv_usec)
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


int recvDataAes(int sock, void *buffer, int length, unsigned char *aes_key, unsigned char *aes_iv, long tv_sec, long tv_usec)
{
	int rec = 0;
	fd_set readfds;
	int nfds = -1;
	struct timeval tv;
	bzero(buffer, length+1);
	pSEND_RECV_DATA pData;
	unsigned char *buffer2 = calloc(BUFFER_SIZE*2, sizeof(unsigned char));
	int ret = 0;
	int encryptDataLength = 0;
	unsigned char *tmp = calloc(16, sizeof(unsigned char));
	
	while(1){
		FD_ZERO(&readfds);
		FD_SET(sock, &readfds);
		nfds = sock + 1;
		tv.tv_sec = tv_sec;
		tv.tv_usec = tv_usec;
		
		if(select(nfds, &readfds, NULL, NULL, &tv) == 0){
#ifdef _DEBUG
			printf("[I] recvDataAes timeout.\n");
#endif
			break;
		}
		
		if(FD_ISSET(sock, &readfds)){
			rec = recv(sock, buffer2, BUFFER_SIZE*2, 0);
			if(rec <= 0){
				if(errno == EINTR){
					continue;
				}else if(errno == EAGAIN){
					usleep(5000);
					continue;
				}else{
					free(buffer2);
					free(tmp);
					return -1;
				}
			}else if(rec >= 16){	// unsigned char encryptDataLength[16]
				pData = (pSEND_RECV_DATA)buffer2;
				
				ret = aesDecrypt(pData->encryptDataLength, 16, aes_key, aes_iv, (unsigned char *)tmp);
				if(ret == 4){	// int encryptDataLength
					encryptDataLength = (tmp[0] << 24)|(tmp[1]<<16)|(tmp[2]<<8)|(tmp[3]);
				}else{
					free(buffer2);
					free(tmp);
					return -1;
				}
				
				if(encryptDataLength <= rec-16){
					ret = aesDecrypt(pData->encryptData, encryptDataLength, aes_key, aes_iv, (unsigned char *)buffer);
					if(ret > 0){
						rec = ret;
					}else{
						free(buffer2);
						free(tmp);
						return -1;
					}
					
					break;
				}else{
					break;
				}
			}else{
				break;
			}
		}
	}
	
	free(buffer2);
	free(tmp);
	return rec;
}


int recvDataTls(int sock, SSL *ssl ,void *buffer, int length, long tv_sec, long tv_usec)
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
#endif
				return -2;
			}
		}
	}
	
	return rec;
}


int sendData(int sock, void *buffer, int length, long tv_sec, long tv_usec)
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
#endif
			break;
		}
		
		if(FD_ISSET(sock, &writefds)){
			sen = send(sock, buffer+sendLength, len, 0);
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


int sendDataAes(int sock, void *buffer, int length, unsigned char *aes_key, unsigned char *aes_iv, long tv_sec, long tv_usec)
{
	int sen = 0;
	int sendLength = 0;
	int len = 0;
	fd_set writefds;
	int nfds = -1;
	struct timeval tv;
	SEND_RECV_DATA data;
	bzero(data.encryptDataLength, 16);
	bzero(data.encryptData, BUFFER_SIZE*2);
	int ret = 0;
	int encryptDataLength = 0;
	unsigned char *tmp = calloc(16, sizeof(unsigned char));
	
	ret = aesEncrypt((unsigned char *)buffer, length, aes_key, aes_iv, data.encryptData);
	if(ret > 0){
		encryptDataLength = ret;
	}else{
		free(tmp);
		return -1;
	}
	
	tmp[0] = (unsigned char)(encryptDataLength >> 24);
	tmp[1] = (unsigned char)(encryptDataLength >> 16);
	tmp[2] = (unsigned char)(encryptDataLength >> 8);
	tmp[3] = (unsigned char)encryptDataLength;
	ret = aesEncrypt((unsigned char *)tmp, 4, aes_key, aes_iv, data.encryptDataLength);
	if(ret != 16){	// unsigned char encryptDataLength[16]
		free(tmp);
		return -1;
	}
	
	len = 16 + encryptDataLength;
	
	while(len > 0){
		FD_ZERO(&writefds);
		FD_SET(sock, &writefds);
		nfds = sock + 1;
		tv.tv_sec = tv_sec;
		tv.tv_usec = tv_usec;
		
		if(select(nfds, NULL, &writefds, NULL, &tv) == 0){
#ifdef _DEBUG
			printf("[I] sendDataAes timeout.\n");
#endif
			break;
		}
		
		if(FD_ISSET(sock, &writefds)){
			sen = send(sock, (unsigned char *)&data+sendLength, len, 0);
			if(sen <= 0){
				if(errno == EINTR){
					continue;
				}else if(errno == EAGAIN){
					usleep(5000);
					continue;
				}else{
					free(tmp);
					return -1;
				}
			}
			sendLength += sen;
			len -= sen;
		}
	}
	
	return sendLength;
}


int sendDataTls(int sock, SSL *ssl, void *buffer, int length, long tv_sec, long tv_usec)
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
#endif
				return -2;
			}
		}
	}
		
	return sen;
}


int forwarder(int clientSock, int targetSock, long tv_sec, long tv_usec)
{
	int rec,sen;
	fd_set readfds;
	int nfds = -1;
	struct timeval tv;
	char buffer[BUFFER_SIZE+1];
	bzero(buffer, BUFFER_SIZE+1);
	
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
#endif
			break;
		}
		
		if(FD_ISSET(clientSock, &readfds)){
			if((rec = read(clientSock, buffer, BUFFER_SIZE)) > 0){
				sen = write(targetSock, buffer, rec);
				if(sen <= 0){
					break;
				}
			}else{
				break;
			}
		}
		
		if(FD_ISSET(targetSock, &readfds)){
			if((rec = read(targetSock, buffer, BUFFER_SIZE)) > 0){
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


int forwarderAes(int clientSock, int targetSock, unsigned char *aes_key, unsigned char *aes_iv, long tv_sec, long tv_usec)
{
	int rec,sen;
	fd_set readfds;
	int nfds = -1;
	struct timeval tv;
	unsigned char *buffer = calloc(BUFFER_SIZE*10, sizeof(unsigned char));
	int ret = 0;
	int recvLength = 0;
	int len = 0;
	int index = 0;
	FORWARDER_DATA data;
	pFORWARDER_DATA pData;
	int encryptDataLength = 0;
	unsigned char *tmp = calloc(16, sizeof(unsigned char));
	unsigned char *buffer2 = calloc(BUFFER_SIZE*10, sizeof(unsigned char));
	
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
#endif
			break;
		}
		
		if(FD_ISSET(clientSock, &readfds)){
			bzero(buffer, BUFFER_SIZE*10);
			bzero(&data.encryptDataLength, 16);
			bzero(&data.encryptData, BUFFER_SIZE*10);
			bzero(tmp, 16);
			
			if((rec = read(clientSock, buffer, BUFFER_SIZE)) > 0){
				ret = aesEncrypt((unsigned char *)buffer, rec, aes_key, aes_iv, data.encryptData);
				if(ret > 0){
					encryptDataLength = ret;
				}else{
					free(buffer);
					free(buffer2);
					free(tmp);
					return -1;
				}
				
				tmp[0] = (unsigned char)(encryptDataLength >> 24);
				tmp[1] = (unsigned char)(encryptDataLength >> 16);
				tmp[2] = (unsigned char)(encryptDataLength >> 8);
				tmp[3] = (unsigned char)encryptDataLength;
				ret = aesEncrypt((unsigned char *)tmp, 4, aes_key, aes_iv, data.encryptDataLength);
				if(ret != 16){	// unsigned char encryptDataLength[16]
					free(buffer);
					free(buffer2);
					free(tmp);
					return -1;
				}
				
				len = 16 + encryptDataLength;
				sen = write(targetSock, (unsigned char *)&data, len);
				if(sen <= 0){
					break;
				}
			}else{
				break;
			}
		}
		
		if(FD_ISSET(targetSock, &readfds)){
			bzero(buffer, BUFFER_SIZE*10);
			bzero(buffer2, BUFFER_SIZE*10);
			bzero(tmp, 16);
			
			if((rec = read(targetSock, buffer, BUFFER_SIZE*10)) > 0){
				recvLength = rec;
				len = rec;
				index = 0;
				
				while(len > 0){
					if(len >= 16){
						pData = (pFORWARDER_DATA)(buffer + index);
						
						ret = aesDecrypt(pData->encryptDataLength, 16, aes_key, aes_iv, tmp);
						if(ret != 4){	// int encryptDataLength
							free(buffer);
							free(buffer2);
							free(tmp);
							return -1;
						}
						encryptDataLength = (tmp[0] << 24)|(tmp[1]<<16)|(tmp[2]<<8)|(tmp[3]);
						
						if(index + 16 + encryptDataLength <= recvLength){
							rec = aesDecrypt(pData->encryptData, encryptDataLength, aes_key, aes_iv, buffer2);
							if(rec < 0){
								free(buffer);
								free(buffer2);
								free(tmp);
								return -1;
							}
							
							sen = write(clientSock, buffer2, rec);
							if(sen <= 0){
								free(buffer);
								free(buffer2);
								free(tmp);
								return -1;
							}
							
							index += 16 + encryptDataLength;
							len -= 16 + encryptDataLength;
						}else{
							break;
						}
					}else{
						break;
					}
				}
			}else{
				break;
			}
		}
	}
	
	free(buffer);
	free(buffer2);
	free(tmp);
	return 0;
}


int forwarderTls(int clientSock, int targetSock, SSL *targetSsl, long tv_sec, long tv_usec)
{
	int rec,sen;
	fd_set readfds;
	int nfds = -1;
	struct timeval tv;
	char buffer[BUFFER_SIZE+1];
	bzero(buffer, BUFFER_SIZE+1);
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
#endif
			break;
		}
		
		if(FD_ISSET(clientSock, &readfds)){
			if((rec = read(clientSock, buffer, BUFFER_SIZE)) > 0){
				while(1){
					sen = SSL_write(targetSsl, buffer, rec);
					err = SSL_get_error(targetSsl, sen);
					
					if(err == SSL_ERROR_NONE){
						break;
					}else if(err == SSL_ERROR_WANT_WRITE){
						usleep(5000);
					}else if(err == SSL_ERROR_WANT_READ){
						usleep(5000);
					}else{
#ifdef _DEBUG
						printf("[E] SSL_read error:%d:%s.\n", err, ERR_error_string(ERR_peek_last_error(), NULL));
#endif
						return -2;
					}
				}
			}else{
				break;
			}
		}
		
		if(FD_ISSET(targetSock, &readfds)){
			rec = SSL_read(targetSsl, buffer, BUFFER_SIZE);
			err = SSL_get_error(targetSsl, rec);
			
			if(err == SSL_ERROR_NONE){
				sen = write(clientSock, buffer, rec);
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
				printf("[E] SSL_write error:%d:%s.\n", err, ERR_error_string(ERR_peek_last_error(), NULL));
#endif
				return -2;
			}
		}
	}

	return 0;
}


void finiSsl(pSSLPARAM pSslParam)
{
	// Socks5 over TLS
	if(pSslParam->targetSslSocks5 != NULL){
		SSL_shutdown(pSslParam->targetSslSocks5);
		SSL_free(pSslParam->targetSslSocks5);
	}
	if(pSslParam->targetCtxSocks5 != NULL){
		SSL_CTX_free(pSslParam->targetCtxSocks5);
	}
	
	// HTTPS
	if(pSslParam->targetSslHttp != NULL){
//		SSL_shutdown(pSslParam->targetSslHttp);
		SSL_free(pSslParam->targetSslHttp);
	}
	if(pSslParam->targetCtxHttp != NULL){
		SSL_CTX_free(pSslParam->targetCtxHttp);
	}

	return;
}


int worker(void *ptr)
{
	pPARAM pParam = (pPARAM)ptr;
	int clientSock = pParam->clientSock;
	long tv_sec = pParam->tv_sec;		// recv send
	long tv_usec = pParam->tv_usec;		// recv send
	long forwarder_tv_sec = pParam->forwarder_tv_sec;
	long forwarder_tv_usec = pParam->forwarder_tv_usec;
	
	int targetSock = -1;
	struct sockaddr_in targetAddr, *pTmpIpv4;		// IPv4
	memset(&targetAddr, 0, sizeof(struct sockaddr_in));
	
	struct sockaddr_in6 targetAddr6, *pTmpIpv6;	// IPv6
	memset(&targetAddr6, 0, sizeof(struct sockaddr_in6));

	struct addrinfo hints, *pTargetHost;
	memset(&hints, 0, sizeof(struct addrinfo));	

	int family = 0;
	char *domainname = socks5TargetIp;
	u_short domainnameLength = strlen(domainname);
	char *colon = NULL;
	char *service = socks5TargetPort;
	int flags = 0;
	
	int ret = 0;
	int err = 0;
	
	SSL_CTX *targetCtxHttp = NULL;
	SSL *targetSslHttp = NULL;
	SSL_CTX *targetCtxSocks5 = NULL;
	SSL *targetSslSocks5 = NULL;

	SSLPARAM sslParam;
	sslParam.targetCtxHttp = NULL;
	sslParam.targetSslHttp = NULL;
	sslParam.targetCtxSocks5 = NULL;
	sslParam.targetSslSocks5 = NULL;

	char buffer[BUFFER_SIZE+1];
	bzero(&buffer, BUFFER_SIZE+1);
	int rec, sen;
	int count = 0;
	int check = 0;
	
	char httpRequest[BUFFER_SIZE+1];
	int httpRequestLength = 0;
	bzero(httpRequest, BUFFER_SIZE+1);
	
	EVP_ENCODE_CTX *base64EncodeCtx = NULL;
	int length = 0;
	unsigned char aes_key[33];
	bzero(&aes_key, 33);
	ret = RAND_bytes((unsigned char *)aes_key, 32);
	if(ret != 1){
#ifdef _DEBUG
		printf("[E] aes key generate error:%s.\n", ERR_error_string(ERR_peek_last_error(), NULL));
#endif
		close(clientSock);
		return -1;
	}
	unsigned char aes_key_b64[45];
	bzero(&aes_key_b64, 45);
	base64EncodeCtx = EVP_ENCODE_CTX_new();
	EVP_EncodeInit(base64EncodeCtx);
	EVP_EncodeUpdate(base64EncodeCtx, (unsigned char *)aes_key_b64, &length, (unsigned char *)aes_key, 32);
	EVP_EncodeFinal(base64EncodeCtx, (unsigned char *)aes_key_b64, &length);
	EVP_ENCODE_CTX_free(base64EncodeCtx);
	aes_key_b64[44] = 0x0;	// delete newline character
#ifdef _DEBUG
	printf("[I] aes key (base64):%s\n", aes_key_b64);
#endif
	
	unsigned char aes_iv[17];
	bzero(&aes_iv, 17);
	ret = RAND_bytes((unsigned char *)aes_iv, 16);
	if(ret != 1){
#ifdef _DEBUG
		printf("[E] aes iv generate error:%s.\n", ERR_error_string(ERR_peek_last_error(), NULL));
#endif
		close(clientSock);
		return -1;
	}
	unsigned char aes_iv_b64[25];
	bzero(&aes_iv_b64, 25);
	base64EncodeCtx = EVP_ENCODE_CTX_new();
	EVP_EncodeInit(base64EncodeCtx);
	EVP_EncodeUpdate(base64EncodeCtx, (unsigned char *)aes_iv_b64, &length, (unsigned char *)aes_iv, 16);
	EVP_EncodeFinal(base64EncodeCtx, (unsigned char *)aes_iv_b64, &length);
	EVP_ENCODE_CTX_free(base64EncodeCtx);
	aes_iv_b64[24] = 0x0;	// delete newline character
#ifdef _DEBUG
	printf("[I] aes iv  (base64):%s\n", aes_iv_b64);
#endif
	
	
#ifdef _DEBUG
	printf("[I] Domainname:%s, Length:%d.\n", domainname, domainnameLength);
#endif
	colon = strstr(domainname, ":");	// check ipv6 address
	if(colon == NULL){	// ipv4 address or domainname
		hints.ai_family = AF_INET;	// IPv4
		if(getaddrinfo(domainname, service, &hints, &pTargetHost) != 0){
			hints.ai_family = AF_INET6;	// IPv6
			if(getaddrinfo(domainname, service, &hints, &pTargetHost) != 0){
#ifdef _DEBUG
				printf("[E] Cannnot resolv the domain name:%s.\n", domainname);
#endif
				close(clientSock);
				return -1;
			}
		}
	}else{	// ipv6 address
		hints.ai_family = AF_INET6;	// IPv6
		if(getaddrinfo(domainname, service, &hints, &pTargetHost) != 0){
#ifdef _DEBUG
			printf("[E] Cannnot resolv the domain name:%s.\n", domainname);
#endif
			close(clientSock);
			return -1;
		}
	}

	if(pTargetHost->ai_family == AF_INET){
		family = AF_INET;
		targetAddr.sin_family = AF_INET;
		pTmpIpv4 = (struct sockaddr_in *)pTargetHost->ai_addr;
		memcpy(&targetAddr.sin_addr, &pTmpIpv4->sin_addr, sizeof(unsigned long));
		memcpy(&targetAddr.sin_port, &pTmpIpv4->sin_port, 2);
		freeaddrinfo(pTargetHost);
	}else if(pTargetHost->ai_family == AF_INET6){
		family = AF_INET6;
		targetAddr6.sin6_family = AF_INET6;
		pTmpIpv6 = (struct sockaddr_in6 *)pTargetHost->ai_addr;
		memcpy(&targetAddr6.sin6_addr, &pTmpIpv6->sin6_addr, sizeof(struct in6_addr));		
		memcpy(&targetAddr6.sin6_port, &pTmpIpv6->sin6_port, 2);;
		freeaddrinfo(pTargetHost);
	}else{
#ifdef _DEBUG
		printf("[E] Not implemented.\n");
#endif
		freeaddrinfo(pTargetHost);
		close(clientSock);
		return -1;
	}

	if(family == AF_INET){	// IPv4
		targetSock = socket(AF_INET, SOCK_STREAM, 0);

		flags = fcntl(targetSock, F_GETFL, 0);
		flags &= ~O_NONBLOCK;
		fcntl(targetSock, F_SETFL, flags);
				
		if(err = connect(targetSock, (struct sockaddr *)&targetAddr, sizeof(targetAddr)) < 0){
#ifdef _DEBUG
			printf("[E] Connect failed. errno:%d\n", err);
#endif
			close(targetSock);
			close(clientSock);
			return -1;
		}
	}else if(family == AF_INET6){	// IPv6
		targetSock = socket(AF_INET6, SOCK_STREAM, 0);
		
		flags = fcntl(targetSock, F_GETFL, 0);
		flags &= ~O_NONBLOCK;
		fcntl(targetSock, F_SETFL, flags);
				
		if(err = connect(targetSock, (struct sockaddr *)&targetAddr6, sizeof(targetAddr6)) < 0){
#ifdef _DEBUG
			printf("[E] Connect failed. errno:%d\n", err);
#endif
			close(targetSock);
			close(clientSock);
			return -1;
		}
	}else{
#ifdef _DEBUG
		printf("[E] Not implemented.\n");
#endif
		close(clientSock);
		return -1;
	}
#ifdef _DEBUG
	printf("[I] Connect target socks5 server.\n");
#endif

	if(socks5OverTlsFlag == 0){	// Socks5 over AES
		httpRequestLength = snprintf(httpRequest, BUFFER_SIZE+1, "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\n%s: %s\r\n%s: %s\r\n%s: %s\r\n%s: %ld\r\n%s: %ld\r\n%s: %ld\r\n%s: %ld\r\nConnection: close\r\n\r\n", domainname, HTTP_REQUEST_HEADER_SOCKS5_KEY, HTTP_REQUEST_HEADER_SOCKS5_VALUE, HTTP_REQUEST_HEADER_AESKEY_KEY, aes_key_b64, HTTP_REQUEST_HEADER_AESIV_KEY, aes_iv_b64, HTTP_REQUEST_HEADER_TVSEC_KEY, tv_sec, HTTP_REQUEST_HEADER_TVUSEC_KEY, tv_usec, HTTP_REQUEST_HEADER_FORWARDER_TVSEC_KEY, forwarder_tv_sec, HTTP_REQUEST_HEADER_FORWARDER_TVUSEC_KEY, forwarder_tv_usec);
	}else{	// Socks5 over TLS
		httpRequestLength = snprintf(httpRequest, BUFFER_SIZE+1, "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\n%s: %s\r\n%s: %s\r\n%s: %s\r\n%s: %s\r\n%s: %ld\r\n%s: %ld\r\n%s: %ld\r\n%s: %ld\r\nConnection: close\r\n\r\n", domainname, HTTP_REQUEST_HEADER_SOCKS5_KEY, HTTP_REQUEST_HEADER_SOCKS5_VALUE, HTTP_REQUEST_HEADER_AESKEY_KEY, aes_key_b64, HTTP_REQUEST_HEADER_AESIV_KEY, aes_iv_b64, HTTP_REQUEST_HEADER_TLS_KEY, HTTP_REQUEST_HEADER_TLS_VALUE2, HTTP_REQUEST_HEADER_TVSEC_KEY, tv_sec, HTTP_REQUEST_HEADER_TVUSEC_KEY, tv_usec, HTTP_REQUEST_HEADER_FORWARDER_TVSEC_KEY, forwarder_tv_sec, HTTP_REQUEST_HEADER_FORWARDER_TVUSEC_KEY, forwarder_tv_usec);
	}
	
	if(httpsFlag == 1){	// HTTPS
		// SSL Initialize
		OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS, NULL);

		// SSL TLS connection
		targetCtxHttp = SSL_CTX_new(TLS_client_method());
		if(targetCtxHttp == NULL){
#ifdef _DEBUG
			printf("[E] SSL_CTX_new error.\n");
#endif
			close(targetSock);
			close(clientSock);
			return -2;
		}
		sslParam.targetCtxHttp = targetCtxHttp;

		SSL_CTX_set_mode(targetCtxHttp, SSL_MODE_AUTO_RETRY);
		
		if(SSL_CTX_set_min_proto_version(targetCtxHttp, TLS1_2_VERSION) == 0){
#ifdef _DEBUG
			printf("[E] SSL_CTX_set_min_proto_version error.\n");
#endif
			finiSsl(&sslParam);
			close(targetSock);
			return -2;
		}
		
		SSL_CTX_set_default_verify_paths(targetCtxHttp);
		SSL_CTX_load_verify_locations(targetCtxHttp, serverCertificateFilenameHttps, serverCertificateFileDirectoryPathHttps);
		SSL_CTX_set_verify(targetCtxHttp, SSL_VERIFY_PEER, NULL);
		
		targetSslHttp = SSL_new(targetCtxHttp);
		if(targetSslHttp == NULL){
#ifdef _DEBUG
			printf("[E] SSL_new error.\n");
#endif
			finiSsl(&sslParam);
			close(targetSock);
			close(clientSock);
			return -2;
		}
		sslParam.targetSslHttp = targetSslHttp;
	
		if(SSL_set_fd(targetSslHttp, targetSock) == 0){
#ifdef _DEBUG
			printf("[E] SSL_set_fd error.\n");
#endif
			finiSsl(&sslParam);
			close(targetSock);
			close(clientSock);
			return -2;
		}
		
#ifdef _DEBUG
		printf("[I] Try HTTPS connection. (SSL_connect)\n");
#endif
		ret = SSL_connect(targetSslHttp);
		if(ret <= 0){
			err = SSL_get_error(targetSslHttp, ret);
#ifdef _DEBUG
			printf("[E] SSL_connect error:%d:%s.\n", err, ERR_error_string(ERR_peek_last_error(), NULL));
#endif
			finiSsl(&sslParam);
			close(targetSock);
			close(clientSock);
			return -2;
		}
#ifdef _DEBUG
		printf("[I] Succeed HTTPS connection. (SSL_connect)\n");
#endif
		
		// HTTP Request
		sen = sendDataTls(targetSock, targetSslHttp, httpRequest, httpRequestLength, tv_sec, tv_usec);
#ifdef _DEBUG
		printf("[I] Send http request.\n");
#endif
		
	}else{
		// HTTP Request
		sen = sendData(targetSock, httpRequest, httpRequestLength, tv_sec, tv_usec);
#ifdef _DEBUG
		printf("[I] Send http request.\n");
#endif
	}
	
	
	// check Server
	count = 0;
	check = 0;
	do{
		count++;
		rec = recvDataAes(targetSock, buffer, BUFFER_SIZE, aes_key, aes_iv, tv_sec, tv_usec);
#ifdef _DEBUG
		printf("[I] count:%d rec:%d\n", count, rec);
#endif
		if(rec >= 2 && !strncmp(buffer, "OK", strlen("OK"))){
			check = 1;
			break;
		}
	}while(count < 3);
	if(check == 1){
#ifdef _DEBUG
		printf("[I] Server Socks5 OK.\n");
#endif
	}else{
#ifdef _DEBUG
		printf("[E] Server Socks5 NG.\n");
#endif
		finiSsl(&sslParam);
		close(targetSock);
		close(clientSock);
		return -1;
	}

	
	if(socks5OverTlsFlag == 1){	// Socks5 over TLS
		// SSL Initialize
		OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS, NULL);
		
		// SSL TLS connection
		targetCtxSocks5 = SSL_CTX_new(TLS_client_method());
		if(targetCtxSocks5 == NULL){
#ifdef _DEBUG
			printf("[E] SSL_CTX_new error.\n");
#endif
			close(targetSock);
			close(clientSock);
			return -2;
		}
		sslParam.targetCtxSocks5 = targetCtxSocks5;

		SSL_CTX_set_mode(targetCtxSocks5, SSL_MODE_AUTO_RETRY);
		
		if(SSL_CTX_set_min_proto_version(targetCtxSocks5, TLS1_2_VERSION) == 0){
#ifdef _DEBUG
			printf("[E] SSL_CTX_set_min_proto_version error.\n");
#endif
			finiSsl(&sslParam);
			close(targetSock);
			return -2;
		}

		SSL_CTX_set_default_verify_paths(targetCtxSocks5);
		SSL_CTX_load_verify_locations(targetCtxSocks5, serverCertificateFilenameSocks5, serverCertificateFileDirectoryPathSocks5);
		SSL_CTX_set_verify(targetCtxSocks5, SSL_VERIFY_PEER, NULL);
		
		targetSslSocks5 = SSL_new(targetCtxSocks5);
		if(targetSslSocks5 == NULL){
#ifdef _DEBUG
			printf("[E] SSL_new error.\n");
#endif
			finiSsl(&sslParam);
			close(targetSock);
			close(clientSock);
			return -2;
		}
		sslParam.targetSslSocks5 = targetSslSocks5;

		if(SSL_set_fd(targetSslSocks5, targetSock) == 0){
#ifdef _DEBUG
			printf("[E] SSL_set_fd error.\n");
#endif
			finiSsl(&sslParam);
			close(targetSock);
			close(clientSock);
			return -2;
		}
		
#ifdef _DEBUG
		printf("[I] Try Socks5 over TLS connection. (SSL_connect)\n");
#endif
		ret = SSL_connect(targetSslSocks5);
		if(ret <= 0){
			err = SSL_get_error(targetSslSocks5, ret);
#ifdef _DEBUG
			printf("[E] SSL_connect error:%d:%s.\n", err, ERR_error_string(ERR_peek_last_error(), NULL));
#endif
			finiSsl(&sslParam);
			close(targetSock);
			close(clientSock);
			return -2;
		}
#ifdef _DEBUG
		printf("[I] Succeed Socks5 over TLS connection. (SSL_connect)\n");
#endif
	}


	// socks SELECTION_REQUEST	client -> server
#ifdef _DEBUG
	printf("[I] Recieving selection request. client -> server\n");
#endif
	if((rec = recvData(clientSock, buffer, BUFFER_SIZE, tv_sec, tv_usec)) <= 0){
#ifdef _DEBUG
		printf("[E] Recieving selection request error. client -> server\n");
#endif
		finiSsl(&sslParam);
		close(targetSock);
		close(clientSock);
		return -1;
	}
#ifdef _DEBUG
	printf("[I] Recieve selection request:%d bytes. client -> server\n", rec);
#endif


	// socks SELECTION_REQUEST	server -> target
#ifdef _DEBUG
	printf("[I] Sending selection request. server -> target\n");
#endif
	if(socks5OverTlsFlag == 0){
		sen = sendDataAes(targetSock, buffer, rec, aes_key, aes_iv, tv_sec, tv_usec);
	}else{
		sen = sendDataTls(targetSock, targetSslSocks5, buffer, rec, tv_sec, tv_usec);
	}
#ifdef _DEBUG
	printf("[I] Send selection request:%d bytes. server -> target\n", sen);	
#endif


	// socks SELECTION_RESPONSE	server <- target
#ifdef _DEBUG
	printf("[I] Recieving selection response. server <- target\n");
#endif
	if(socks5OverTlsFlag == 0){
		rec = recvDataAes(targetSock, buffer, BUFFER_SIZE, aes_key, aes_iv, tv_sec, tv_usec);
	}else{
		rec = recvDataTls(targetSock, targetSslSocks5, buffer, BUFFER_SIZE, tv_sec, tv_usec);
	}
	if(rec != sizeof(SELECTION_RESPONSE)){
#ifdef _DEBUG
		printf("[E] Recieving selection response error. server <- target\n");
#endif
		finiSsl(&sslParam);
		close(targetSock);
		close(clientSock);
		return -1;
	}
#ifdef _DEBUG
	printf("[I] Recieve selection response:%d bytes. server <- target\n", rec);
#endif


	// socks SELECTION_RESPONSE	client <- server
#ifdef _DEBUG
	printf("[I] Sending selection response. client <- server\n");
#endif
	sen = sendData(clientSock, buffer, rec, tv_sec, tv_usec);
#ifdef _DEBUG
	printf("[I] Send selection response:%d bytes. client <- server\n", sen);
#endif
	pSELECTION_RESPONSE pSelectionResponse = (pSELECTION_RESPONSE)&buffer;
	if((unsigned char)pSelectionResponse->method == 0xFF){
#ifdef _DEBUG
		printf("[E] Target socks5server Authentication Method error.\n");
#endif
	}

	if(pSelectionResponse->method == 0x2){	// USERNAME_PASSWORD_AUTHENTICATION
		// socks USERNAME_PASSWORD_AUTHENTICATION_REQUEST		client -> server
#ifdef _DEBUG
		printf("[I] Recieving username password authentication request. client -> server\n");
#endif
		if((rec = recvData(clientSock, buffer, BUFFER_SIZE, tv_sec, tv_usec)) <= 0){
#ifdef _DEBUG
			printf("[E] Recieving username password authentication request error. client -> server\n");
#endif
			finiSsl(&sslParam);
			close(targetSock);
			close(clientSock);
			return -1;
		}
#ifdef _DEBUG
		printf("[I] Recieve username password authentication request:%d bytes. client -> server\n", rec);
#endif


		// socks USERNAME_PASSWORD_AUTHENTICATION_REQUEST		server -> target
#ifdef _DEBUG
		printf("[I] Sending username password authentication request. server -> target\n");
#endif
		if(socks5OverTlsFlag == 0){
			sen = sendDataAes(targetSock, buffer, rec, aes_key, aes_iv, tv_sec, tv_usec);
		}else{
			sen = sendDataTls(targetSock, targetSslSocks5, buffer, rec, tv_sec, tv_usec);
		}
#ifdef _DEBUG
		printf("[I] Send username password authentication request:%d bytes. server -> target\n", sen);	
#endif
		

		// socks USERNAME_PASSWORD_AUTHENTICATION_RESPONSE	server <- target
#ifdef _DEBUG
		printf("[I] Recieving username password authentication response. server <- target\n");
#endif
		if(socks5OverTlsFlag == 0){
			rec = recvDataAes(targetSock, buffer, BUFFER_SIZE, aes_key, aes_iv, tv_sec, tv_usec);
		}else{
			rec = recvDataTls(targetSock, targetSslSocks5, buffer, BUFFER_SIZE, tv_sec, tv_usec);
		}
		if(rec <= 0){
#ifdef _DEBUG
			printf("[E] Recieving username password authentication response error. server <- target\n");
#endif
			finiSsl(&sslParam);
			close(targetSock);
			close(clientSock);
			return -1;
		}
#ifdef _DEBUG
		printf("[I] Recieve username password authentication response:%d bytes. server <- target\n", rec);
#endif


		// socks USERNAME_PASSWORD_AUTHENTICATION_RESPONSE	client <- server
#ifdef _DEBUG
		printf("[I] Sending username password authentication response. client <- server\n");
#endif
		sen = sendData(clientSock, buffer, rec, tv_sec, tv_usec);
#ifdef _DEBUG
		printf("[I] Send username password authentication response:%d bytes. client <- server\n", sen);
#endif
	}


	// socks SOCKS_REQUEST	client -> server
#ifdef _DEBUG
	printf("[I] Recieving socks request. client -> server\n");
#endif
	if((rec = recvData(clientSock, buffer, BUFFER_SIZE, tv_sec, tv_usec)) <= 0){
#ifdef _DEBUG
		printf("[E] Recieving socks request error. client -> server\n");
#endif
		finiSsl(&sslParam);
		close(targetSock);
		close(clientSock);
		return -1;
	}
#ifdef _DEBUG
	printf("[I] Recieve socks request:%d bytes. client -> server\n", rec);
#endif


	// socks SOCKS_REQUEST	server -> target
#ifdef _DEBUG
	printf("[I] Sending socks request. server -> target\n");
#endif
	if(socks5OverTlsFlag == 0){
		sen = sendDataAes(targetSock, buffer, rec, aes_key, aes_iv, tv_sec, tv_usec);
	}else{
		sen = sendDataTls(targetSock, targetSslSocks5, buffer, rec, tv_sec, tv_usec);
	}
#ifdef _DEBUG
	printf("[I] Send socks request:%d bytes. server -> target\n", sen);	
#endif
	

	// socks SOCKS_RESPONSE	server <- target
#ifdef _DEBUG
	printf("[I] Recieving socks response. server <- target\n");
#endif
	if(socks5OverTlsFlag == 0){
		rec = recvDataAes(targetSock, buffer, BUFFER_SIZE, aes_key, aes_iv, tv_sec, tv_usec);
	}else{
		rec = recvDataTls(targetSock, targetSslSocks5, buffer, BUFFER_SIZE, tv_sec, tv_usec);
	}
	if(rec <= 0){
#ifdef _DEBUG
		printf("[E] Recieving socks response error. server <- target\n");
#endif
		finiSsl(&sslParam);
		close(targetSock);
		close(clientSock);
		return -1;
	}
#ifdef _DEBUG
	printf("[I] Recieve socks response:%d bytes. server <- target\n", rec);
#endif


	// socks SOCKS_RESPONSE	client <- server
#ifdef _DEBUG
	printf("[I] Sending socks response. client <- server\n");
#endif
	sen = sendData(clientSock, buffer, rec, tv_sec, tv_usec);
#ifdef _DEBUG
	printf("[I] Send socks response:%d bytes. client <- server\n", sen);
#endif


	// forwarder
#ifdef _DEBUG
	printf("[I] Forwarder.\n");
#endif
	if(socks5OverTlsFlag == 0){
		err = forwarderAes(clientSock, targetSock, aes_key, aes_iv, forwarder_tv_sec, forwarder_tv_usec);
	}else{
		err = forwarderTls(clientSock, targetSock, targetSslSocks5, forwarder_tv_sec, forwarder_tv_usec);
	}


#ifdef _DEBUG
	printf("[I] Worker exit.\n");
#endif
	sleep(5);
	finiSsl(&sslParam);
	close(targetSock);
	close(clientSock);

	return 0;
}

void usage(char *filename)
{
	printf("usage   : %s -h listen_ip -p listen_port -H target_socks5server_domainname -P target_socks5server_port [-s (HTTPS)] [-t (Socks5 over TLS)] [-A recv/send tv_sec(timeout 0-10 sec)] [-B recv/send tv_usec(timeout 0-1000000 microsec)] [-C forwarder tv_sec(timeout 0-300 sec)] [-D forwarder tv_usec(timeout 0-1000000 microsec)]\n", filename);
	printf("example : %s -h 0.0.0.0 -p 9050 -H 192.168.0.10 -P 80\n", filename);
	printf("        : %s -h 0.0.0.0 -p 9050 -H foobar.test -P 80 -t\n", filename);
	printf("        : %s -h 0.0.0.0 -p 9050 -H foobar.test -P 80 -t -A 3 -B 0 -C 3 -D 0\n", filename);
	printf("        : %s -h 0.0.0.0 -p 9050 -H 192.168.0.10 -P 443 -s\n", filename);
	printf("        : %s -h 0.0.0.0 -p 9050 -H foobar.test -P 443 -s -t\n", filename);
	printf("        : %s -h 0.0.0.0 -p 9050 -H foobar.test -P 443 -s -t -A 3 -B 0 -C 3 -D 0\n", filename);
}

int main(int argc, char **argv)
{
	int opt;
	const char* optstring = "h:p:H:P:stA:B:C:D:";
	opterr = 0;
	long tv_sec = 3;	// recv send
	long tv_usec = 0;	// recv send
	long forwarder_tv_sec = 3;
	long forwarder_tv_usec = 0;
	
	while((opt=getopt(argc, argv, optstring)) != -1){
		switch(opt){
		case 'h':
			socks5ServerIp = optarg;
			break;
			
		case 'p':
			socks5ServerPort = optarg;
			break;
		
		case 'H':
			socks5TargetIp = optarg;
			break;
			
		case 'P':
			socks5TargetPort = optarg;
			break;
			
		case 's':
			httpsFlag = 1;
			break;
			
		case 't':
			socks5OverTlsFlag = 1;
			break;
			
		case 'A':
			tv_sec = atol(optarg);
			break;
			
		case 'B':
			tv_usec = atol(optarg);
			break;
			
		case 'C':
			forwarder_tv_sec = atol(optarg);
			break;
			
		case 'D':
			forwarder_tv_usec = atol(optarg);
			break;
			
		default:
			usage(argv[0]);
			exit(1);
		}
	}

	if(socks5ServerIp == NULL || socks5ServerPort == NULL || socks5TargetIp == NULL || socks5TargetPort == NULL){
		usage(argv[0]);
		exit(1);
	}
	
	if(tv_sec < 0 || tv_sec > 10 || tv_usec < 0 || tv_usec > 1000000){
		tv_sec = 3;
		tv_usec = 0;
	}else if(tv_sec == 0 && tv_usec == 0){
		tv_sec = 3;
		tv_usec = 0;
	}
	
	if(forwarder_tv_sec < 0 || forwarder_tv_sec > 300 || forwarder_tv_usec < 0 || forwarder_tv_usec > 1000000){
		forwarder_tv_sec = 3;
		forwarder_tv_usec = 0;
	}else if(forwarder_tv_sec == 0 && forwarder_tv_usec == 0){
		forwarder_tv_sec = 3;
		forwarder_tv_usec = 0;
	}
	
	if(httpsFlag == 0){	// HTTP
#ifdef _DEBUG
		printf("[I] HTTPS:off\n");
#endif
	}else{	// HTTPS
#ifdef _DEBUG
		printf("[I] HTTPS:on\n");
#endif
	}
	
	if(socks5OverTlsFlag == 0){	// Socks5 over AES
#ifdef _DEBUG
		printf("[I] Socks5 over AES\n");
#endif
	}else{	// Socks5 over TLS
#ifdef _DEBUG
		printf("[I] Socks5 over TLS\n");
#endif
	}
	
#ifdef _DEBUG
	printf("[I] Timeout recv/send tv_sec(0-10 sec):%ld sec recv/send tv_usec(0-1000000 microsec):%ld microsec.\n", tv_sec, tv_usec);
	printf("[I] Timeout forwarder tv_sec(0-300 sec):%ld sec forwarder tv_usec(0-1000000 microsec):%ld microsec.\n", forwarder_tv_sec, forwarder_tv_usec);
#endif
	
	
	int serverSock, clientSock;
	struct sockaddr_in serverAddr, clientAddr;

	serverAddr.sin_family = AF_INET;
	serverAddr.sin_addr.s_addr = inet_addr(socks5ServerIp);
	serverAddr.sin_port = htons(atoi(socks5ServerPort));
	
	serverSock = socket(AF_INET, SOCK_STREAM, 0);
	int reuse = 1;
	setsockopt(serverSock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int));
	
	// bind
	if(bind(serverSock, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) == -1) {
#ifdef _DEBUG
		printf("[E] bind error.\n");
#endif
		return -1;
	}
	
	// listen
	listen(serverSock, 5);
#ifdef _DEBUG
	printf("[I] Listenning port %d on %s.\n", ntohs(serverAddr.sin_port), inet_ntoa(serverAddr.sin_addr));
#endif

	// accept
	int clientAddrLen = sizeof(clientAddr);
	while((clientSock = accept(serverSock, (struct sockaddr *)&clientAddr, (socklen_t *)&clientAddrLen))){
#ifdef _DEBUG
		printf("[I] Connected from %s.\n", inet_ntoa(clientAddr.sin_addr));
#endif

		int flags = fcntl(clientSock, F_GETFL, 0);
		flags &= ~O_NONBLOCK;
		fcntl(clientSock, F_SETFL, flags);
		
		pthread_t thread;
		PARAM param;
		param.clientSock = clientSock;
		param.tv_sec = tv_sec;
		param.tv_usec = tv_usec;
		param.forwarder_tv_sec = forwarder_tv_sec;
		param.forwarder_tv_usec = forwarder_tv_usec;
		
		if(pthread_create(&thread, NULL, (void *)worker, &param))
		{
#ifdef _DEBUG
			printf("[E] pthread_create failed.\n");
#endif
			close(clientSock);
		}else{
			pthread_detach(thread);
		}
	}

	close(serverSock);

	return 0;
}

