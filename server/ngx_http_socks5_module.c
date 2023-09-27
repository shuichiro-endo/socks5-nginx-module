/*
 * Title:  socks5 server (nginx filter module)
 * Author: Shuichiro Endo
 */

//#define _DEBUG

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <stdio.h>
#include <strings.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <time.h>
#include <unistd.h>
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
#include "ngx_http_socks5_module.h"
#include "serverkey.h"

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

static char authentication_method = 0x0;	// 0x0:No Authentication Required	0x2:Username/Password Authentication
static char username[256] = "socks5user";
static char password[256] = "supersecretpassword";

char cipher_suite_tls_1_2[1000] = "AESGCM+ECDSA:CHACHA20+ECDSA:+AES256";	// TLS1.2
char cipher_suite_tls_1_3[1000] = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256";	// TLS1.3


static ngx_http_output_header_filter_pt ngx_http_next_header_filter;

static ngx_http_output_body_filter_pt ngx_http_next_body_filter;

static ngx_http_module_t ngx_http_socks5_module_ctx = {
	NULL,					/* preconfiguration */
	ngx_http_socks5_init,			/* postconfiguration */
	NULL,					/* create main configuration */
	NULL,					/* init main configuration */
	NULL,					/* create server configuration */
	NULL,					/* marge server configuration */
	NULL,					/* create location configuration */
	NULL					/* merge location configuration */
};

ngx_module_t ngx_http_socks5_module = {
	NGX_MODULE_V1,
	&ngx_http_socks5_module_ctx,		/* module context */
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


int encrypt_aes(ngx_http_request_t *r, unsigned char *plaintext, int plaintext_length, unsigned char *aes_key, unsigned char *aes_iv, unsigned char *ciphertext)
{
	EVP_CIPHER_CTX *ctx;
	int length;
	int ciphertext_length;
	int ret;
	
	ctx = EVP_CIPHER_CTX_new();
	if(ctx == NULL){
#ifdef _DEBUG
//		printf("[E] EVP_CIPHER_CTX_new error.\n");
//		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] EVP_CIPHER_CTX_new error.");
#endif
		return -1;
	}
	
	ret = EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, aes_iv);
	if(ret != 1){
#ifdef _DEBUG
//		printf("[E] EVP_EncryptInit_ex error.\n");
//		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] EVP_EncryptInit_ex error.");
#endif
		return -1;
	}
	
	ret = EVP_EncryptUpdate(ctx, ciphertext, &length, plaintext, plaintext_length);
	if(ret != 1){
#ifdef _DEBUG
//		printf("[E] EVP_EncryptUpdate error.\n");
//		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] EVP_EncryptUpdate error.");
#endif
		return -1;
	}
	ciphertext_length = length;
	
	ret = EVP_EncryptFinal_ex(ctx, ciphertext+length, &length);
	if(ret != 1){
#ifdef _DEBUG
//		printf("[E] EVP_EncryptFinal_ex error.\n");
//		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] EVP_EncryptFinal_ex error.");
#endif
		return -1;
	}
	ciphertext_length += length;
	
	EVP_CIPHER_CTX_free(ctx);
	
	return ciphertext_length;
}


int decrypt_aes(ngx_http_request_t *r, unsigned char *ciphertext, int ciphertext_length, unsigned char *aes_key, unsigned char *aes_iv, unsigned char *plaintext)
{
	EVP_CIPHER_CTX *ctx;
	int length;
	int plaintext_length;
	int ret;
	
	ctx = EVP_CIPHER_CTX_new();
	if(ctx == NULL){
#ifdef _DEBUG
//		printf("[E] EVP_CIPHER_CTX_new error.\n");
//		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] EVP_CIPHER_CTX_new error.");
#endif
		return -1;
	}
	
	ret = EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, aes_iv);
	if(ret != 1){
#ifdef _DEBUG
//		printf("[E] EVP_DecryptInit_ex error.\n");
//		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] EVP_DecryptInit_ex error.");
#endif
		return -1;
	}
	
	ret = EVP_DecryptUpdate(ctx, plaintext, &length, ciphertext, ciphertext_length);
	if(ret != 1){
#ifdef _DEBUG
//		printf("[E] EVP_DecryptUpdate error.\n");
//		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] EVP_DecryptUpdate error.");
#endif
		return -1;
	}
	plaintext_length = length;
	
	ret = EVP_DecryptFinal_ex(ctx, plaintext+length, &length);
	if(ret != 1){
#ifdef _DEBUG
//		printf("[E] EVP_DecryptFinal_ex error.\n");
//		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] EVP_DecryptFinal_ex error.");
#endif
		return -1;
	}
	plaintext_length += length;
	
	EVP_CIPHER_CTX_free(ctx);
	
	return plaintext_length;
}


int recv_data(ngx_http_request_t *r, int sock, void *buffer, int length, long tv_sec, long tv_usec)
{
	int rec = 0;
	fd_set readfds;
	int nfds = -1;
	struct timeval tv;
	struct timeval start;
	struct timeval end;
	long t = 0;
	bzero(buffer, length+1);
	
	if(gettimeofday(&start, NULL) == -1){
#ifdef _DEBUG
		printf("[E] gettimeofday error.\n");
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] gettimeofday error.");
#endif
		return -1;
	}
	
	while(1){
		if(gettimeofday(&end, NULL) == -1){
#ifdef _DEBUG
			printf("[E] gettimeofday error.\n");
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] gettimeofday error.");
#endif
			return -1;
		}
		
		t = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec);	// microsecond
		if(t >= (tv_sec * 1000000 + tv_usec)){
#ifdef _DEBUG
			printf("[I] recv_data_aes timeout.\n");
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] recv_data_aes timeout.");
#endif
			return -1;
		}
		
		FD_ZERO(&readfds);
		FD_SET(sock, &readfds);
		nfds = sock + 1;
		tv.tv_sec = tv_sec;
		tv.tv_usec = tv_usec;
		
		if(select(nfds, &readfds, NULL, NULL, &tv) == 0){
#ifdef _DEBUG
			printf("[I] recv_data select timeout.\n");
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] recv_data select timeout.");
#endif
			return -1;
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


int recv_data_aes(ngx_http_request_t *r, int sock, void *buffer, int length, unsigned char *aes_key, unsigned char *aes_iv, long tv_sec, long tv_usec)
{
	int rec = 0;
	fd_set readfds;
	int nfds = -1;
	struct timeval tv;
	struct timeval start;
	struct timeval end;
	long t = 0;
	bzero(buffer, length+1);
	int ret = 0;
	struct send_recv_data_aes *data;
	int encrypt_data_length = 0;
	unsigned char *tmp = calloc(16, sizeof(unsigned char));
	unsigned char *buffer2 = calloc(BUFFER_SIZE*2, sizeof(unsigned char));
	
	if(gettimeofday(&start, NULL) == -1){
#ifdef _DEBUG
		printf("[E] gettimeofday error.\n");
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] gettimeofday error.");
#endif
		free(tmp);
		free(buffer2);
		return -1;
	}

	while(1){
		if(gettimeofday(&end, NULL) == -1){
#ifdef _DEBUG
			printf("[E] gettimeofday error.\n");
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] gettimeofday error.");
#endif
			free(tmp);
			free(buffer2);
			return -1;
		}
		
		t = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec);	// microsecond
		if(t >= (tv_sec * 1000000 + tv_usec)){
#ifdef _DEBUG
			printf("[I] recv_data_aes timeout.\n");
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] recv_data_aes timeout.");
#endif
			free(tmp);
			free(buffer2);
			return -1;
		}

		FD_ZERO(&readfds);
		FD_SET(sock, &readfds);
		nfds = sock + 1;
		tv.tv_sec = tv_sec;
		tv.tv_usec = tv_usec;

		if(select(nfds, &readfds, NULL, NULL, &tv) == 0){
#ifdef _DEBUG
			printf("[I] recv_data_aes select timeout.\n");
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] recv_data_aes select timeout.");
#endif
			free(tmp);
			free(buffer2);
			return -1;
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
					free(tmp);
					free(buffer2);
					return -1;
				}
			}else if(rec >= 16){	// unsigned char encrypt_data_length[16]
				data = (struct send_recv_data_aes *)buffer2;
				
				ret = decrypt_aes(r, data->encrypt_data_length, 16, aes_key, aes_iv, (unsigned char *)tmp);
				if(ret == 4){	// int encrypt_data_length
					encrypt_data_length = (tmp[0] << 24)|(tmp[1] << 16)|(tmp[2] << 8)|(tmp[3]);
				}else{
					free(tmp);
					free(buffer2);
					return -1;
				}
				
				if(encrypt_data_length <= rec-16){
					ret = decrypt_aes(r, data->encrypt_data, encrypt_data_length, aes_key, aes_iv, (unsigned char *)buffer);
					if(ret > 0){
						rec = ret;
					}else{
						free(tmp);
						free(buffer2);
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

	free(tmp);
	free(buffer2);
	return rec;
}


int recv_data_tls(ngx_http_request_t *r, int sock, SSL *ssl ,void *buffer, int length, long tv_sec, long tv_usec)
{
	int rec = 0;
	int err = 0;
	fd_set readfds;
	int nfds = -1;
	struct timeval tv;
	struct timeval start;
	struct timeval end;
	long t = 0;
	bzero(buffer, length+1);
	
	if(gettimeofday(&start, NULL) == -1){
#ifdef _DEBUG
		printf("[E] gettimeofday error.\n");
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] gettimeofday error.");
#endif
		return -2;
	}
	
	while(1){
		if(gettimeofday(&end, NULL) == -1){
#ifdef _DEBUG
			printf("[E] gettimeofday error.\n");
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] gettimeofday error.");
#endif
			return -2;
		}
		
		t = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec);	// microsecond
		if(t >= (tv_sec * 1000000 + tv_usec)){
#ifdef _DEBUG
			printf("[I] recv_data_tls timeout.\n");
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] recv_data_tls timeout.");
#endif
			return -2;
		}
		
		FD_ZERO(&readfds);
		FD_SET(sock, &readfds);
		nfds = sock + 1;
		tv.tv_sec = tv_sec;
		tv.tv_usec = tv_usec;
		
		if(select(nfds, &readfds, NULL, NULL, &tv) == 0){
#ifdef _DEBUG
			printf("[I] recv_data_tls select timeout.\n");
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] recv_data_tls select timeout.");
#endif
			return -2;
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
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] SSL_read error:%d:%s.", err, ERR_error_string(ERR_peek_last_error(), NULL));
#endif
				return -2;
			}
		}
	}
	
	return rec;
}


int send_data(ngx_http_request_t *r, int sock, void *buffer, int length, long tv_sec, long tv_usec)
{
	int sen = 0;
	int send_length = 0;
	int len = length;
	fd_set writefds;
	int nfds = -1;
	struct timeval tv;
	struct timeval start;
	struct timeval end;
	long t = 0;
	
	if(gettimeofday(&start, NULL) == -1){
#ifdef _DEBUG
		printf("[E] gettimeofday error.\n");
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] gettimeofday error.");
#endif
		return -1;
	}
	
	while(len > 0){
		if(gettimeofday(&end, NULL) == -1){
#ifdef _DEBUG
			printf("[E] gettimeofday error.\n");
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] gettimeofday error.");
#endif
			return -1;
		}
		
		t = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec);	// microsecond
		if(t >= (tv_sec * 1000000 + tv_usec)){
#ifdef _DEBUG
			printf("[I] send_data timeout.\n");
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] send_data timeout.");
#endif
			return -1;
		}
		
		FD_ZERO(&writefds);
		FD_SET(sock, &writefds);
		nfds = sock + 1;
		tv.tv_sec = tv_sec;
		tv.tv_usec = tv_usec;
		
		if(select(nfds, NULL, &writefds, NULL, &tv) == 0){
#ifdef _DEBUG
			printf("[I] send_data select timeout.\n");
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] send_data select timeout.");
#endif
			return -1;
		}
		
		if(FD_ISSET(sock, &writefds)){
			sen = send(sock, (char *)buffer+send_length, len, 0);
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
			send_length += sen;
			len -= sen;
		}
	}
	
	return length;
}


int send_data_aes(ngx_http_request_t *r, int sock, void *buffer, int length, unsigned char *aes_key, unsigned char *aes_iv, long tv_sec, long tv_usec)
{
	int sen = 0;
	int send_length = 0;
	int len = 0;
	fd_set writefds;
	int nfds = -1;
	struct timeval tv;
	struct timeval start;
	struct timeval end;
	long t = 0;
	int ret = 0;
	struct send_recv_data_aes *data = (struct send_recv_data_aes *)calloc(1, sizeof(struct send_recv_data_aes));
	int encrypt_data_length = 0;
	unsigned char *tmp = calloc(16, sizeof(unsigned char));
	
	ret = encrypt_aes(r, (unsigned char *)buffer, length, aes_key, aes_iv, data->encrypt_data);
	if(ret > 0){
		encrypt_data_length = ret;
	}else{
		free(tmp);
		free(data);
		return -1;
	}
	
	tmp[0] = (unsigned char)encrypt_data_length >> 24;
	tmp[1] = (unsigned char)encrypt_data_length >> 16;
	tmp[2] = (unsigned char)encrypt_data_length >> 8;
	tmp[3] = (unsigned char)encrypt_data_length;
	
	ret = encrypt_aes(r, (unsigned char *)tmp, 4, aes_key, aes_iv, data->encrypt_data_length);
	if(ret != 16){	// unsigned char encrypt_data_length[16]
		free(tmp);
		free(data);
		return -1;
	}
	
	len = 16 + encrypt_data_length;
	
	if(gettimeofday(&start, NULL) == -1){
#ifdef _DEBUG
		printf("[E] gettimeofday error.\n");
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] gettimeofday error.");
#endif
		free(tmp);
		free(data);
		return -1;
	}
	
	while(len > 0){
		if(gettimeofday(&end, NULL) == -1){
#ifdef _DEBUG
			printf("[E] gettimeofday error.\n");
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] gettimeofday error.");
#endif
			free(tmp);
			free(data);
			return -1;
		}
		
		t = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec);	// microsecond
		if(t >= (tv_sec * 1000000 + tv_usec)){
#ifdef _DEBUG
			printf("[I] send_data_aes timeout.\n");
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] send_data_aes timeout.");
#endif
			free(tmp);
			free(data);
			return -1;
		}
		
		FD_ZERO(&writefds);
		FD_SET(sock, &writefds);
		nfds = sock + 1;
		tv.tv_sec = tv_sec;
		tv.tv_usec = tv_usec;
		
		if(select(nfds, NULL, &writefds, NULL, &tv) == 0){
#ifdef _DEBUG
			printf("[I] send_data_aes select timeout.\n");
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] send_data_aes select timeout.");
#endif
			free(tmp);
			free(data);
			return -1;
		}
		
		if(FD_ISSET(sock, &writefds)){
			sen = send(sock, (unsigned char *)data+send_length, len, 0);
			if(sen <= 0){
				if(errno == EINTR){
					continue;
				}else if(errno == EAGAIN){
					usleep(5000);
					continue;
				}else{
					free(tmp);
					free(data);
					return -1;
				}
			}
			send_length += sen;
			len -= sen;
		}
	}
	
	free(tmp);
	free(data);
	return length;
}


int send_data_tls(ngx_http_request_t *r, int sock, SSL *ssl, void *buffer, int length, long tv_sec, long tv_usec)
{
	int sen = 0;
	int err = 0;
	fd_set writefds;
	int nfds = -1;
	struct timeval tv;
	struct timeval start;
	struct timeval end;
	long t = 0;
	
	if(gettimeofday(&start, NULL) == -1){
#ifdef _DEBUG
		printf("[E] gettimeofday error.\n");
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] gettimeofday error.");
#endif
		return -2;
	}
	
	while(1){
		if(gettimeofday(&end, NULL) == -1){
#ifdef _DEBUG
			printf("[E] gettimeofday error.\n");
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] gettimeofday error.");
#endif
			return -2;
		}
		
		t = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec);	// microsecond
		if(t >= (tv_sec * 1000000 + tv_usec)){
#ifdef _DEBUG
			printf("[I] send_data_tls timeout.\n");
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] send_data_tls timeout.");
#endif
			return -2;
		}
		
		FD_ZERO(&writefds);
		FD_SET(sock, &writefds);
		nfds = sock + 1;
		tv.tv_sec = tv_sec;
		tv.tv_usec = tv_usec;
		
		if(select(nfds, NULL, &writefds, NULL, &tv) == 0){
#ifdef _DEBUG
			printf("[I] send_data_tls select timeout.\n");
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] send_data_tls select timeout.");
#endif
			return -2;
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
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] SSL_write error:%d:%s.", err, ERR_error_string(ERR_peek_last_error(), NULL));
#endif
				return -2;
			}
		}
	}
		
	return length;
}


int forwarder(ngx_http_request_t *r, int client_sock, int target_sock, long tv_sec, long tv_usec)
{
	int rec, sen;
	int len = 0;
	int send_length = 0;
	fd_set readfds;
	int nfds = -1;
	struct timeval tv;
	char buffer[BUFFER_SIZE+1];
	bzero(buffer, BUFFER_SIZE+1);
	
	while(1){
		FD_ZERO(&readfds);
		FD_SET(client_sock, &readfds);
		FD_SET(target_sock, &readfds);
		nfds = (client_sock > target_sock ? client_sock : target_sock) + 1;
		tv.tv_sec = tv_sec;
		tv.tv_usec = tv_usec;
		
		if(select(nfds, &readfds, NULL, NULL, &tv) == 0){
#ifdef _DEBUG
			printf("[I] forwarder select timeout.\n");
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] forwarder select timeout.");
#endif
			break;
		}
						
		if(FD_ISSET(client_sock, &readfds)){
			if((rec = recv(client_sock, buffer, BUFFER_SIZE, 0)) > 0){
				len = rec;
				send_length = 0;
				
				while(len > 0){
					sen = send(target_sock, buffer+send_length, len, 0);
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
					send_length += sen;
					len -= sen;
				}
			}else{
				break;
			}
		}
		
		if(FD_ISSET(target_sock, &readfds)){
			if((rec = recv(target_sock, buffer, BUFFER_SIZE, 0)) > 0){
				len = rec;
				send_length = 0;
				
				while(len > 0){
					sen = send(client_sock, buffer+send_length, len, 0);
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
					send_length += sen;
					len -= sen;
				}
			}else{
				break;
			}
		}
	}
	
	return 0;
}


int forwarder_aes(ngx_http_request_t *r, int client_sock, int target_sock, unsigned char *aes_key, unsigned char *aes_iv, long tv_sec, long tv_usec)
{
	int rec, sen;
	int len = 0;
	int send_length = 0;
	fd_set readfds;
	int nfds = -1;
	struct timeval tv;
	int ret = 0;
	struct send_recv_data_aes *data = (struct send_recv_data_aes *)calloc(1, sizeof(struct send_recv_data_aes));
	int encrypt_data_length = 0;
	unsigned char *tmp = calloc(16, sizeof(unsigned char));
	unsigned char *buffer = calloc(BUFFER_SIZE*2, sizeof(unsigned char));
	unsigned char *buffer2 = calloc(BUFFER_SIZE*2, sizeof(unsigned char));
	
	while(1){
		FD_ZERO(&readfds);
		FD_SET(client_sock, &readfds);
		FD_SET(target_sock, &readfds);
		nfds = (client_sock > target_sock ? client_sock : target_sock) + 1;
		tv.tv_sec = tv_sec;
		tv.tv_usec = tv_usec;
		
		if(select(nfds, &readfds, NULL, NULL, &tv) == 0){
#ifdef _DEBUG
			printf("[I] forwarder_aes select timeout.\n");
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] forwarder_aes select timeout.");
#endif
			break;
		}
		
		if(FD_ISSET(client_sock, &readfds)){
			bzero(tmp, 16);
			bzero(buffer, BUFFER_SIZE*2);
			bzero(buffer2, BUFFER_SIZE*2);
			
			if((rec = recv(client_sock, buffer, 16, 0)) > 0){	// unsigned char encrypt_data_length[16]
				if(rec != 16){
					break;
				}
				
				ret = decrypt_aes(r, (unsigned char *)buffer, 16, aes_key, aes_iv, tmp);
				if(ret != 4){	// int encrypt_data_length
					free(tmp);
					free(data);
					free(buffer);
					free(buffer2);
					return -1;
				}
				
				encrypt_data_length = (tmp[0] << 24)|(tmp[1] << 16)|(tmp[2] << 8)|(tmp[3]);
				if(encrypt_data_length <= 0 || encrypt_data_length > BUFFER_SIZE*2 || (encrypt_data_length & 0xf) != 0){
					free(tmp);
					free(data);
					free(buffer);
					free(buffer2);
					return -1;
				}
				
				bzero(buffer, BUFFER_SIZE*2);
				
				if((rec = recv(client_sock, buffer, encrypt_data_length, 0)) > 0){
					if(rec != encrypt_data_length){
						free(tmp);
						free(data);
						free(buffer);
						free(buffer2);
						return -1;
					}
					
					ret = decrypt_aes(r, (unsigned char *)buffer, encrypt_data_length, aes_key, aes_iv, buffer2);
					if(ret < 0){
						free(tmp);
						free(data);
						free(buffer);
						free(buffer2);
						return -1;
					}
					
					len = ret;
					send_length = 0;
					
					while(len > 0){
						sen = send(target_sock, buffer2+send_length, len, 0);
						if(sen <= 0){
							if(errno == EINTR){
								continue;
							}else if(errno == EAGAIN){
								usleep(5000);
								continue;
							}else{
								free(tmp);
								free(data);
								free(buffer);
								free(buffer2);
								return -1;
							}
						}
						send_length += sen;
						len -= sen;
					}
				}else{
					break;
				}
			}else{
				break;
			}
		}
		
		if(FD_ISSET(target_sock, &readfds)){
			bzero(tmp, 16);
			bzero(data, sizeof(struct send_recv_data_aes));
			bzero(buffer, BUFFER_SIZE*2);
			
			if((rec = recv(target_sock, buffer, BUFFER_SIZE, 0)) > 0){
				ret = encrypt_aes(r, (unsigned char *)buffer, rec, aes_key, aes_iv, data->encrypt_data);
				if(ret > 0){
					encrypt_data_length = ret;
				}else{
					free(tmp);
					free(data);
					free(buffer);
					free(buffer2);
					return -1;
				}
				
				tmp[0] = (unsigned char)(encrypt_data_length >> 24);
				tmp[1] = (unsigned char)(encrypt_data_length >> 16);
				tmp[2] = (unsigned char)(encrypt_data_length >> 8);
				tmp[3] = (unsigned char)encrypt_data_length;
				
				ret = encrypt_aes(r, (unsigned char *)tmp, 4, aes_key, aes_iv, data->encrypt_data_length);
				if(ret != 16){	// unsigned char encrypt_data_length[16]
					free(tmp);
					free(data);
					free(buffer);
					free(buffer2);
					return -1;
				}
				
				len = 16 + encrypt_data_length;
				send_length = 0;
				
				while(len > 0){
					sen = send(client_sock, (unsigned char *)data+send_length, len, 0);
					if(sen <= 0){
						if(errno == EINTR){
							continue;
						}else if(errno == EAGAIN){
							usleep(5000);
							continue;
						}else{
							free(tmp);
							free(data);
							free(buffer);
							free(buffer2);
							return -1;
						}
					}
					send_length += sen;
					len -= sen;
				}
			}else{
				break;
			}
		}
	}
	
	free(tmp);
	free(data);
	free(buffer);
	free(buffer2);
	return 0;
}


int forwarder_tls(ngx_http_request_t *r, int client_sock, int target_sock, SSL *client_ssl_socks5, long tv_sec, long tv_usec)
{
	int rec, sen;
	int len = 0;
	int send_length = 0;
	fd_set readfds;
	int nfds = -1;
	struct timeval tv;
	char buffer[BUFFER_SIZE+1];
	bzero(buffer, BUFFER_SIZE+1);
	int err = 0;
	
	while(1){
		FD_ZERO(&readfds);
		FD_SET(client_sock, &readfds);
		FD_SET(target_sock, &readfds);
		nfds = (client_sock > target_sock ? client_sock : target_sock) + 1;
		tv.tv_sec = tv_sec;
		tv.tv_usec = tv_usec;
		
		if(select(nfds, &readfds, NULL, NULL, &tv) == 0){
#ifdef _DEBUG
			printf("[I] forwarder_tls select timeout.\n");
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] forwarder_tls select timeout.");
#endif
			break;
		}
		
		if(FD_ISSET(client_sock, &readfds)){
			rec = SSL_read(client_ssl_socks5, buffer, BUFFER_SIZE);
			err = SSL_get_error(client_ssl_socks5, rec);
			
			if(err == SSL_ERROR_NONE){
				len = rec;
				send_length = 0;
				
				while(len > 0){
					sen = send(target_sock, buffer+send_length, len, 0);
					if(sen <= 0){
						if(errno == EINTR){
							continue;
						}else if(errno == EAGAIN){
							usleep(5000);
							continue;
						}else{
							return -2;
						}
					}
					send_length += sen;
					len -= sen;
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
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] SSL_read error:%d:%s.", err, ERR_error_string(ERR_peek_last_error(), NULL));
#endif
				return -2;
			}
		}
		
		if(FD_ISSET(target_sock, &readfds)){
			if((rec = recv(target_sock, buffer, BUFFER_SIZE, 0)) > 0){
				while(1){
					sen = SSL_write(client_ssl_socks5, buffer, rec);
					err = SSL_get_error(client_ssl_socks5, sen);

					if(err == SSL_ERROR_NONE){
						break;
					}else if(err == SSL_ERROR_WANT_WRITE){
						usleep(5000);
					}else if(err == SSL_ERROR_WANT_READ){
						usleep(5000);
					}else{
#ifdef _DEBUG
						printf("[E] SSL_write error:%d:%s.\n", err, ERR_error_string(ERR_peek_last_error(), NULL));
						ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] SSL_write error:%d:%s.", err, ERR_error_string(ERR_peek_last_error(), NULL));
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


int send_socks_response_ipv4(ngx_http_request_t *r, int client_sock, char ver, char req, char rsv, char atyp, long tv_sec, long tv_usec)
{
	int sen;
	struct socks_response_ipv4 *socks_response_ipv4 = (struct socks_response_ipv4 *)malloc(sizeof(struct socks_response_ipv4));
		
	socks_response_ipv4->ver = ver;		// protocol version
	socks_response_ipv4->req = req;		// Connection refused
	socks_response_ipv4->rsv = rsv;		// RESERVED
	socks_response_ipv4->atyp = atyp;	// IPv4
	bzero(socks_response_ipv4->bnd_addr, 4);	// BND.ADDR
	bzero(socks_response_ipv4->bnd_port, 2);	// BND.PORT

	sen = send_data(r, client_sock, socks_response_ipv4, sizeof(struct socks_response_ipv4), tv_sec, tv_usec);

	free(socks_response_ipv4);

	return sen;
}


int send_socks_response_ipv4_aes(ngx_http_request_t *r, int client_sock, char ver, char req, char rsv, char atyp, unsigned char *aes_key, unsigned char *aes_iv, long tv_sec, long tv_usec)
{
	int sen;
	struct socks_response_ipv4 *socks_response_ipv4 = (struct socks_response_ipv4 *)malloc(sizeof(struct socks_response_ipv4));
	
	socks_response_ipv4->ver = ver;		// protocol version
	socks_response_ipv4->req = req;		// Connection refused
	socks_response_ipv4->rsv = rsv;		// RESERVED
	socks_response_ipv4->atyp = atyp;	// IPv4
	bzero(socks_response_ipv4->bnd_addr, 4);	// BND.ADDR
	bzero(socks_response_ipv4->bnd_port, 2);	// BND.PORT

	sen = send_data_aes(r, client_sock, socks_response_ipv4, sizeof(struct socks_response_ipv4), aes_key, aes_iv, tv_sec, tv_usec);

	free(socks_response_ipv4);

	return sen;
}


int send_socks_response_ipv4_tls(ngx_http_request_t *r, int client_sock, SSL *client_ssl, char ver, char req, char rsv, char atyp, long tv_sec, long tv_usec)
{
	int sen;
	struct socks_response_ipv4 *socks_response_ipv4 = (struct socks_response_ipv4 *)malloc(sizeof(struct socks_response_ipv4));
	
	socks_response_ipv4->ver = ver;		// protocol version
	socks_response_ipv4->req = req;		// Connection refused
	socks_response_ipv4->rsv = rsv;		// RESERVED
	socks_response_ipv4->atyp = atyp;	// IPv4
	bzero(socks_response_ipv4->bnd_addr, 4);	// BND.ADDR
	bzero(socks_response_ipv4->bnd_port, 2);	// BND.PORT

	sen = send_data_tls(r, client_sock, client_ssl, socks_response_ipv4, sizeof(struct socks_response_ipv4), tv_sec, tv_usec);

	free(socks_response_ipv4);

	return sen;
}


int send_socks_response_ipv6(ngx_http_request_t *r, int client_sock, char ver, char req, char rsv, char atyp, long tv_sec, long tv_usec)
{
	int sen;
	struct socks_response_ipv6 *socks_response_ipv6 = (struct socks_response_ipv6 *)malloc(sizeof(struct socks_response_ipv6));
	
	socks_response_ipv6->ver = ver;		// protocol version
	socks_response_ipv6->req = req;		// Connection refused
	socks_response_ipv6->rsv = rsv;		// RESERVED
	socks_response_ipv6->atyp = atyp;	// IPv6
	bzero(socks_response_ipv6->bnd_addr, 16);	// BND.ADDR
	bzero(socks_response_ipv6->bnd_port, 2);	// BND.PORT
	
	sen = send_data(r, client_sock, socks_response_ipv6, sizeof(struct socks_response_ipv6), tv_sec, tv_usec);
	
	free(socks_response_ipv6);

	return sen;
}


int send_socks_response_ipv6_aes(ngx_http_request_t *r, int client_sock, char ver, char req, char rsv, char atyp, unsigned char *aes_key, unsigned char *aes_iv, long tv_sec, long tv_usec)
{
	int sen;
	struct socks_response_ipv6 *socks_response_ipv6 = (struct socks_response_ipv6 *)malloc(sizeof(struct socks_response_ipv6));
	
	socks_response_ipv6->ver = ver;		// protocol version
	socks_response_ipv6->req = req;		// Connection refused
	socks_response_ipv6->rsv = rsv;		// RESERVED
	socks_response_ipv6->atyp = atyp;	// IPv6
	bzero(socks_response_ipv6->bnd_addr, 16);	// BND.ADDR
	bzero(socks_response_ipv6->bnd_port, 2);	// BND.PORT
	
	sen = send_data_aes(r, client_sock, socks_response_ipv6, sizeof(struct socks_response_ipv6), aes_key, aes_iv, tv_sec, tv_usec);
	
	free(socks_response_ipv6);

	return sen;
}


int send_socks_response_ipv6_tls(ngx_http_request_t *r, int client_sock, SSL *client_ssl, char ver, char req, char rsv, char atyp, long tv_sec, long tv_usec)
{
	int sen;
	struct socks_response_ipv6 *socks_response_ipv6 = (struct socks_response_ipv6 *)malloc(sizeof(struct socks_response_ipv6));
	
	socks_response_ipv6->ver = ver;		// protocol version
	socks_response_ipv6->req = req;		// Connection refused
	socks_response_ipv6->rsv = rsv;		// RESERVED
	socks_response_ipv6->atyp = atyp;	// IPv6
	bzero(socks_response_ipv6->bnd_addr, 16);	// BND.ADDR
	bzero(socks_response_ipv6->bnd_port, 2);	// BND.PORT
	
	sen = send_data_tls(r, client_sock, client_ssl, socks_response_ipv6, sizeof(struct socks_response_ipv6), tv_sec, tv_usec);
	
	free(socks_response_ipv6);

	return sen;
}


int worker(ngx_http_request_t *r, void *ptr)
{
	struct worker_param *worker_param = (struct worker_param *)ptr;
	int client_sock = worker_param->client_sock;
	SSL *client_ssl_socks5 = worker_param->client_ssl_socks5;
	int socks5_over_tls_flag = worker_param->socks5_over_tls_flag;	// 0:socks5 over aes 1:socks5 over tls
	unsigned char *aes_key = worker_param->aes_key;
	unsigned char *aes_iv = worker_param->aes_iv;
	long tv_sec = worker_param->tv_sec;		// recv send
	long tv_usec = worker_param->tv_usec;		// recv send
	long forwarder_tv_sec = worker_param->forwarder_tv_sec;
	long forwarder_tv_usec = worker_param->forwarder_tv_usec;
	
	char buffer[BUFFER_SIZE+1];
	bzero(buffer, BUFFER_SIZE+1);
	int sen = 0;
	int rec = sen;
	int err = 0;
	
	
	// socks selection_request
#ifdef _DEBUG
	printf("[I] Receive selection request.\n");
	ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] Receive selection request.");
#endif
	if(socks5_over_tls_flag == 0){	// Socks5 over AES
		rec = recv_data_aes(r, client_sock, buffer, BUFFER_SIZE, aes_key, aes_iv, tv_sec, tv_usec);
	}else{	// Socks5 over TLS
		rec = recv_data_tls(r, client_sock, client_ssl_socks5, buffer, BUFFER_SIZE, tv_sec, tv_usec);
	}
	if(rec <= 0){
#ifdef _DEBUG
		printf("[E] Receive selection request.\n");
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Receive selection request.");
#endif
		return -1;
	}
#ifdef _DEBUG
	printf("[I] Receive selection request:%d bytes.\n", rec);
	ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] Receive selection request:%d bytes.", rec);
#endif
	struct selection_request *selection_request = (struct selection_request *)buffer;
	unsigned char method = 0xFF;
	for(int i=0; i<selection_request->nmethods; i++){
		if(selection_request->methods[i] == 0x0 || selection_request->methods[i] == 0x2){	// no authentication required or username/password
			method = selection_request->methods[i];
			break;
		}
	}
	if(method == 0xFF){
#ifdef _DEBUG
		printf("[E] Selection request method error.\n");
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Selection request method error.");
#endif
	}


	// socks selection_response
	struct selection_response *selection_response = (struct selection_response *)malloc(sizeof(struct selection_response));
	selection_response->ver = 0x5;		// socks version 5
	selection_response->method = method;	// no authentication required or username/password
	if(selection_request->ver != 0x5 || authentication_method != method){
		selection_response->method = 0xFF;
	}
	if(socks5_over_tls_flag == 0){	// Socks5 over AES
		sen = send_data_aes(r, client_sock, selection_response, sizeof(struct selection_response), aes_key, aes_iv, tv_sec, tv_usec);
	}else{	// Socks5 over TLS
		sen = send_data_tls(r, client_sock, client_ssl_socks5, selection_response, sizeof(struct selection_response), tv_sec, tv_usec);
	}
	if(sen <= 0){
#ifdef _DEBUG
		printf("[E] Send selection response.\n");
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Send selection response.");
#endif
		free(selection_response);
		return -1;
	}
	
	free(selection_response);
#ifdef _DEBUG
	printf("[I] Send selection response:%d bytes.\n", sen);
	ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] Send selection response:%d bytes.", sen);
#endif
	
	if(authentication_method != method){
#ifdef _DEBUG
		printf("[E] Authentication method error. server:0x%x client:0x%x\n", authentication_method, method);
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Authentication method error. server:0x%x client:0x%x", authentication_method, method);
#endif
		return -1;
	}


	// socks username_password_authentication
	unsigned char ulen = 0;
	unsigned char plen = 0;
	char uname[256] = {0};
	char passwd[256] = {0};
	if(method == 0x2){
		// socks username_password_authentication_request
#ifdef _DEBUG
		printf("[I] Receive username password authentication request.\n");
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] Receive username password authentication request.");
#endif
		if(socks5_over_tls_flag == 0){	// Socks5 over AES
			rec = recv_data_aes(r, client_sock, buffer, BUFFER_SIZE, aes_key, aes_iv, tv_sec, tv_usec);
		}else{	// Socks5 over TLS
			rec = recv_data_tls(r, client_sock, client_ssl_socks5, buffer, BUFFER_SIZE, tv_sec, tv_usec);
		}
		if(rec <= 0){
#ifdef _DEBUG
			printf("[E] Receive username password authentication request.\n");
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Receive username password authentication request.");
#endif
			return -1;
		}
#ifdef _DEBUG
		printf("[I] Receive username password authentication request:%d bytes.\n", rec);
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] Receive username password authentication request:%d bytes.", rec);
#endif
		struct username_password_authentication_request_tmp *username_password_authentication_request = (struct username_password_authentication_request_tmp *)buffer;

		ulen = username_password_authentication_request->ulen;
		memcpy(uname, &username_password_authentication_request->uname, ulen);
		memcpy(&plen, &username_password_authentication_request->uname + ulen, 1);
		memcpy(passwd, &username_password_authentication_request->uname + ulen + 1, plen);
#ifdef _DEBUG
		printf("[I] uname:%s ulen:%d, passwd:%s plen:%d\n", uname, ulen, passwd, plen);
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] uname:%s ulen:%d, passwd:%s plen:%d", uname, ulen, passwd, plen);
#endif


		// socks username_password_authentication_response
		struct username_password_authentication_response *username_password_authentication_response = (struct username_password_authentication_response *)malloc(sizeof(struct username_password_authentication_response));
		username_password_authentication_response->ver = 0x1;
		
		if(username_password_authentication_request->ver == 0x1 && !strncmp(uname, username, sizeof(username)) && !strncmp(passwd, password, sizeof(password))){
#ifdef _DEBUG
			printf("[I] Succeed username password authentication.\n");
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] Succeed username password authentication.");
#endif
			username_password_authentication_response->status = 0x0;
			
			if(socks5_over_tls_flag == 0){	// Socks5 over AES
				sen = send_data_aes(r, client_sock, username_password_authentication_response, sizeof(struct username_password_authentication_response), aes_key, aes_iv, tv_sec, tv_usec);
			}else{	// Socks5 over TLS
				sen = send_data_tls(r, client_sock, client_ssl_socks5, username_password_authentication_response, sizeof(struct username_password_authentication_response), tv_sec, tv_usec);
			}
			if(sen <= 0){
#ifdef _DEBUG
				printf("[E] Send username password authentication response.\n");
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Send username password authentication response.");
#endif
				
				free(username_password_authentication_response);
				return -1;
			}
#ifdef _DEBUG
			printf("[I] Send username password authentication response:%d bytes.\n", sen);
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] Send username password authentication response:%d bytes.", sen);
#endif
			
			free(username_password_authentication_response);
		}else{
#ifdef _DEBUG
			printf("[E] Fail username password authentication.\n");
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Fail username password authentication.");
#endif
			username_password_authentication_response->status = 0xFF;
			
			if(socks5_over_tls_flag == 0){	// Socks5 over AES
				sen = send_data_aes(r, client_sock, username_password_authentication_response, sizeof(struct username_password_authentication_response), aes_key, aes_iv, tv_sec, tv_usec);
			}else{	// Socks5 over TLS
				sen = send_data_tls(r, client_sock, client_ssl_socks5, username_password_authentication_response, sizeof(struct username_password_authentication_response), tv_sec, tv_usec);
			}
			if(sen <= 0){
#ifdef _DEBUG
				printf("[E] Send username password authentication response.\n");
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Send username password authentication response.");
#endif
			}else{
#ifdef _DEBUG
				printf("[I] Send username password authentication response:%d bytes.\n", sen);
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] Send username password authentication response:%d bytes.", sen);
#endif
			}
			
			free(username_password_authentication_response);
			return -1;
		}
	}
	
	
	// socks socks_request
#ifdef _DEBUG
	printf("[I] Receive socks request.\n");
	ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] Receive socks request.");
#endif
	bzero(buffer, BUFFER_SIZE+1);
	if(socks5_over_tls_flag == 0){	// Socks5 over AES
		rec = recv_data_aes(r, client_sock, buffer, BUFFER_SIZE, aes_key, aes_iv, tv_sec, tv_usec);
	}else{	// Socks5 over TLS
		rec = recv_data_tls(r, client_sock, client_ssl_socks5, buffer, BUFFER_SIZE, tv_sec, tv_usec);
	}
	if(rec <= 0){
#ifdef _DEBUG
		printf("[E] Receive socks request.\n");
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Receive socks request.");
#endif
		return -1;
	}
#ifdef _DEBUG
	printf("[I] Receive socks request:%d bytes.\n", rec);
	ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] Receive socks request:%d bytes.", rec);
#endif
	
	struct socks_request *socks_request = (struct socks_request *)buffer;
	struct socks_request_ipv4 *socks_request_ipv4;
	struct socks_request_domainname *socks_request_domainname;
	struct socks_request_ipv6 *socks_request_ipv6;
	
	char atyp = socks_request->atyp;
	if(atyp != 0x1 && atyp != 0x3 && atyp != 0x4){
#ifdef _DEBUG
		printf("[E] Socks request atyp(%d) error.\n", atyp);
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Socks request atyp(%d) error.", atyp);
		printf("[E] Not implemented.\n");
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Not implemented.");
#endif

		// socks socks_response
		if(socks5_over_tls_flag == 0){	// Socks5 over AES
			sen = send_socks_response_ipv4_aes(r, client_sock, 0x5, 0x8, 0x0, 0x1, aes_key, aes_iv, tv_sec, tv_usec);
		}else{	// Socks5 over TLS
			sen = send_socks_response_ipv4_tls(r, client_sock, client_ssl_socks5, 0x5, 0x8, 0x0, 0x1, tv_sec, tv_usec);
		}
		if(sen <= 0){
#ifdef _DEBUG
			printf("[E] Send socks response.\n");
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Send socks response.");
#endif
		}

		return -1;
	}
	
	char cmd = socks_request->cmd;
	if(cmd != 0x1){	// CONNECT only
#ifdef _DEBUG
		printf("[E] Socks request cmd(%d) error.\n", cmd);
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Socks request cmd(%d) error.", cmd);
		printf("[E] Not implemented.\n");
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Not implemented.");
#endif
		
		// socks socks_response
		if(atyp == 0x1 || atyp == 0x3){	// IPv4
			if(socks5_over_tls_flag == 0){	// Socks5 over AES
				sen = send_socks_response_ipv4_aes(r, client_sock, 0x5, 0x7, 0x0, 0x1, aes_key, aes_iv, tv_sec, tv_usec);
			}else{	// Socks5 over TLS
				sen = send_socks_response_ipv4_tls(r, client_sock, client_ssl_socks5, 0x5, 0x7, 0x0, 0x1, tv_sec, tv_usec);
			}
		}else{	// IPv6
			if(socks5_over_tls_flag == 0){	// Socks5 over AES
				sen = send_socks_response_ipv6_aes(r, client_sock, 0x5, 0x7, 0x0, 0x4, aes_key, aes_iv, tv_sec, tv_usec);
			}else{	// Socks5 over TLS
				sen = send_socks_response_ipv6_tls(r, client_sock, client_ssl_socks5, 0x5, 0x7, 0x0, 0x4, tv_sec, tv_usec);
			}
		}
		if(sen <= 0){
#ifdef _DEBUG
			printf("[E] Send socks response.\n");
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Send socks response.");
#endif
		}
		
		return -1;
	}
		
	struct sockaddr_in target_addr, *tmp_ipv4;		// IPv4
	memset(&target_addr, 0, sizeof(struct sockaddr_in));
	
	struct sockaddr_in6 target_addr6, *tmp_ipv6;	// IPv6
	memset(&target_addr6, 0, sizeof(struct sockaddr_in6));
	
	struct addrinfo hints, *target_host;
	memset(&hints, 0, sizeof(struct addrinfo));
	
	int family = 0;
	char domainname[256] = {0};
	u_short domainname_length = 0;
	char *colon;
	
	if(socks_request->atyp == 0x1){	// IPv4
		family = AF_INET;
		target_addr.sin_family = AF_INET;
		socks_request_ipv4 = (struct socks_request_ipv4 *)buffer;
		memcpy(&target_addr.sin_addr.s_addr, &socks_request_ipv4->dst_addr, 4);
		memcpy(&target_addr.sin_port, &socks_request_ipv4->dst_port, 2);
	}else if(socks_request->atyp == 0x3){	// domain name
		socks_request_domainname = (struct socks_request_domainname *)buffer;
		domainname_length = socks_request_domainname->dst_addr_len;
		memcpy(&domainname, &socks_request_domainname->dst_addr, domainname_length);
#ifdef _DEBUG
		printf("[I] Domainname:%s, Length:%d.\n", domainname, domainname_length);
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] Domainname:%s, Length:%d.", domainname, domainname_length);
#endif

		colon = strstr(domainname, ":");	// check ipv6 address
		if(colon == NULL){	// ipv4 address or domainname
			hints.ai_family = AF_INET;	// IPv4
			if(getaddrinfo(domainname, NULL, &hints, &target_host) != 0){
				hints.ai_family = AF_INET6;	// IPv6
				if(getaddrinfo(domainname, NULL, &hints, &target_host) != 0){
#ifdef _DEBUG
					printf("[E] Cannot resolv the domain name:%s.\n", (char *)domainname);
					ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Cannot resolv the domain name:%s.", (char *)domainname);
#endif
					
					// socks socks_response
					if(socks5_over_tls_flag == 0){	// Socks5 over AES
						sen = send_socks_response_ipv4_aes(r, client_sock, 0x5, 0x5, 0x0, 0x1, aes_key, aes_iv, tv_sec, tv_usec);
					}else{	// Socks5 over TLS
						sen = send_socks_response_ipv4_tls(r, client_sock, client_ssl_socks5, 0x5, 0x5, 0x0, 0x1, tv_sec, tv_usec);
					}
					if(sen <= 0){
#ifdef _DEBUG
						printf("[E] Send socks response.\n");
						ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Send socks response.");
#endif
					}
					
					return -1;
				}
			}
		}else{	// ipv6 address
			hints.ai_family = AF_INET6;	// IPv6
			if(getaddrinfo(domainname, NULL, &hints, &target_host) != 0){
#ifdef _DEBUG
				printf("[E] Cannot resolv the domain name:%s.\n", (char *)domainname);
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Cannot resolv the domain name:%s.", (char *)domainname);
#endif
				
				// socks socks_response
				if(socks5_over_tls_flag == 0){	// Socks5 over AES
					sen = send_socks_response_ipv6_aes(r, client_sock, 0x5, 0x5, 0x0, 0x4, aes_key, aes_iv, tv_sec, tv_usec);
				}else{	// Socks5 over TLS
					sen = send_socks_response_ipv6_tls(r, client_sock, client_ssl_socks5, 0x5, 0x5, 0x0, 0x4, tv_sec, tv_usec);
				}
				if(sen <= 0){
#ifdef _DEBUG
					printf("[E] Send socks response.\n");
					ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Send socks response.");
#endif
				}

				return -1;
			}
		}
		
		if(target_host->ai_family == AF_INET){
			family = AF_INET;
			target_addr.sin_family = AF_INET;
			tmp_ipv4 = (struct sockaddr_in *)target_host->ai_addr;
			memcpy(&target_addr.sin_addr, &tmp_ipv4->sin_addr, sizeof(unsigned long));
			memcpy(&target_addr.sin_port, &socks_request_domainname->dst_addr[domainname_length], 2);
			freeaddrinfo(target_host);
		}else if(target_host->ai_family == AF_INET6){
			family = AF_INET6;
			target_addr6.sin6_family = AF_INET6;
			tmp_ipv6 = (struct sockaddr_in6 *)target_host->ai_addr;
			memcpy(&target_addr6.sin6_addr, &tmp_ipv6->sin6_addr, sizeof(struct in6_addr));
			memcpy(&target_addr6.sin6_port, &socks_request_domainname->dst_addr[domainname_length], 2);
			freeaddrinfo(target_host);
		}else{
#ifdef _DEBUG
			printf("[E] Not implemented.\n");
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Not implemented.");
#endif

			// socks socks_response
			if(socks5_over_tls_flag == 0){	// Socks5 over AES
				sen = send_socks_response_ipv4_aes(r, client_sock, 0x5, 0x1, 0x0, 0x1, aes_key, aes_iv, tv_sec, tv_usec);
			}else{	// Socks5 over TLS
				sen = send_socks_response_ipv4_tls(r, client_sock, client_ssl_socks5, 0x1, 0x5, 0x0, 0x1, tv_sec, tv_usec);
			}
			if(sen <= 0){
#ifdef _DEBUG
				printf("[E] Send socks response.\n");
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Send socks response.");
#endif
			}
			
			freeaddrinfo(target_host);
			return -1;
		}
	}else if(socks_request->atyp == 0x4){	// IPv6
		family = AF_INET6;
		target_addr6.sin6_family = AF_INET6;
		socks_request_ipv6 = (struct socks_request_ipv6 *)buffer;
		memcpy(&target_addr6.sin6_addr, &socks_request_ipv6->dst_addr, 16);
		memcpy(&target_addr6.sin6_port, &socks_request_ipv6->dst_port, 2);
	}else {
#ifdef _DEBUG
		printf("[E] Not implemented.\n");
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Not implemented.");
#endif

		// socks socks_response
		if(socks5_over_tls_flag == 0){	// Socks5 over AES
			sen = send_socks_response_ipv4_aes(r, client_sock, 0x5, 0x1, 0x0, 0x1, aes_key, aes_iv, tv_sec, tv_usec);
		}else{	// Socks5 over TLS
			sen = send_socks_response_ipv4_tls(r, client_sock, client_ssl_socks5, 0x1, 0x5, 0x0, 0x1, tv_sec, tv_usec);
		}
		if(sen <= 0){
#ifdef _DEBUG
			printf("[E] Send socks response.\n");
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Send socks response.");
#endif
		}
		
		return -1;
	}
	
	
	// socks socks_response
	int target_sock;
	char target_addr6_string[INET6_ADDRSTRLEN+1] = {0};
	char *target_addr6_string_pointer = target_addr6_string;
	int flags = 0;
	
	if(atyp == 0x1){	// IPv4
#ifdef _DEBUG
		printf("[I] Connecting. ip:%s port:%d\n", inet_ntoa(target_addr.sin_addr), ntohs(target_addr.sin_port));
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] Connecting. ip:%s port:%d", inet_ntoa(target_addr.sin_addr), ntohs(target_addr.sin_port));
#endif

		if(cmd == 0x1){	// CONNECT
#ifdef _DEBUG
			printf("[I] SOCKS_RESPONSE cmd:CONNECT.\n");
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] SOCKS_RESPONSE cmd:CONNECT.");
#endif
			target_sock = socket(AF_INET, SOCK_STREAM, 0);
			
			// blocking
			flags = fcntl(target_sock, F_GETFL, 0);
			fcntl(target_sock, F_SETFL, flags & ~O_NONBLOCK);
			
			if((err = connect(target_sock, (struct sockaddr *)&target_addr, sizeof(target_addr))) < 0){
#ifdef _DEBUG
				printf("[E] Cannot connect. errno:%d\n", err);
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Cannot connect. errno:%d", err);
#endif
				
				if(socks5_over_tls_flag == 0){	// Socks5 over AES
					sen = send_socks_response_ipv4_aes(r, client_sock, 0x5, 0x5, 0x0, 0x1, aes_key, aes_iv, tv_sec, tv_usec);
				}else{	// Socks5 over TLS
					sen = send_socks_response_ipv4_tls(r, client_sock, client_ssl_socks5, 0x5, 0x5, 0x0, 0x1, tv_sec, tv_usec);
				}
				if(sen <= 0){
#ifdef _DEBUG
					printf("[E] Send socks response.\n");
					ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Send socks response.");
#endif
				}else{
#ifdef _DEBUG
					printf("[I] Socks Request:%d bytes, Socks Response:%d bytes.\n", rec, sen);
					ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] Socks Request:%d bytes, Socks Response:%d bytes.", rec, sen);
#endif
				}
				
				close_socket(target_sock);
				return -1;
			}

#ifdef _DEBUG
			printf("[I] Connected. ip:%s port:%d\n", inet_ntoa(target_addr.sin_addr), ntohs(target_addr.sin_port));
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] Connected. ip:%s port:%d", inet_ntoa(target_addr.sin_addr), ntohs(target_addr.sin_port));
#endif
			
			if(socks5_over_tls_flag == 0){	// Socks5 over AES
				sen = send_socks_response_ipv4_aes(r, client_sock, 0x5, 0x0, 0x0, 0x1, aes_key, aes_iv, tv_sec, tv_usec);
			}else{	// Socks5 over TLS
				sen = send_socks_response_ipv4_tls(r, client_sock, client_ssl_socks5, 0x5, 0x0, 0x0, 0x1, tv_sec, tv_usec);
			}
			if(sen <= 0){
#ifdef _DEBUG
				printf("[E] Send socks response.\n");
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Send socks response.");
#endif
				
				close_socket(target_sock);
				return -1;
			}else{
#ifdef _DEBUG
				printf("[I] Socks Request:%d bytes, Socks Response:%d bytes.\n", rec, sen);
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] Socks Request:%d bytes, Socks Response:%d bytes.", rec, sen);
#endif
			}
			
		}else if(cmd == 0x2){	// BIND
#ifdef _DEBUG
			printf("[I] SOCKS_RESPONSE cmd:BIND.\n");
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] SOCKS_RESPONSE cmd:BIND.");
			printf("[E] Not implemented.\n");
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Not implemented.");
#endif
			
			if(socks5_over_tls_flag == 0){	// Socks5 over AES
				sen = send_socks_response_ipv4_aes(r, client_sock, 0x5, 0x7, 0x0, 0x1, aes_key, aes_iv, tv_sec, tv_usec);
			}else{	// Socks5 over TLS
				sen = send_socks_response_ipv4_tls(r, client_sock, client_ssl_socks5, 0x5, 0x7, 0x0, 0x1, tv_sec, tv_usec);
			}
			if(sen <= 0){
#ifdef _DEBUG
				printf("[E] Send socks response.\n");
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Send socks response.");
#endif
			}
			
			return -1;
			
		}else if(cmd == 0x3){	// UDP ASSOCIATE
#ifdef _DEBUG
			printf("[I] SOCKS_RESPONSE cmd:UDP ASSOCIATE.\n");
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] SOCKS_RESPONSE cmd:UDP ASSOCIATE.");
			printf("[E] Not implemented.\n");
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Not implemented.");
#endif
			
			if(socks5_over_tls_flag == 0){	// Socks5 over AES
				sen = send_socks_response_ipv4_aes(r, client_sock, 0x5, 0x7, 0x0, 0x1, aes_key, aes_iv, tv_sec, tv_usec);
			}else{	// Socks5 over TLS
				sen = send_socks_response_ipv4_tls(r, client_sock, client_ssl_socks5, 0x5, 0x7, 0x0, 0x1, tv_sec, tv_usec);
			}
			if(sen <= 0){
#ifdef _DEBUG
				printf("[E] Send socks response.\n");
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Send socks response.");
#endif
			}
			
			return -1;
			
		}else{
#ifdef _DEBUG
			printf("[E] Not implemented.\n");
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Not implemented.");
#endif
			
			if(socks5_over_tls_flag == 0){	// Socks5 over AES
				sen = send_socks_response_ipv4_aes(r, client_sock, 0x5, 0x1, 0x0, 0x1, aes_key, aes_iv, tv_sec, tv_usec);
			}else{	// Socks5 over TLS
				sen = send_socks_response_ipv4_tls(r, client_sock, client_ssl_socks5, 0x5, 0x1, 0x0, 0x1, tv_sec, tv_usec);
			}
			if(sen <= 0){
#ifdef _DEBUG
				printf("[E] Send socks response.\n");
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Send socks response.");
#endif
			}
			
			return -1;
		}
	}else if(atyp == 0x3){	// domain name
		if(family == AF_INET){	// IPv4
#ifdef _DEBUG
			printf("[I] Connecting. ip:%s port:%d\n", inet_ntoa(target_addr.sin_addr), ntohs(target_addr.sin_port));
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] Connecting. ip:%s port:%d", inet_ntoa(target_addr.sin_addr), ntohs(target_addr.sin_port));
#endif

			if(cmd == 0x1){	// CONNECT
#ifdef _DEBUG
				printf("[I] SOCKS_RESPONSE cmd:CONNECT.\n");
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] SOCKS_RESPONSE cmd:CONNECT.");
#endif
				target_sock = socket(AF_INET, SOCK_STREAM, 0);
				
				// blocking
				flags = fcntl(target_sock, F_GETFL, 0);
				fcntl(target_sock, F_SETFL, flags & ~O_NONBLOCK);
				
				if((err = connect(target_sock, (struct sockaddr *)&target_addr, sizeof(target_addr))) < 0){
#ifdef _DEBUG
					printf("[E] Cannot connect. errno:%d\n", err);
					ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Cannot connect. errno:%d", err);
#endif
					
					if(socks5_over_tls_flag == 0){	// Socks5 over AES
						sen = send_socks_response_ipv4_aes(r, client_sock, 0x5, 0x5, 0x0, 0x1, aes_key, aes_iv, tv_sec, tv_usec);
					}else{	// Socks5 over TLS
						sen = send_socks_response_ipv4_tls(r, client_sock, client_ssl_socks5, 0x5, 0x5, 0x0, 0x1, tv_sec, tv_usec);
					}
					if(sen <= 0){
#ifdef _DEBUG
						printf("[E] Send socks response.\n");
						ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Send socks response.");
#endif
					}else{
#ifdef _DEBUG
						printf("[I] Socks Request:%d bytes, Socks Response:%d bytes.\n", rec, sen);
						ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] Socks Request:%d bytes, Socks Response:%d bytes.", rec, sen);
#endif
					}
					
					close_socket(target_sock);
					return -1;
				}

#ifdef _DEBUG
				printf("[I] Connected. ip:%s port:%d\n", inet_ntoa(target_addr.sin_addr), ntohs(target_addr.sin_port));
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] Connected. ip:%s port:%d", inet_ntoa(target_addr.sin_addr), ntohs(target_addr.sin_port));
#endif
				
				if(socks5_over_tls_flag == 0){	// Socks5 over AES
					sen = send_socks_response_ipv4_aes(r, client_sock, 0x5, 0x0, 0x0, 0x1, aes_key, aes_iv, tv_sec, tv_usec);
				}else{	// Socks5 over TLS
					sen = send_socks_response_ipv4_tls(r, client_sock, client_ssl_socks5, 0x5, 0x0, 0x0, 0x1, tv_sec, tv_usec);
				}
				if(sen <= 0){
#ifdef _DEBUG
					printf("[E] Send socks response.\n");
					ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Send socks response.");
#endif
					
					close_socket(target_sock);
					return -1;
				}else{
#ifdef _DEBUG
					printf("[I] Socks Request:%d bytes, Socks Response:%d bytes.\n", rec, sen);
					ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] Socks Request:%d bytes, Socks Response:%d bytes.", rec, sen);
#endif
				}
				
			}else if(cmd == 0x2){	// BIND
#ifdef _DEBUG
				printf("[I] SOCKS_RESPONSE cmd:BIND.\n");
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] SOCKS_RESPONSE cmd:BIND.");
				printf("[E] Not implemented.\n");
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Not implemented.");
#endif
				
				if(socks5_over_tls_flag == 0){	// Socks5 over AES
					sen = send_socks_response_ipv4_aes(r, client_sock, 0x5, 0x7, 0x0, 0x1, aes_key, aes_iv, tv_sec, tv_usec);
				}else{	// Socks5 over TLS
					sen = send_socks_response_ipv4_tls(r, client_sock, client_ssl_socks5, 0x5, 0x7, 0x0, 0x1, tv_sec, tv_usec);
				}
				if(sen <= 0){
#ifdef _DEBUG
					printf("[E] Send socks response.\n");
					ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Send socks response.");
#endif
				}
				
				return -1;
				
			}else if(cmd == 0x3){	// UDP ASSOCIATE
#ifdef _DEBUG
				printf("[I] SOCKS_RESPONSE cmd:UDP ASSOCIATE.\n");
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] SOCKS_RESPONSE cmd:UDP ASSOCIATE.");
				printf("[E] Not implemented.\n");
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Not implemented.");
#endif
				
				if(socks5_over_tls_flag == 0){	// Socks5 over AES
					sen = send_socks_response_ipv4_aes(r, client_sock, 0x5, 0x7, 0x0, 0x1, aes_key, aes_iv, tv_sec, tv_usec);
				}else{	// Socks5 over TLS
					sen = send_socks_response_ipv4_tls(r, client_sock, client_ssl_socks5, 0x5, 0x7, 0x0, 0x1, tv_sec, tv_usec);
				}
				if(sen <= 0){
#ifdef _DEBUG
					printf("[E] Send socks response.\n");
					ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Send socks response.");
#endif
				}
				
				return -1;
				
			}else{
#ifdef _DEBUG
				printf("[E] Not implemented.\n");
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Not implemented.");
#endif
				
				if(socks5_over_tls_flag == 0){	// Socks5 over AES
					sen = send_socks_response_ipv4_aes(r, client_sock, 0x5, 0x1, 0x0, 0x1, aes_key, aes_iv, tv_sec, tv_usec);
				}else{	// Socks5 over TLS
					sen = send_socks_response_ipv4_tls(r, client_sock, client_ssl_socks5, 0x5, 0x1, 0x0, 0x1, tv_sec, tv_usec);
				}
				if(sen <= 0){
#ifdef _DEBUG
					printf("[E] Send socks response.\n");
					ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Send socks response.");
#endif
				}
				
				return -1;
				
			}
		}else if(family == AF_INET6){	// IPv6
			inet_ntop(AF_INET6, &target_addr6.sin6_addr, target_addr6_string_pointer, INET6_ADDRSTRLEN);
#ifdef _DEBUG
			printf("[I] Connecting. ip:%s port:%d\n", target_addr6_string_pointer, ntohs(target_addr6.sin6_port));
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] Connecting. ip:%s port:%d", target_addr6_string_pointer, ntohs(target_addr6.sin6_port));
#endif

			if(cmd == 0x1){	// CONNECT
#ifdef _DEBUG
				printf("[I] SOCKS_RESPONSE cmd:CONNECT.\n");
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] SOCKS_RESPONSE cmd:CONNECT.");
#endif
				target_sock = socket(AF_INET6, SOCK_STREAM, 0);

				// blocking
				flags = fcntl(target_sock, F_GETFL, 0);
				fcntl(target_sock, F_SETFL, flags & ~O_NONBLOCK);
			
				if((err = connect(target_sock, (struct sockaddr *)&target_addr6, sizeof(target_addr6))) < 0){
#ifdef _DEBUG
					printf("[E] Cannot connect. errno:%d\n", err);
					ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Cannot connect. errno:%d", err);
#endif
					
					if(socks5_over_tls_flag == 0){	// Socks5 over AES
						sen = send_socks_response_ipv6_aes(r, client_sock, 0x5, 0x5, 0x0, 0x4, aes_key, aes_iv, tv_sec, tv_usec);
					}else{	// Socks5 over TLS
						sen = send_socks_response_ipv6_tls(r, client_sock, client_ssl_socks5, 0x5, 0x5, 0x0, 0x4, tv_sec, tv_usec);
					}
					if(sen <= 0){
#ifdef _DEBUG
						printf("[E] Send socks response.\n");
						ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Send socks response.");
#endif
					}else{
#ifdef _DEBUG
						printf("[I] Socks Request:%d bytes, Socks Response:%d bytes.\n", rec, sen);
						ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] Socks Request:%d bytes, Socks Response:%d bytes.", rec, sen);
#endif
					}
					
					close_socket(target_sock);
					return -1;
				}

#ifdef _DEBUG
				printf("[I] Connected. ip:%s port:%d\n", target_addr6_string_pointer, ntohs(target_addr6.sin6_port));
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] Connected. ip:%s port:%d", target_addr6_string_pointer, ntohs(target_addr6.sin6_port));
#endif
				
				if(socks5_over_tls_flag == 0){	// Socks5 over AES
					sen = send_socks_response_ipv6_aes(r, client_sock, 0x5, 0x0, 0x0, 0x4, aes_key, aes_iv, tv_sec, tv_usec);
				}else{	// Socks5 over TLS
					sen = send_socks_response_ipv6_tls(r, client_sock, client_ssl_socks5, 0x5, 0x0, 0x0, 0x4, tv_sec, tv_usec);
				}
				if(sen <= 0){
#ifdef _DEBUG
					printf("[E] Send socks response.\n");
					ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Send socks response.");
#endif
					
					close_socket(target_sock);
					return -1;
				}else{
#ifdef _DEBUG
					printf("[I] Socks Request:%d bytes, Socks Response:%d bytes.\n", rec, sen);
					ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] Socks Request:%d bytes, Socks Response:%d bytes.", rec, sen);
#endif
				}
				
			}else if(cmd == 0x2){	// BIND
#ifdef _DEBUG
				printf("[I] SOCKS_RESPONSE cmd:BIND.\n");
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] SOCKS_RESPONSE cmd:BIND.");
				printf("[E] Not implemented.\n");
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Not implemented.");
#endif
				
				if(socks5_over_tls_flag == 0){	// Socks5 over AES
					sen = send_socks_response_ipv6_aes(r, client_sock, 0x5, 0x7, 0x0, 0x4, aes_key, aes_iv, tv_sec, tv_usec);
				}else{	// Socks5 over TLS
					sen = send_socks_response_ipv6_tls(r, client_sock, client_ssl_socks5, 0x5, 0x7, 0x0, 0x4, tv_sec, tv_usec);
				}
				if(sen <= 0){
#ifdef _DEBUG
					printf("[E] Send socks response.\n");
					ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Send socks response.");
#endif
				}
				
				return -1;
				
			}else if(cmd == 0x3){	// UDP ASSOCIATE
#ifdef _DEBUG
				printf("[I] SOCKS_RESPONSE cmd:UDP ASSOCIATE.\n");
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] SOCKS_RESPONSE cmd:UDP ASSOCIATE.");
				printf("[E] Not implemented.\n");
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Not implemented.");
#endif
				
				if(socks5_over_tls_flag == 0){	// Socks5 over AES
					sen = send_socks_response_ipv6_aes(r, client_sock, 0x5, 0x7, 0x0, 0x4, aes_key, aes_iv, tv_sec, tv_usec);
				}else{	// Socks5 over TLS
					sen = send_socks_response_ipv6_tls(r, client_sock, client_ssl_socks5, 0x5, 0x7, 0x0, 0x4, tv_sec, tv_usec);
				}
				if(sen <= 0){
#ifdef _DEBUG
					printf("[E] Send socks response.\n");
					ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Send socks response.");
#endif
				}
				
				return -1;
				
			}else{
#ifdef _DEBUG
				printf("[E] Not implemented.\n");
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Not implemented.");
#endif
				
				if(socks5_over_tls_flag == 0){	// Socks5 over AES
					sen = send_socks_response_ipv4_aes(r, client_sock, 0x5, 0x1, 0x0, 0x1, aes_key, aes_iv, tv_sec, tv_usec);
				}else{	// Socks5 over TLS
					sen = send_socks_response_ipv4_tls(r, client_sock, client_ssl_socks5, 0x5, 0x1, 0x0, 0x1, tv_sec, tv_usec);
				}
				if(sen <= 0){
#ifdef _DEBUG
					printf("[E] Send socks response.\n");
					ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Send socks response.");
#endif
				}
				
				return -1;
				
			}		
		}else{
#ifdef _DEBUG
			printf("[E] Not implemented.\n");
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Not implemented.");
#endif
			
			if(socks5_over_tls_flag == 0){	// Socks5 over AES
				sen = send_socks_response_ipv4_aes(r, client_sock, 0x5, 0x1, 0x0, 0x1, aes_key, aes_iv, tv_sec, tv_usec);
			}else{	// Socks5 over TLS
				sen = send_socks_response_ipv4_tls(r, client_sock, client_ssl_socks5, 0x5, 0x1, 0x0, 0x1, tv_sec, tv_usec);
			}
			if(sen <= 0){
#ifdef _DEBUG
				printf("[E] Send socks response.\n");
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Send socks response.");
#endif
			}
			
			return -1;
			
		}
	}else if(atyp == 0x4){	// IPv6
		inet_ntop(AF_INET6, &target_addr6.sin6_addr, target_addr6_string_pointer, INET6_ADDRSTRLEN);
#ifdef _DEBUG
		printf("[I] Connecting. ip:%s port:%d\n", target_addr6_string_pointer, ntohs(target_addr6.sin6_port));
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] Connecting. ip:%s port:%d", target_addr6_string_pointer, ntohs(target_addr6.sin6_port));
#endif

		if(cmd == 0x1){	// CONNECT
#ifdef _DEBUG
			printf("[I] SOCKS_RESPONSE cmd:CONNECT.\n");
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] SOCKS_RESPONSE cmd:CONNECT.");
#endif
			target_sock = socket(AF_INET6, SOCK_STREAM, 0);
			
			// blocking
			flags = fcntl(target_sock, F_GETFL, 0);
			fcntl(target_sock, F_SETFL, flags & ~O_NONBLOCK);
			
			if((err = connect(target_sock, (struct sockaddr *)&target_addr6, sizeof(target_addr6))) < 0){
#ifdef _DEBUG
				printf("[E] Cannot connect. errno:%d\n", err);
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Cannot connect. errno:%d", err);
#endif
				
				if(socks5_over_tls_flag == 0){	// Socks5 over AES
					sen = send_socks_response_ipv6_aes(r, client_sock, 0x5, 0x5, 0x0, 0x4, aes_key, aes_iv, tv_sec, tv_usec);
				}else{	// Socks5 over TLS
					sen = send_socks_response_ipv6_tls(r, client_sock, client_ssl_socks5, 0x5, 0x5, 0x0, 0x4, tv_sec, tv_usec);
				}
				if(sen <= 0){
#ifdef _DEBUG
					printf("[E] Send socks response.\n");
					ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Send socks response.");
#endif
				}else{
#ifdef _DEBUG
					printf("[I] Socks Request:%d bytes, Socks Response:%d bytes.\n", rec, sen);
					ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] Socks Request:%d bytes, Socks Response:%d bytes.", rec, sen);
#endif
				}
				
				close_socket(target_sock);
				return -1;
			}

#ifdef _DEBUG
			printf("[I] Connected. ip:%s port:%d\n", target_addr6_string_pointer, ntohs(target_addr6.sin6_port));
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] Connected. ip:%s port:%d", target_addr6_string_pointer, ntohs(target_addr6.sin6_port));
#endif
			
			if(socks5_over_tls_flag == 0){	// Socks5 over AES
				sen = send_socks_response_ipv6_aes(r, client_sock, 0x5, 0x0, 0x0, 0x4, aes_key, aes_iv, tv_sec, tv_usec);
			}else{	// Socks5 over TLS
				sen = send_socks_response_ipv6_tls(r, client_sock, client_ssl_socks5, 0x5, 0x0, 0x0, 0x4, tv_sec, tv_usec);
			}
			if(sen <= 0){
#ifdef _DEBUG
				printf("[E] Send socks response.\n");
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Send socks response.");
#endif
				
				close_socket(target_sock);
				return -1;
			}else{
#ifdef _DEBUG
				printf("[I] Socks Request:%d bytes, Socks Response:%d bytes.\n", rec, sen);
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] Socks Request:%d bytes, Socks Response:%d bytes.", rec, sen);
#endif
			}
			
		}else if(cmd == 0x2){	// BIND
#ifdef _DEBUG
			printf("[I] SOCKS_RESPONSE cmd:BIND.\n");
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] SOCKS_RESPONSE cmd:BIND.");
			printf("[E] Not implemented.\n");
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Not implemented.");
#endif
			
			if(socks5_over_tls_flag == 0){	// Socks5 over AES
				sen = send_socks_response_ipv6_aes(r, client_sock, 0x5, 0x7, 0x0, 0x4, aes_key, aes_iv, tv_sec, tv_usec);
			}else{	// Socks5 over TLS
				sen = send_socks_response_ipv6_tls(r, client_sock, client_ssl_socks5, 0x5, 0x7, 0x0, 0x4, tv_sec, tv_usec);
			}
			if(sen <= 0){
#ifdef _DEBUG
				printf("[E] Send socks response.\n");
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Send socks response.");
#endif
			}
			
			return -1;
			
		}else if(cmd == 0x3){	// UDP ASSOCIATE
#ifdef _DEBUG
			printf("[I] SOCKS_RESPONSE cmd:UDP ASSOCIATE.\n");
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] SOCKS_RESPONSE cmd:UDP ASSOCIATE.");
			printf("[E] Not implemented.\n");
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Not implemented.");
#endif
			
			if(socks5_over_tls_flag == 0){	// Socks5 over AES
				sen = send_socks_response_ipv6_aes(r, client_sock, 0x5, 0x7, 0x0, 0x4, aes_key, aes_iv, tv_sec, tv_usec);
			}else{	// Socks5 over TLS
				sen = send_socks_response_ipv6_tls(r, client_sock, client_ssl_socks5, 0x5, 0x7, 0x0, 0x4, tv_sec, tv_usec);
			}
			if(sen <= 0){
#ifdef _DEBUG
				printf("[E] Send socks response.\n");
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Send socks response.");
#endif
			}
			
			return -1;
			
		}else{
#ifdef _DEBUG
			printf("[E] Not implemented.\n");
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Not implemented.");
#endif
			
			if(socks5_over_tls_flag == 0){	// Socks5 over AES
				sen = send_socks_response_ipv6_aes(r, client_sock, 0x5, 0x1, 0x0, 0x4, aes_key, aes_iv, tv_sec, tv_usec);
			}else{	// Socks5 over TLS
				sen = send_socks_response_ipv6_tls(r, client_sock, client_ssl_socks5, 0x5, 0x1, 0x0, 0x4, tv_sec, tv_usec);
			}
			if(sen <= 0){
#ifdef _DEBUG
				printf("[E] Send socks response.\n");
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Send socks response.");
#endif
			}
			
			return -1;
		}
	}else{
#ifdef _DEBUG
		printf("[E] Not implemented.\n");
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Not implemented.");
#endif
		
		if(socks5_over_tls_flag == 0){	// Socks5 over AES
			sen = send_socks_response_ipv4_aes(r, client_sock, 0x5, 0x1, 0x0, 0x1, aes_key, aes_iv, tv_sec, tv_usec);
		}else{	// Socks5 over TLS
			sen = send_socks_response_ipv4_tls(r, client_sock, client_ssl_socks5, 0x5, 0x1, 0x0, 0x1, tv_sec, tv_usec);
		}
		if(sen <= 0){
#ifdef _DEBUG
				printf("[E] Send socks response.\n");
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Send socks response.");
#endif
		}
		
		return -1;
	}
	
	
	// forwarder
#ifdef _DEBUG
	printf("[I] Forwarder.\n");
	ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] Forwarder.");
#endif
	if(socks5_over_tls_flag == 0){	// Socks5 over AES
		err = forwarder_aes(r, client_sock, target_sock, aes_key, aes_iv, forwarder_tv_sec, forwarder_tv_usec);
	}else{	// Socks5 over TLS
		err = forwarder_tls(r, client_sock, target_sock, client_ssl_socks5, forwarder_tv_sec, forwarder_tv_usec);
	}
	
#ifdef _DEBUG
	printf("[I] Worker exit.\n");
	ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] Worker exit.");
#endif
	close_socket(target_sock);
	
	return 0;
}


int ssl_sccept_non_blocking(ngx_http_request_t *r, int sock, SSL *ssl, long tv_sec, long tv_usec)
{
	fd_set readfds;
	fd_set writefds;
	int nfds = -1;
	struct timeval tv;
	tv.tv_sec = tv_sec;
	tv.tv_usec = tv_usec;
	struct timeval start;
	struct timeval end;
	long t = 0;
	int ret = 0;
	int err = 0;
	int flags = 0;
	
	// non blocking
	flags = fcntl(sock, F_GETFL, 0);
	fcntl(sock, F_SETFL, flags | O_NONBLOCK);
	
	if(gettimeofday(&start, NULL) == -1){
#ifdef _DEBUG
		printf("[E] gettimeofday error.\n");
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] gettimeofday error.");
#endif
		// blocking
		flags = fcntl(sock, F_GETFL, 0);
		fcntl(sock, F_SETFL, flags & ~O_NONBLOCK);
		return -2;
	}

	while(1){
		FD_ZERO(&readfds);
		FD_ZERO(&writefds);
		FD_SET(sock, &readfds);
		FD_SET(sock, &writefds);
		nfds = sock + 1;
		
		if(select(nfds, &readfds, &writefds, NULL, &tv) == 0){
#ifdef _DEBUG
			printf("[I] ssl_sccept_non_blocking select timeout.\n");
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] ssl_sccept_non_blocking select timeout.");
#endif
			// blocking
			flags = fcntl(sock, F_GETFL, 0);
			fcntl(sock, F_SETFL, flags & ~O_NONBLOCK);
			return -2;
		}
		
		if(FD_ISSET(sock, &readfds) || FD_ISSET(sock, &writefds)){
			ret = SSL_accept(ssl);
			err = SSL_get_error(ssl, ret);
			
			if(err == SSL_ERROR_NONE){
				break;
			}else if(err == SSL_ERROR_WANT_READ){
				usleep(5000);
			}else if(err == SSL_ERROR_WANT_WRITE){
				usleep(5000);
			}else{
#ifdef _DEBUG
				printf("[E] SSL_accept error:%d:%s.\n", err, ERR_error_string(ERR_peek_last_error(), NULL));
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] SSL_accept error:%d:%s.", err, ERR_error_string(ERR_peek_last_error(), NULL));
#endif
				// blocking
				flags = fcntl(sock, F_GETFL, 0);
				fcntl(sock, F_SETFL, flags & ~O_NONBLOCK);
				return -2;
			}
		}
		
		if(gettimeofday(&end, NULL) == -1){
#ifdef _DEBUG
			printf("[E] gettimeofday error.\n");
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] gettimeofday error.");
#endif
			// blocking
			flags = fcntl(sock, F_GETFL, 0);
			fcntl(sock, F_SETFL, flags & ~O_NONBLOCK);
			return -2;
		}
		
		t = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec);	// microsecond
		if(t >= (tv_sec * 1000000 + tv_usec)){
#ifdef _DEBUG
			printf("[I] ssl_sccept_non_blocking timeout.\n");
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] ssl_sccept_non_blocking timeout.");
#endif
			// blocking
			flags = fcntl(sock, F_GETFL, 0);
			fcntl(sock, F_SETFL, flags & ~O_NONBLOCK);
			return -2;
		}
	}
	
	// blocking
	flags = fcntl(sock, F_GETFL, 0);
	fcntl(sock, F_SETFL, flags & ~O_NONBLOCK);
	
	return ret;
}


void fini_ssl(struct ssl_param *param)
{
	// Socks5 over TLS
	if(param->client_ssl_socks5 != NULL){
		SSL_shutdown(param->client_ssl_socks5);
		SSL_free(param->client_ssl_socks5);
	}
	if(param->client_ctx_socks5 != NULL){
		SSL_CTX_free(param->client_ctx_socks5);
	}
	
	return;
}


void close_socket(int sock)
{
	shutdown(sock, SHUT_RDWR);
	usleep(500);
	close(sock);
	
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
	int socks5_flag = 0;
	int client_sock = r->connection->fd;
	int flags = 0;
	int ret = 0;
	int err = 0;
	int socks5_over_tls_flag = 0;	// 0:socks5 over aes 1:socks5 over tls
	
	SSL_CTX *client_ctx_socks5 = NULL;
	SSL *client_ssl_socks5 = NULL;
	
	struct worker_param worker_param;
	long tv_sec = 3;	// recv send
	long tv_usec = 0;	// recv send
	long forwarder_tv_sec = 3;
	long forwarder_tv_usec = 0;
	struct ssl_param ssl_param;
	ssl_param.client_ctx_socks5 = NULL;
	ssl_param.client_ssl_socks5 = NULL;

	BIO *bio = NULL;
	EVP_PKEY *s_privatekey_socks5 = NULL;
	X509 *s_cert_socks5 = NULL;
	
	EVP_ENCODE_CTX *base64_encode_ctx = NULL;
	int length = 0;
	unsigned char aes_key_b64[45];
	unsigned char aes_iv_b64[25];
	unsigned char aes_key[33];
	unsigned char aes_iv[17];
	bzero(&aes_key_b64, 45);
	bzero(&aes_iv_b64, 25);
	bzero(&aes_key, 33);
	bzero(&aes_iv, 17);
	
	
	// search header
	h = search_headers_in(r, (u_char *)HTTP_REQUEST_HEADER_SOCKS5_KEY, (size_t)(strlen(HTTP_REQUEST_HEADER_SOCKS5_KEY)));
	if(h != NULL &&  ngx_strcasecmp(h->value.data, (u_char *)HTTP_REQUEST_HEADER_SOCKS5_VALUE) == 0){	// socks5
		socks5_flag = 1;
	}
	
	h = search_headers_in(r, (u_char *)HTTP_REQUEST_HEADER_AESKEY_KEY, (size_t)(strlen(HTTP_REQUEST_HEADER_AESKEY_KEY)));
	if(h != NULL){	// aes key
		memcpy(&aes_key_b64, (unsigned char *)h->value.data, 44);
		base64_encode_ctx = EVP_ENCODE_CTX_new();
		EVP_DecodeInit(base64_encode_ctx);
		EVP_DecodeUpdate(base64_encode_ctx, (unsigned char *)aes_key, &length, (unsigned char *)aes_key_b64, 44);
		EVP_DecodeFinal(base64_encode_ctx, (unsigned char *)aes_key, &length);
		EVP_ENCODE_CTX_free(base64_encode_ctx);
#ifdef _DEBUG
		printf("[I] aes_key_b64:%s\n", aes_key_b64);
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] aes_key_b64:%s", aes_key_b64);
#endif
	}
	
	h = search_headers_in(r, (u_char *)HTTP_REQUEST_HEADER_AESIV_KEY, (size_t)(strlen(HTTP_REQUEST_HEADER_AESIV_KEY)));
	if(h != NULL){	// aes iv
		memcpy(&aes_iv_b64, (unsigned char *)h->value.data, 24);
		base64_encode_ctx = EVP_ENCODE_CTX_new();
		EVP_DecodeInit(base64_encode_ctx);
		EVP_DecodeUpdate(base64_encode_ctx, (unsigned char *)aes_iv, &length, (unsigned char *)aes_iv_b64, 24);
		EVP_DecodeFinal(base64_encode_ctx, (unsigned char *)aes_iv, &length);
		EVP_ENCODE_CTX_free(base64_encode_ctx);
#ifdef _DEBUG
		printf("[I] aes_iv_b64:%s\n", aes_iv_b64);
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] aes_iv_b64:%s", aes_iv_b64);
#endif
	}
	
	h = search_headers_in(r, (u_char *)HTTP_REQUEST_HEADER_TLS_KEY, (size_t)(strlen(HTTP_REQUEST_HEADER_TLS_KEY)));
	if(h != NULL &&  ngx_strcasecmp(h->value.data, (u_char *)HTTP_REQUEST_HEADER_TLS_VALUE2) == 0){
		socks5_over_tls_flag = 1;	// Socks5 over TLS
	}else{
		socks5_over_tls_flag = 0;	// Socks5 over AES
	}
	
	h = search_headers_in(r, (u_char *)HTTP_REQUEST_HEADER_TVSEC_KEY, (size_t)(strlen(HTTP_REQUEST_HEADER_TVSEC_KEY)));
	if(h != NULL){
		tv_sec = atol((char *)h->value.data);
	}
	
	h = search_headers_in(r, (u_char *)HTTP_REQUEST_HEADER_TVUSEC_KEY, (size_t)(strlen(HTTP_REQUEST_HEADER_TVUSEC_KEY)));
	if(h != NULL){
		tv_usec = atol((char *)h->value.data);
	}
	
	h = search_headers_in(r, (u_char *)HTTP_REQUEST_HEADER_FORWARDER_TVSEC_KEY, (size_t)(strlen(HTTP_REQUEST_HEADER_FORWARDER_TVSEC_KEY)));
	if(h != NULL){
		forwarder_tv_sec = atol((char *)h->value.data);
	}
	
	h = search_headers_in(r, (u_char *)HTTP_REQUEST_HEADER_FORWARDER_TVUSEC_KEY, (size_t)(strlen(HTTP_REQUEST_HEADER_FORWARDER_TVUSEC_KEY)));
	if(h != NULL){
		forwarder_tv_usec = atol((char *)h->value.data);
	}
	
	if(socks5_flag == 1){	// socks5
#ifdef _DEBUG
		printf("[I] Socks5 start.\n");
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] Socks5 start.");
#endif
		
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
#ifdef _DEBUG
		printf("[I] Timeout recv/send tv_sec:%ld sec recv/send tv_usec:%ld microsec.\n", tv_sec, tv_usec);
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] Timeout recv/send tv_sec:%l sec recv/send tv_usec:%l microsec.", tv_sec, tv_usec);
		printf("[I] Timeout forwarder tv_sec:%ld sec forwarder tv_usec:%ld microsec.\n", forwarder_tv_sec, forwarder_tv_usec);
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] Timeout forwarder tv_sec:%l sec forwarder tv_usec:%l microsec.", forwarder_tv_sec, forwarder_tv_usec);
#endif

		// blocking
		flags = fcntl(client_sock, F_GETFL, 0);
		fcntl(client_sock, F_SETFL, flags & ~O_NONBLOCK);
		
		// send OK to client
		ret = send_data_aes(r, client_sock, "OK", strlen("OK"), aes_key, aes_iv, tv_sec, tv_usec);
		if(ret <= 0){
#ifdef _DEBUG
			printf("[E] Send OK message error.\n");
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Send OK message error.");
#endif
			return ngx_http_next_header_filter(r);
		}
#ifdef _DEBUG
		printf("[I] Send OK message.\n");
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] Send OK message.");
#endif
		
		if(socks5_over_tls_flag == 1){	// Socks5 over TLS
			// SSL Initialize
			OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS, NULL);
			
			// SSL TLS connection
			client_ctx_socks5 = SSL_CTX_new(TLS_server_method());
			if(client_ctx_socks5 == NULL){
#ifdef _DEBUG
				printf("[E] SSL_CTX_new error.\n");
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] SSL_CTX_new error.");
#endif
				return ngx_http_next_header_filter(r);
			}
			ssl_param.client_ctx_socks5 = client_ctx_socks5;
			
			// server private key (Socks5 over TLS)
			bio = BIO_new(BIO_s_mem());
			BIO_write(bio, server_privatekey_socks5, strlen(server_privatekey_socks5));
			PEM_read_bio_PrivateKey(bio, &s_privatekey_socks5, NULL, NULL);
			BIO_free(bio);
			
			// server X509 certificate (Socks5 over TLS)
			bio = BIO_new(BIO_s_mem());
			BIO_write(bio, server_certificate_socks5, strlen(server_certificate_socks5));
			PEM_read_bio_X509(bio, &s_cert_socks5, NULL, NULL);
			BIO_free(bio);

			SSL_CTX_use_certificate(client_ctx_socks5, s_cert_socks5);
			SSL_CTX_use_PrivateKey(client_ctx_socks5, s_privatekey_socks5);
			err = SSL_CTX_check_private_key(client_ctx_socks5);
			if(err != 1){
#ifdef _DEBUG
				printf("[E] SSL_CTX_check_private_key error.\n");
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] SSL_CTX_check_private_key error.");
#endif
				fini_ssl(&ssl_param);
				return ngx_http_next_header_filter(r);
			}
			
//			SSL_CTX_set_mode(client_ctx_socks5, SSL_MODE_AUTO_RETRY);
			
			if(SSL_CTX_set_min_proto_version(client_ctx_socks5, TLS1_2_VERSION) == 0){
#ifdef _DEBUG
				printf("[E] SSL_CTX_set_min_proto_version error.\n");
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] SSL_CTX_set_min_proto_version error.");
#endif
				fini_ssl(&ssl_param);
				return ngx_http_next_header_filter(r);
			}
			
			ret = SSL_CTX_set_cipher_list(client_ctx_socks5, cipher_suite_tls_1_2);
			if(ret == 0){
#ifdef _DEBUG
				printf("[E] SSL_CTX_set_cipher_list error.\n");
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] SSL_CTX_set_cipher_list error.");
#endif
				fini_ssl(&ssl_param);
				return ngx_http_next_header_filter(r);
			}
			
			ret = SSL_CTX_set_ciphersuites(client_ctx_socks5, cipher_suite_tls_1_3);
			if(ret == 0){
#ifdef _DEBUG
				printf("[E] SSL_CTX_set_ciphersuites error.\n");
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] SSL_CTX_set_ciphersuites error.");
#endif
				fini_ssl(&ssl_param);
				return ngx_http_next_header_filter(r);
			}
			
			client_ssl_socks5 = SSL_new(client_ctx_socks5);
			if(client_ssl_socks5 == NULL){
#ifdef _DEBUG
				printf("[E] SSL_new error.\n");
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] SSL_new error.");
#endif
				fini_ssl(&ssl_param);
				return ngx_http_next_header_filter(r);
			}
			ssl_param.client_ssl_socks5 = client_ssl_socks5;
			
			if(SSL_set_fd(client_ssl_socks5, client_sock) == 0){
#ifdef _DEBUG
				printf("[E] SSL_set_fd error.\n");
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] SSL_set_fd error.");
#endif
				fini_ssl(&ssl_param);
				return ngx_http_next_header_filter(r);
			}
			
			// accept
#ifdef _DEBUG
			printf("[I] Try Socks5 over TLS connection. (SSL_accept)\n");
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] Try Socks5 over TLS connection. (SSL_accept)");
#endif
			ret = ssl_sccept_non_blocking(r, client_sock, client_ssl_socks5, tv_sec, tv_usec);
			if(ret == -2){
#ifdef _DEBUG
				printf("[E] SSL_accept error.\n");
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] SSL_accept error.");
#endif
				fini_ssl(&ssl_param);
				return ngx_http_next_header_filter(r);
			}
#ifdef _DEBUG
			printf("[I] Succeed Socks5 over TLS connection. (SSL_accept)\n");
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] Succeed Socks5 over TLS connection. (SSL_accept)");
#endif
		}
		
		worker_param.client_sock = client_sock;
		worker_param.client_ssl_socks5 = client_ssl_socks5;
		worker_param.socks5_over_tls_flag = socks5_over_tls_flag;
		worker_param.aes_key = (unsigned char *)aes_key;
		worker_param.aes_iv = (unsigned char *)aes_iv;
		worker_param.tv_sec = tv_sec;
		worker_param.tv_usec = tv_usec;
		worker_param.forwarder_tv_sec = forwarder_tv_sec;
		worker_param.forwarder_tv_usec = forwarder_tv_usec;
		
		ret = worker(r, &worker_param);
		
		fini_ssl(&ssl_param);
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

