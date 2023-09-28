/*
 * Title:  socks5 client windows (nginx module)
 * Author: Shuichiro Endo
 */

#define _DEBUG

#include <stdio.h>
#include <winsock2.h>
#include <Windows.h>
#include <ws2tcpip.h>
#include <string.h>
#include <iostream>
#include <stdlib.h>
#include <process.h>
#include <time.h>

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

#pragma comment(lib,"ws2_32.lib")	// Winsock Library
#pragma comment(lib,"libssl.lib")	// OpenSSL Library
#pragma comment(lib,"libcrypto.lib")	// OpenSSL Library

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

int optstringIndex = 0;
char *optarg = NULL;

char *socks5_server_ip = NULL;
char *socks5_server_port = NULL;
char *socks5_target_ip = NULL;
char *socks5_target_port = NULL;
int https_flag = 0;		// 0:http 1:https
int socks5_over_tls_flag = 0;	// 0:socks5 over aes 1:socks5 over tls

char server_certificate_filename_https[256] = "server_https.crt";	// server certificate filename (HTTPS)
char server_certificate_file_directory_path_https[256] = ".";	// server certificate file directory path (HTTPS)

char server_certificate_filename_socks5[256] = "server_socks5.crt";	// server certificate filename (Socks5 over TLS)
char server_certificate_file_directory_path_socks5[256] = ".";	// server certificate file directory path (Socks5 over TLS)


int encrypt_aes(unsigned char *plaintext, int plaintext_length, unsigned char *aes_key, unsigned char *aes_iv, unsigned char *ciphertext)
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


int decrypt_aes(unsigned char *ciphertext, int ciphertext_length, unsigned char *aes_key, unsigned char *aes_iv, unsigned char *plaintext)
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


/*
 * Reference:
 * https://stackoverflow.com/questions/10905892/equivalent-of-gettimeofday-for-windows
 */
int gettimeofday(timeval *tv, timezone *tz)
{
	if(tv){
		FILETIME filetime;
		ULARGE_INTEGER x;
		ULONGLONG usec;
		static const ULONGLONG epoch_offset_us = 11644473600000000ULL;

#if _WIN32_WINNT >= WIN32_WINNT_WIN8
		GetSystemTimePreciseAsFileTime(&filetime);
#else
		GetSystemTimeAsFileTime(&filetime);
#endif

		x.LowPart = filetime.dwLowDateTime;
		x.HighPart = filetime.dwHighDateTime;
		usec = x.QuadPart / 10 - epoch_offset_us;
		tv->tv_sec = (long)(usec / 1000000ULL);
		tv->tv_usec = (long)(usec % 1000000ULL);
	}else{
		return -1;
	}

	if(tz){
		TIME_ZONE_INFORMATION timezone;
		GetTimeZoneInformation(&timezone);
		tz->tz_minuteswest = timezone.Bias;
		tz->tz_dsttime = 0;
	}

	return 0;
}


int recv_data(SOCKET sock, void *buffer, int length, long tv_sec, long tv_usec)
{
	int rec = 0;
	int err = 0;
	fd_set readfds;
	timeval tv;
	timeval start;
	timeval end;
	long t = 0;
	ZeroMemory(buffer, length+1);
	
	if(gettimeofday(&start, NULL) == -1){
#ifdef _DEBUG
		printf("[E] gettimeofday error.\n");
#endif
		return -1;
	}
	
	while(1){
		if(gettimeofday(&end, NULL) == -1){
#ifdef _DEBUG
			printf("[E] gettimeofday error.\n");
#endif
			return -1;
		}
		
		t = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec);	// microsecond
		if(t >= (tv_sec * 1000000 + tv_usec)){
#ifdef _DEBUG
			printf("[I] recv_data timeout.\n");
#endif
			return -1;
		}
		
		FD_ZERO(&readfds);
		FD_SET(sock, &readfds);
		tv.tv_sec = tv_sec;
		tv.tv_usec = tv_usec;
		
		if(select(NULL, &readfds, NULL, NULL, &tv) == 0){
#ifdef _DEBUG
			printf("[I] recv_data select timeout.\n");
#endif
			return -1;
		}
		
		if(FD_ISSET(sock, &readfds)){
			rec = recv(sock, (char *)buffer, length, 0);
			if(rec == SOCKET_ERROR){
				err = WSAGetLastError();
				if(err == WSAEWOULDBLOCK){
					Sleep(5);
					continue;
				}
#ifdef _DEBUG
				printf("[E] recv error:%d.\n", err);
#endif
				return -1;
			}else{
				break;
			}
		}
	}
	
	return rec;
}


int recv_data_aes(SOCKET sock, void *buffer, int length, unsigned char *aes_key, unsigned char *aes_iv, long tv_sec, long tv_usec)
{
	int rec = 0;
	int err = 0;
	fd_set readfds;
	timeval tv;
	timeval start;
	timeval end;
	long t = 0;
	ZeroMemory(buffer, length+1);
	int ret = 0;
	send_recv_data_aes *data;
	int encrypt_data_length = 0;
	unsigned char *tmp = (unsigned char *)calloc(16, sizeof(unsigned char));
	char *buffer2 = (char *)calloc(BUFFER_SIZE*2, sizeof(char));
	
	if(gettimeofday(&start, NULL) == -1){
#ifdef _DEBUG
		printf("[E] gettimeofday error.\n");
#endif
		free(tmp);
		free(buffer2);
		return -1;
	}
	
	while(1){
		if(gettimeofday(&end, NULL) == -1){
#ifdef _DEBUG
			printf("[E] gettimeofday error.\n");
#endif
			free(tmp);
			free(buffer2);
			return -1;
		}
		
		t = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec);	// microsecond
		if(t >= (tv_sec * 1000000 + tv_usec)){
#ifdef _DEBUG
			printf("[I] recv_data_aes timeout.\n");
#endif
			free(tmp);
			free(buffer2);
			return -1;
		}
		
		FD_ZERO(&readfds);
		FD_SET(sock, &readfds);
		tv.tv_sec = tv_sec;
		tv.tv_usec = tv_usec;
		
		if(select(NULL, &readfds, NULL, NULL, &tv) == 0){
#ifdef _DEBUG
			printf("[I] recv_data_aes select timeout.\n");
#endif
			free(tmp);
			free(buffer2);
			return -1;
		}
		
		if(FD_ISSET(sock, &readfds)){
			rec = recv(sock, buffer2, BUFFER_SIZE*2, 0);
			if(rec == SOCKET_ERROR){
				err = WSAGetLastError();
				if(err == WSAEWOULDBLOCK){
					Sleep(5);
					continue;
				}
#ifdef _DEBUG
				printf("[E] recv error:%d.\n", err);
#endif
				free(tmp);
				free(buffer2);
				return -1;
			}else if(rec >= 16){	// unsigned char encrypt_data_length[16]
				data = (send_recv_data_aes *)buffer2;
				
				ret = decrypt_aes(data->encrypt_data_length, 16, aes_key, aes_iv, (unsigned char *)tmp);
				if(ret == 4){	// int encrypt_data_length
					encrypt_data_length = (tmp[0] << 24)|(tmp[1] << 16)|(tmp[2] << 8)|(tmp[3]);
				}else{
					free(tmp);
					free(buffer2);
					return -1;
				}
				
				if(encrypt_data_length <= rec-16){
					ret = decrypt_aes(data->encrypt_data, encrypt_data_length, aes_key, aes_iv, (unsigned char *)buffer);
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


int recv_data_tls(SOCKET sock, SSL *ssl ,void *buffer, int length, long tv_sec, long tv_usec)
{
	int rec = 0;
	int err = 0;
	fd_set readfds;
	timeval tv;
	timeval start;
	timeval end;
	long t = 0;
	ZeroMemory(buffer, length+1);
	
	if(gettimeofday(&start, NULL) == -1){
#ifdef _DEBUG
		printf("[E] gettimeofday error.\n");
#endif
		return -2;
	}
	
	while(1){
		if(gettimeofday(&end, NULL) == -1){
#ifdef _DEBUG
			printf("[E] gettimeofday error.\n");
#endif
			return -2;
		}
		
		t = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec);	// microsecond
		if(t >= (tv_sec * 1000000 + tv_usec)){
#ifdef _DEBUG
			printf("[I] recv_data_tls timeout.\n");
#endif
			return -2;
		}
		
		FD_ZERO(&readfds);
		FD_SET(sock, &readfds);
		tv.tv_sec = tv_sec;
		tv.tv_usec = tv_usec;
		
		if(select(NULL, &readfds, NULL, NULL, &tv) == 0){
#ifdef _DEBUG
			printf("[I] recv_data_tls select timeout.\n");
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
				Sleep(5);
			}else if(err == SSL_ERROR_WANT_WRITE){
				Sleep(5);
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


int send_data(SOCKET sock, void *buffer, int length, long tv_sec, long tv_usec)
{
	int sen = 0;
	int err = 0;
	int send_length = 0;
	int len = length;
	fd_set writefds;
	timeval tv;
	timeval start;
	timeval end;
	long t = 0;
	
	if(gettimeofday(&start, NULL) == -1){
#ifdef _DEBUG
		printf("[E] gettimeofday error.\n");
#endif
		return -1;
	}
	
	while(len > 0){
		if(gettimeofday(&end, NULL) == -1){
#ifdef _DEBUG
			printf("[E] gettimeofday error.\n");
#endif
			return -1;
		}
		
		t = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec);	// microsecond
		if(t >= (tv_sec * 1000000 + tv_usec)){
#ifdef _DEBUG
			printf("[I] send_data timeout.\n");
#endif
			return -1;
		}
		
		FD_ZERO(&writefds);
		FD_SET(sock, &writefds);
		tv.tv_sec = tv_sec;
		tv.tv_usec = tv_usec;
		
		if(select(NULL, NULL, &writefds, NULL, &tv) == 0){
#ifdef _DEBUG
			printf("[I] send_data select timeout.\n");
#endif
			return -1;
		}
		
		if(FD_ISSET(sock, &writefds)){
			sen = send(sock, (char *)buffer+send_length, len, 0);
			if(sen == SOCKET_ERROR){
				err = WSAGetLastError();
				if(err == WSAEWOULDBLOCK){
					Sleep(5);
					continue;
				}
#ifdef _DEBUG
				printf("[E] send error:%d.\n", err);
#endif
				return -1;
			}
			send_length += sen;
			len -= sen;
		}
	}
	
	return length;
}


int send_data_aes(SOCKET sock, void *buffer, int length, unsigned char *aes_key, unsigned char *aes_iv, long tv_sec, long tv_usec)
{
	int sen = 0;
	int err = 0;
	int send_length = 0;
	int len = 0;
	fd_set writefds;
	timeval tv;
	timeval start;
	timeval end;
	long t = 0;
	int ret = 0;
	send_recv_data_aes *data = (send_recv_data_aes *)calloc(1, sizeof(send_recv_data_aes));
	int encrypt_data_length = 0;
	unsigned char *tmp = (unsigned char *)calloc(16, sizeof(unsigned char));
	
	ret = encrypt_aes((unsigned char *)buffer, length, aes_key, aes_iv, data->encrypt_data);
	if(ret > 0){
		encrypt_data_length = ret;
	}else{
		free(tmp);
		free(data);
		return -1;
	}
	
	tmp[0] = (unsigned char)(encrypt_data_length >> 24);
	tmp[1] = (unsigned char)(encrypt_data_length >> 16);
	tmp[2] = (unsigned char)(encrypt_data_length >> 8);
	tmp[3] = (unsigned char)encrypt_data_length;
	
	ret = encrypt_aes((unsigned char *)tmp, 4, aes_key, aes_iv, data->encrypt_data_length);
	if(ret != 16){	// unsigned char encrypt_data_length[16]
		free(tmp);
		free(data);
		return -1;
	}
	
	len = 16 + encrypt_data_length;
	
	if(gettimeofday(&start, NULL) == -1){
#ifdef _DEBUG
		printf("[E] gettimeofday error.\n");
#endif
		free(tmp);
		free(data);
		return -1;
	}
	
	while(len > 0){
		if(gettimeofday(&end, NULL) == -1){
#ifdef _DEBUG
			printf("[E] gettimeofday error.\n");
#endif
			free(tmp);
			free(data);
			return -1;
		}
		
		t = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec);	// microsecond
		if(t >= (tv_sec * 1000000 + tv_usec)){
#ifdef _DEBUG
			printf("[I] send_data_aes timeout.\n");
#endif
			free(tmp);
			free(data);
			return -1;
		}
		
		FD_ZERO(&writefds);
		FD_SET(sock, &writefds);
		tv.tv_sec = tv_sec;
		tv.tv_usec = tv_usec;
		
		if(select(NULL, NULL, &writefds, NULL, &tv) == 0){
#ifdef _DEBUG
			printf("[I] send_data_aes select timeout.\n");
#endif
			free(tmp);
			free(data);
			return -1;
		}
		
		if(FD_ISSET(sock, &writefds)){
			sen = send(sock, (char *)data+send_length, len, 0);
			if(sen == SOCKET_ERROR){
				err = WSAGetLastError();
				if(err == WSAEWOULDBLOCK){
					Sleep(5);
					continue;
				}
#ifdef _DEBUG
				printf("[E] send error:%d.\n", err);
#endif
				free(tmp);
				free(data);
				return -1;
			}
			send_length += sen;
			len -= sen;
		}
	}
	
	free(tmp);
	free(data);
	return length;
}


int send_data_tls(SOCKET sock, SSL *ssl, void *buffer, int length, long tv_sec, long tv_usec)
{
	int sen = 0;
	int err = 0;
	fd_set writefds;
	timeval tv;
	timeval start;
	timeval end;
	long t = 0;
	
	if(gettimeofday(&start, NULL) == -1){
#ifdef _DEBUG
		printf("[E] gettimeofday error.\n");
#endif
		return -2;
	}
	
	while(1){
		if(gettimeofday(&end, NULL) == -1){
#ifdef _DEBUG
			printf("[E] gettimeofday error.\n");
#endif
			return -2;
		}
		
		t = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec);	// microsecond
		if(t >= (tv_sec * 1000000 + tv_usec)){
#ifdef _DEBUG
			printf("[I] send_data_tls timeout.\n");
#endif
			return -2;
		}
		
		FD_ZERO(&writefds);
		FD_SET(sock, &writefds);
		tv.tv_sec = tv_sec;
		tv.tv_usec = tv_usec;
		
		if(select(NULL, NULL, &writefds, NULL, &tv) == 0){
#ifdef _DEBUG
			printf("[I] send_data_tls select timeout.\n");
#endif
			return -2;
		}
		
		if(FD_ISSET(sock, &writefds)){
			sen = SSL_write(ssl, buffer, length);
			err = SSL_get_error(ssl, sen);
			
			if(err == SSL_ERROR_NONE){
				break;
			}else if(err == SSL_ERROR_WANT_WRITE){
				Sleep(5);
			}else if(err == SSL_ERROR_WANT_READ){
				Sleep(5);
			}else{
#ifdef _DEBUG
				printf("[E] SSL_write error:%d:%s.\n", err, ERR_error_string(ERR_peek_last_error(), NULL));
#endif
				return -2;
			}
		}
	}
		
	return length;
}


int forwarder(SOCKET client_sock, SOCKET target_sock, long tv_sec, long tv_usec)
{
	int rec,sen;
	int err = 0;
	int len = 0;
	int send_length = 0;
	fd_set readfds;
	timeval tv;
	char buffer[BUFFER_SIZE+1];
	ZeroMemory(buffer, BUFFER_SIZE+1);
	
	while(1){
		FD_ZERO(&readfds);
		FD_SET(client_sock, &readfds);
		FD_SET(target_sock, &readfds);
		tv.tv_sec = tv_sec;
		tv.tv_usec = tv_usec;
		
		if(select(NULL, &readfds, NULL, NULL, &tv) == 0){
#ifdef _DEBUG
			printf("[I] forwarder select timeout.\n");
#endif
			break;
		}
		
		if(FD_ISSET(client_sock, &readfds)){
			rec = recv(client_sock, buffer, BUFFER_SIZE, 0);
			if(rec == SOCKET_ERROR){
				err = WSAGetLastError();
				if(err == WSAEWOULDBLOCK){
					Sleep(5);
				}else{
#ifdef _DEBUG
					printf("[E] recv error:%d.\n", err);
#endif
					return -1;
				}
			}else{
				len = rec;
				send_length = 0;
				
				while(len > 0){
					sen = send(target_sock, buffer+send_length, len, 0);
					if(sen == SOCKET_ERROR){
						err = WSAGetLastError();
						if(err == WSAEWOULDBLOCK){
							Sleep(5);
							continue;
						}
#ifdef _DEBUG
						printf("[E] send error:%d.\n", err);
#endif
						return -1;
					}
					send_length += sen;
					len -= sen;
				}
			}
		}
		
		if(FD_ISSET(target_sock, &readfds)){
			rec = recv(target_sock, buffer, BUFFER_SIZE, 0);
			if(rec == SOCKET_ERROR){
				err = WSAGetLastError();
				if(err  == WSAEWOULDBLOCK){
					Sleep(5);
				}else{
#ifdef _DEBUG
					printf("[E] recv error:%d.\n", err);
#endif
					return -1;
				}
			}else{
				len = rec;
				send_length = 0;
				
				while(len > 0){
					sen = send(client_sock, buffer+send_length, len, 0);
					if(sen == SOCKET_ERROR){
						err = WSAGetLastError();
						if(err == WSAEWOULDBLOCK){
							Sleep(5);
							continue;
						}
#ifdef _DEBUG
						printf("[E] send error:%d.\n", err);
#endif
						return -1;
					}
					send_length += sen;
					len -= sen;
				}
			}
		}
	}

	return 0;
}


int forwarder_aes(SOCKET client_sock, SOCKET target_sock, unsigned char *aes_key, unsigned char *aes_iv, long tv_sec, long tv_usec)
{
	int rec,sen;
	int err = 0;
	int len = 0;
	int recv_length = 0;
	int send_length = 0;
	fd_set readfds;
	timeval tv;
	int ret = 0;
	send_recv_data_aes * data = (send_recv_data_aes *)calloc(1, sizeof(send_recv_data_aes));
	int encrypt_data_length = 0;
	unsigned char *tmp = (unsigned char *)calloc(16, sizeof(unsigned char));
	char *buffer = (char *)calloc(BUFFER_SIZE*2, sizeof(char));
	char *buffer2 = (char *)calloc(BUFFER_SIZE*2, sizeof(char));
	
	while(1){
		FD_ZERO(&readfds);
		FD_SET(client_sock, &readfds);
		FD_SET(target_sock, &readfds);
		tv.tv_sec = tv_sec;
		tv.tv_usec = tv_usec;
		
		if(select(NULL, &readfds, NULL, NULL, &tv) == 0){
#ifdef _DEBUG
			printf("[I] forwarder_aes select timeout.\n");
#endif
			break;
		}
		
		if(FD_ISSET(client_sock, &readfds)){
			ZeroMemory(tmp, 16);
			ZeroMemory(data, sizeof(send_recv_data_aes));
			ZeroMemory(buffer, BUFFER_SIZE*2);
			
			rec = recv(client_sock, buffer, BUFFER_SIZE, 0);
			if(rec == SOCKET_ERROR){
				err = WSAGetLastError();
				if(err == WSAEWOULDBLOCK){
					Sleep(5);
					continue;
				}else{
#ifdef _DEBUG
					printf("[E] recv error:%d.\n", err);
#endif
					free(tmp);
					free(data);
					free(buffer);
					free(buffer2);
					return -1;
				}
			}else{
				ret = encrypt_aes((unsigned char *)buffer, rec, aes_key, aes_iv, data->encrypt_data);
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
				
				ret = encrypt_aes((unsigned char *)tmp, 4, aes_key, aes_iv, data->encrypt_data_length);
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
					sen = send(target_sock, (char *)data+send_length, len, 0);
					if(sen == SOCKET_ERROR){
						err = WSAGetLastError();
						if(err == WSAEWOULDBLOCK){
							Sleep(5);
							continue;
						}
#ifdef _DEBUG
						printf("[E] send error:%d.\n", err);
#endif
						free(tmp);
						free(data);
						free(buffer);
						free(buffer2);
						return -1;
					}
					send_length += sen;
					len -= sen;
				}
			}
		}
		
		if(FD_ISSET(target_sock, &readfds)){
			ZeroMemory(tmp, 16);
			ZeroMemory(buffer, BUFFER_SIZE*2);
			ZeroMemory(buffer2, BUFFER_SIZE*2);

			len = 16;
			recv_length = 0;

			while(len > 0){
				rec = recv(target_sock, (char *)buffer+recv_length, len, 0);	// unsigned char encrypt_data_length[16]
				if(rec == SOCKET_ERROR){
					err = WSAGetLastError();
					if(err == WSAEWOULDBLOCK){
						Sleep(5);
						continue;
					}else{
#ifdef _DEBUG
						printf("[E] recv error:%d.\n", err);
#endif
						free(tmp);
						free(data);
						free(buffer);
						free(buffer2);
						return -1;
					}
				}
				recv_length += rec;
				len -= rec;
			}

			ret = decrypt_aes((unsigned char *)buffer, 16, aes_key, aes_iv, (unsigned char *)tmp);
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

			ZeroMemory(buffer, BUFFER_SIZE*2);
			len = encrypt_data_length;
			recv_length = 0;

			while(len > 0){
				rec = recv(target_sock, (char *)buffer+recv_length, len, 0);
				if(rec == SOCKET_ERROR){
					err = WSAGetLastError();
					if(err == WSAEWOULDBLOCK){
						Sleep(5);
						continue;
					}else{
#ifdef _DEBUG
						printf("[E] recv error:%d.\n", err);
#endif
						free(tmp);
						free(data);
						free(buffer);
						free(buffer2);
						return -1;
					}
				}
				recv_length += rec;
				len -= rec;
			}

			ret = decrypt_aes((unsigned char *)buffer, encrypt_data_length, aes_key, aes_iv, (unsigned char *)buffer2);
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
				sen = send(client_sock, buffer2+send_length, len, 0);
				if(sen == SOCKET_ERROR){
					err = WSAGetLastError();
					if(err == WSAEWOULDBLOCK){
						Sleep(5);
						continue;
					}
#ifdef _DEBUG
					printf("[E] send error:%d.\n", err);
#endif
					free(tmp);
					free(data);
					free(buffer);
					free(buffer2);
					return -1;
				}
				send_length += sen;
				len -= sen;
			}
		}
	}
	
	free(tmp);
	free(data);
	free(buffer);
	free(buffer2);
	return 0;
}


int forwarder_tls(SOCKET client_sock, SOCKET target_sock, SSL *target_ssl, long tv_sec, long tv_usec)
{
	int rec,sen;
	int len = 0;
	int send_length = 0;
	fd_set readfds;
	timeval tv;
	char *buffer = (char *)calloc(BUFFER_SIZE*2, sizeof(char));
	int err = 0;
	
	while(1){
		FD_ZERO(&readfds);
		FD_SET(client_sock, &readfds);
		FD_SET(target_sock, &readfds);
		tv.tv_sec = tv_sec;
		tv.tv_usec = tv_usec;
		
		if(select(NULL, &readfds, NULL, NULL, &tv) == 0){
#ifdef _DEBUG
			printf("[I] forwarder_tls select timeout.\n");
#endif
			break;
		}
		
		if(FD_ISSET(client_sock, &readfds)){
			ZeroMemory(buffer, BUFFER_SIZE*2);

			rec = recv(client_sock, buffer, BUFFER_SIZE, 0);
			if(rec == SOCKET_ERROR){
				err = WSAGetLastError();
				if(err == WSAEWOULDBLOCK){
					Sleep(5);
					continue;
				}else{
					free(buffer);
					return -2;
				}
			}else{
				while(1){
					sen = SSL_write(target_ssl, buffer, rec);
					err = SSL_get_error(target_ssl, sen);
					
					if(err == SSL_ERROR_NONE){
						break;
					}else if(err == SSL_ERROR_WANT_WRITE){
						Sleep(5);
					}else if(err == SSL_ERROR_WANT_READ){
						Sleep(5);
					}else{
#ifdef _DEBUG
						printf("[E] SSL_write error:%d:%s.\n", err, ERR_error_string(ERR_peek_last_error(), NULL));
#endif
						free(buffer);
						return -2;
					}
				}
			}
		}
		
		if(FD_ISSET(target_sock, &readfds)){
			ZeroMemory(buffer, BUFFER_SIZE*2);

			rec = SSL_read(target_ssl, buffer, BUFFER_SIZE);
			err = SSL_get_error(target_ssl, rec);
			
			if(err == SSL_ERROR_NONE){
				len = rec;
				send_length = 0;
				
				while(len > 0){
					sen = send(client_sock, buffer+send_length, len, 0);
					if(sen == SOCKET_ERROR){
						err = WSAGetLastError();
						if(err == WSAEWOULDBLOCK){
							Sleep(5);
							continue;
						}
#ifdef _DEBUG
						printf("[E] send error:%d.\n", err);
#endif
						free(buffer);
						return -2;
					}
					send_length += sen;
					len -= sen;
				}
			}else if(err == SSL_ERROR_ZERO_RETURN){
				break;
			}else if(err == SSL_ERROR_WANT_READ){
				Sleep(5);
			}else if(err == SSL_ERROR_WANT_WRITE){
				Sleep(5);
			}else{
#ifdef _DEBUG
				printf("[E] SSL_read error:%d:%s.\n", err, ERR_error_string(ERR_peek_last_error(), NULL));
#endif
				free(buffer);
				return -2;
			}
		}
	}

	free(buffer);
	return 0;
}


int ssl_connect_non_blocking(SOCKET sock, SSL *ssl, long tv_sec, long tv_usec)
{
	fd_set readfds;
	fd_set writefds;
	timeval tv;
	timeval start;
	timeval end;
	long t = 0;
	int ret = 0;
	int err = 0;
	u_long iMode = 0;
	
	// non blocking
	iMode = 1;	// non-blocking mode
	err = ioctlsocket(sock, FIONBIO, &iMode);
	if(err != NO_ERROR){
#ifdef _DEBUG
		printf("[E] ioctlsocket error:%d\n.", err);
#endif
		return -2;
	}

	if(gettimeofday(&start, NULL) == -1){
#ifdef _DEBUG
		printf("[E] gettimeofday error.\n");
#endif
		// blocking
		iMode = 0;	// blocking mode
		err = ioctlsocket(sock, FIONBIO, &iMode);
		if(err != NO_ERROR){
#ifdef _DEBUG
			printf("[E] ioctlsocket error:%d\n.", err);
#endif
		}
		return -2;
	}

	while(1){
		FD_ZERO(&readfds);
		FD_ZERO(&writefds);
		FD_SET(sock, &readfds);
		FD_SET(sock, &writefds);
		tv.tv_sec = tv_sec;
		tv.tv_usec = tv_usec;
		
		if(select(NULL, &readfds, &writefds, NULL, &tv) == 0){
#ifdef _DEBUG
			printf("[I] ssl_connect_non_blocking select timeout.\n");
#endif
			// blocking
			iMode = 0;	// blocking mode
			err = ioctlsocket(sock, FIONBIO, &iMode);
			if(err != NO_ERROR){
#ifdef _DEBUG
				printf("[E] ioctlsocket error:%d\n.", err);
#endif
			}
			return -2;
		}
		
		if(FD_ISSET(sock, &readfds) || FD_ISSET(sock, &writefds)){
			ret = SSL_connect(ssl);
			err = SSL_get_error(ssl, ret);
			
			if(err == SSL_ERROR_NONE){
				break;
			}else if(err == SSL_ERROR_WANT_READ){
				Sleep(5);
			}else if(err == SSL_ERROR_WANT_WRITE){
				Sleep(5);
			}else{
#ifdef _DEBUG
				printf("[E] SSL_connect error:%d:%s.\n", err, ERR_error_string(ERR_peek_last_error(), NULL));
#endif
				// blocking
				iMode = 0;	// blocking mode
				err = ioctlsocket(sock, FIONBIO, &iMode);
				if(err != NO_ERROR){
#ifdef _DEBUG
					printf("[E] ioctlsocket error:%d\n.", err);
#endif
				}
				return -2;
			}
		}
		
		if(gettimeofday(&end, NULL) == -1){
#ifdef _DEBUG
			printf("[E] gettimeofday error.\n");
#endif
			// blocking
			iMode = 0;	// blocking mode
			err = ioctlsocket(sock, FIONBIO, &iMode);
			if(err != NO_ERROR){
#ifdef _DEBUG
				printf("[E] ioctlsocket error:%d\n.", err);
#endif
			}
			return -2;
		}
		
		t = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec);	// microsecond
		if(t >= (tv_sec * 1000000 + tv_usec)){
#ifdef _DEBUG
			printf("[I] ssl_connect_non_blocking timeout.\n");
#endif
			// blocking
			iMode = 0;	// blocking mode
			err = ioctlsocket(sock, FIONBIO, &iMode);
			if(err != NO_ERROR){
#ifdef _DEBUG
				printf("[E] ioctlsocket error:%d\n.", err);
#endif
			}
			return -2;
		}
	}
	
	// blocking
	iMode = 0;	// blocking mode
	err = ioctlsocket(sock, FIONBIO, &iMode);
	if(err != NO_ERROR){
#ifdef _DEBUG
		printf("[E] ioctlsocket error:%d\n.", err);
#endif
	}
	
	return ret;
}


void fini_ssl(ssl_param *param)
{
	// Socks5 over TLS
	if(param->target_ssl_socks5 != NULL){
		if(https_flag == 0 && socks5_over_tls_flag == 1){	// HTTP and Socks5 over TLS
			SSL_shutdown(param->target_ssl_socks5);
		}
		SSL_free(param->target_ssl_socks5);
	}
	if(param->target_ctx_socks5 != NULL){
		SSL_CTX_free(param->target_ctx_socks5);
	}
	
	// HTTPS
	if(param->target_ssl_http != NULL){
		SSL_shutdown(param->target_ssl_http);
		SSL_free(param->target_ssl_http);
	}
	if(param->target_ctx_http != NULL){
		SSL_CTX_free(param->target_ctx_http);
	}

	return;
}


void close_socket(SOCKET sock)
{
	shutdown(sock, SD_BOTH);
	Sleep(1);
	closesocket(sock);

	return;
}


int worker(void *ptr)
{
	worker_param *worker_param = (struct worker_param *)ptr;
	SOCKET client_sock = worker_param->client_sock;
	long tv_sec = worker_param->tv_sec;		// recv send
	long tv_usec = worker_param->tv_usec;		// recv send
	long forwarder_tv_sec = worker_param->forwarder_tv_sec;
	long forwarder_tv_usec = worker_param->forwarder_tv_usec;
	worker_param = NULL;
	free(ptr);
	
	SOCKET target_sock = -1;
	sockaddr_in target_addr, *tmp_ipv4;		// IPv4
	memset(&target_addr, 0, sizeof(sockaddr_in));
	
	sockaddr_in6 target_addr6, *tmp_ipv6;	// IPv6
	memset(&target_addr6, 0, sizeof(sockaddr_in6));

	addrinfo hints, *target_host;
	memset(&hints, 0, sizeof(addrinfo));

	int family = 0;
	char *domainname = socks5_target_ip;
	u_short domainname_length = strlen(domainname);
	char *colon = NULL;
	char *service = socks5_target_port;
	int flags = 0;
	u_long iMode = 1;	// non-blocking mode
	int ret = 0;
	int err = 0;
	
	SSL_CTX *target_ctx_http = NULL;
	SSL *target_ssl_http = NULL;
	SSL_CTX *target_ctx_socks5 = NULL;
	SSL *target_ssl_socks5 = NULL;

	ssl_param ssl_param;
	ssl_param.target_ctx_http = NULL;
	ssl_param.target_ssl_http = NULL;
	ssl_param.target_ctx_socks5 = NULL;
	ssl_param.target_ssl_socks5 = NULL;

	char buffer[BUFFER_SIZE+1];
	ZeroMemory(&buffer, BUFFER_SIZE+1);
	int rec, sen;
	int count = 0;
	int check = 0;
	
	char http_request[BUFFER_SIZE+1];
	int http_request_length = 0;
	ZeroMemory(http_request, BUFFER_SIZE+1);
	
	EVP_ENCODE_CTX *base64_encode_ctx = NULL;
	int length = 0;
	unsigned char aes_key[33];
	ZeroMemory(&aes_key, 33);
	ret = RAND_bytes((unsigned char *)aes_key, 32);
	if(ret != 1){
#ifdef _DEBUG
		printf("[E] aes key generate error:%s.\n", ERR_error_string(ERR_peek_last_error(), NULL));
#endif
		close_socket(client_sock);
		return -1;
	}
	unsigned char aes_key_b64[45];
	ZeroMemory(&aes_key_b64, 45);
	base64_encode_ctx = EVP_ENCODE_CTX_new();
	EVP_EncodeInit(base64_encode_ctx);
	EVP_EncodeUpdate(base64_encode_ctx, (unsigned char *)aes_key_b64, &length, (unsigned char *)aes_key, 32);
	EVP_EncodeFinal(base64_encode_ctx, (unsigned char *)aes_key_b64, &length);
	EVP_ENCODE_CTX_free(base64_encode_ctx);
	aes_key_b64[44] = 0x0;	// delete newline character
#ifdef _DEBUG
	printf("[I] aes key (base64):%s\n", aes_key_b64);
#endif
	
	unsigned char aes_iv[17];
	ZeroMemory(&aes_iv, 17);
	ret = RAND_bytes((unsigned char *)aes_iv, 16);
	if(ret != 1){
#ifdef _DEBUG
		printf("[E] aes iv generate error:%s.\n", ERR_error_string(ERR_peek_last_error(), NULL));
#endif
		close_socket(client_sock);
		return -1;
	}
	unsigned char aes_iv_b64[25];
	ZeroMemory(&aes_iv_b64, 25);
	base64_encode_ctx = EVP_ENCODE_CTX_new();
	EVP_EncodeInit(base64_encode_ctx);
	EVP_EncodeUpdate(base64_encode_ctx, (unsigned char *)aes_iv_b64, &length, (unsigned char *)aes_iv, 16);
	EVP_EncodeFinal(base64_encode_ctx, (unsigned char *)aes_iv_b64, &length);
	EVP_ENCODE_CTX_free(base64_encode_ctx);
	aes_iv_b64[24] = 0x0;	// delete newline character
#ifdef _DEBUG
	printf("[I] aes iv  (base64):%s\n", aes_iv_b64);
#endif
	
	
#ifdef _DEBUG
	printf("[I] Domainname:%s, Length:%d.\n", domainname, domainname_length);
#endif
	colon = strstr(domainname, ":");	// check ipv6 address
	if(colon == NULL){	// ipv4 address or domainname
		hints.ai_family = AF_INET;	// IPv4
		if(getaddrinfo(domainname, service, &hints, &target_host) != 0){
			hints.ai_family = AF_INET6;	// IPv6
			if(getaddrinfo(domainname, service, &hints, &target_host) != 0){
#ifdef _DEBUG
				printf("[E] Cannot resolv the domain name:%s.\n", domainname);
#endif
				close_socket(client_sock);
				return -1;
			}
		}
	}else{	// ipv6 address
		hints.ai_family = AF_INET6;	// IPv6
		if(getaddrinfo(domainname, service, &hints, &target_host) != 0){
#ifdef _DEBUG
			printf("[E] Cannot resolv the domain name:%s.\n", domainname);
#endif
			close_socket(client_sock);
			return -1;
		}
	}

	if(target_host->ai_family == AF_INET){
		family = AF_INET;
		target_addr.sin_family = AF_INET;
		tmp_ipv4 = (sockaddr_in *)target_host->ai_addr;
		memcpy(&target_addr.sin_addr, &tmp_ipv4->sin_addr, sizeof(unsigned long));
		memcpy(&target_addr.sin_port, &tmp_ipv4->sin_port, 2);
		freeaddrinfo(target_host);
	}else if(target_host->ai_family == AF_INET6){
		family = AF_INET6;
		target_addr6.sin6_family = AF_INET6;
		tmp_ipv6 = (sockaddr_in6 *)target_host->ai_addr;
		memcpy(&target_addr6.sin6_addr, &tmp_ipv6->sin6_addr, sizeof(in6_addr));
		memcpy(&target_addr6.sin6_port, &tmp_ipv6->sin6_port, 2);;
		freeaddrinfo(target_host);
	}else{
#ifdef _DEBUG
		printf("[E] Not implemented.\n");
#endif
		freeaddrinfo(target_host);
		close_socket(client_sock);
		return -1;
	}

	if(family == AF_INET){	// IPv4
		target_sock = socket(AF_INET, SOCK_STREAM, 0);
		if(target_sock == INVALID_SOCKET){
#ifdef _DEBUG
			printf("[E] Socket error:%d.\n", WSAGetLastError());
#endif
			close_socket(client_sock);
			return -1;
		}

		if(err = connect(target_sock, (sockaddr *)&target_addr, sizeof(target_addr)) < 0){
#ifdef _DEBUG
			printf("[E] Connect failed. errno:%d\n", err);
#endif
			close_socket(target_sock);
			close_socket(client_sock);
			return -1;
		}
	}else if(family == AF_INET6){	// IPv6
		target_sock = socket(AF_INET6, SOCK_STREAM, 0);
		if(target_sock == INVALID_SOCKET){
#ifdef _DEBUG
			printf("[E] Socket error:%d.\n", WSAGetLastError());
#endif
			close_socket(client_sock);
			return -1;
		}

		if(err = connect(target_sock, (sockaddr *)&target_addr6, sizeof(target_addr6)) < 0){
#ifdef _DEBUG
			printf("[E] Connect failed. errno:%d\n", err);
#endif
			close_socket(target_sock);
			close_socket(client_sock);
			return -1;
		}
	}else{
#ifdef _DEBUG
		printf("[E] Not implemented.\n");
#endif
		close_socket(client_sock);
		return -1;
	}
#ifdef _DEBUG
	printf("[I] Connect target socks5 server.\n");
#endif

	if(socks5_over_tls_flag == 0){	// Socks5 over AES
		http_request_length = snprintf(http_request, BUFFER_SIZE+1, "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\n%s: %s\r\n%s: %s\r\n%s: %s\r\n%s: %ld\r\n%s: %ld\r\n%s: %ld\r\n%s: %ld\r\nConnection: close\r\n\r\n", domainname, HTTP_REQUEST_HEADER_SOCKS5_KEY, HTTP_REQUEST_HEADER_SOCKS5_VALUE, HTTP_REQUEST_HEADER_AESKEY_KEY, aes_key_b64, HTTP_REQUEST_HEADER_AESIV_KEY, aes_iv_b64, HTTP_REQUEST_HEADER_TVSEC_KEY, tv_sec, HTTP_REQUEST_HEADER_TVUSEC_KEY, tv_usec, HTTP_REQUEST_HEADER_FORWARDER_TVSEC_KEY, forwarder_tv_sec, HTTP_REQUEST_HEADER_FORWARDER_TVUSEC_KEY, forwarder_tv_usec);
	}else{	// Socks5 over TLS
		http_request_length = snprintf(http_request, BUFFER_SIZE+1, "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\n%s: %s\r\n%s: %s\r\n%s: %s\r\n%s: %s\r\n%s: %ld\r\n%s: %ld\r\n%s: %ld\r\n%s: %ld\r\nConnection: close\r\n\r\n", domainname, HTTP_REQUEST_HEADER_SOCKS5_KEY, HTTP_REQUEST_HEADER_SOCKS5_VALUE, HTTP_REQUEST_HEADER_AESKEY_KEY, aes_key_b64, HTTP_REQUEST_HEADER_AESIV_KEY, aes_iv_b64, HTTP_REQUEST_HEADER_TLS_KEY, HTTP_REQUEST_HEADER_TLS_VALUE2, HTTP_REQUEST_HEADER_TVSEC_KEY, tv_sec, HTTP_REQUEST_HEADER_TVUSEC_KEY, tv_usec, HTTP_REQUEST_HEADER_FORWARDER_TVSEC_KEY, forwarder_tv_sec, HTTP_REQUEST_HEADER_FORWARDER_TVUSEC_KEY, forwarder_tv_usec);
	}
	
	if(https_flag == 1){	// HTTPS
		// SSL Initialize
		OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS, NULL);

		// SSL TLS connection
		target_ctx_http = SSL_CTX_new(TLS_client_method());
		if(target_ctx_http == NULL){
#ifdef _DEBUG
			printf("[E] SSL_CTX_new error.\n");
#endif
			close_socket(target_sock);
			close_socket(client_sock);
			return -2;
		}
		ssl_param.target_ctx_http = target_ctx_http;

//		SSL_CTX_set_mode(target_ctx_http, SSL_MODE_AUTO_RETRY);
		
		if(SSL_CTX_set_min_proto_version(target_ctx_http, TLS1_2_VERSION) == 0){
#ifdef _DEBUG
			printf("[E] SSL_CTX_set_min_proto_version error.\n");
#endif
			fini_ssl(&ssl_param);
			close_socket(target_sock);
			close_socket(client_sock);
			return -2;
		}
		
		SSL_CTX_set_default_verify_paths(target_ctx_http);
		SSL_CTX_load_verify_locations(target_ctx_http, server_certificate_filename_https, server_certificate_file_directory_path_https);
		SSL_CTX_set_verify(target_ctx_http, SSL_VERIFY_PEER, NULL);
		
		target_ssl_http = SSL_new(target_ctx_http);
		if(target_ssl_http == NULL){
#ifdef _DEBUG
			printf("[E] SSL_new error.\n");
#endif
			fini_ssl(&ssl_param);
			close_socket(target_sock);
			close_socket(client_sock);
			return -2;
		}
		ssl_param.target_ssl_http = target_ssl_http;
	
		if(SSL_set_fd(target_ssl_http, target_sock) == 0){
#ifdef _DEBUG
			printf("[E] SSL_set_fd error.\n");
#endif
			fini_ssl(&ssl_param);
			close_socket(target_sock);
			close_socket(client_sock);
			return -2;
		}
		
#ifdef _DEBUG
		printf("[I] Try HTTPS connection. (SSL_connect)\n");
#endif
		ret = SSL_connect(target_ssl_http);
		if(ret <= 0){
			err = SSL_get_error(target_ssl_http, ret);
#ifdef _DEBUG
			printf("[E] SSL_connect error:%d:%s.\n", err, ERR_error_string(ERR_peek_last_error(), NULL));
#endif
			fini_ssl(&ssl_param);
			close_socket(target_sock);
			close_socket(client_sock);
			return -2;
		}

#ifdef _DEBUG
		printf("[I] Succeed HTTPS connection. (SSL_connect)\n");
#endif
		
		// HTTP Request
		sen = send_data_tls(target_sock, target_ssl_http, http_request, http_request_length, tv_sec, tv_usec);
		if(sen <= 0){
#ifdef _DEBUG
			printf("[E] Send http request.\n");
#endif
			fini_ssl(&ssl_param);
			close_socket(target_sock);
			close_socket(client_sock);
			return -2;
		}
#ifdef _DEBUG
		printf("[I] Send http request.\n");
#endif
	}else{
		// HTTP Request
		sen = send_data(target_sock, http_request, http_request_length, tv_sec, tv_usec);
		if(sen <= 0){
#ifdef _DEBUG
			printf("[E] Send http request.\n");
#endif
			fini_ssl(&ssl_param);
			close_socket(target_sock);
			close_socket(client_sock);
			return -1;
		}
#ifdef _DEBUG
		printf("[I] Send http request.\n");
#endif
	}
	
	
	// check Server
	count = 0;
	check = 0;
	do{
		count++;
		rec = recv_data_aes(target_sock, buffer, BUFFER_SIZE, aes_key, aes_iv, tv_sec, tv_usec);
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
		rec = recv_data_aes(target_sock, buffer, BUFFER_SIZE, aes_key, aes_iv, tv_sec, tv_usec);	// rec: 2("OK") or -1
#ifdef _DEBUG
//		printf("[I] rec:%d\n", rec);
#endif
	}else{
#ifdef _DEBUG
		printf("[E] Server Socks5 NG.\n");
#endif
		fini_ssl(&ssl_param);
		close_socket(target_sock);
		close_socket(client_sock);
		return -1;
	}

	
	if(socks5_over_tls_flag == 1){	// Socks5 over TLS
		// SSL Initialize
		OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS, NULL);
		
		// SSL TLS connection
		target_ctx_socks5 = SSL_CTX_new(TLS_client_method());
		if(target_ctx_socks5 == NULL){
#ifdef _DEBUG
			printf("[E] SSL_CTX_new error.\n");
#endif
			fini_ssl(&ssl_param);
			close_socket(target_sock);
			close_socket(client_sock);
			return -2;
		}
		ssl_param.target_ctx_socks5 = target_ctx_socks5;

//		SSL_CTX_set_mode(target_ctx_socks5, SSL_MODE_AUTO_RETRY);
		
		if(SSL_CTX_set_min_proto_version(target_ctx_socks5, TLS1_2_VERSION) == 0){
#ifdef _DEBUG
			printf("[E] SSL_CTX_set_min_proto_version error.\n");
#endif
			fini_ssl(&ssl_param);
			close_socket(target_sock);
			close_socket(client_sock);
			return -2;
		}

		SSL_CTX_set_default_verify_paths(target_ctx_socks5);
		SSL_CTX_load_verify_locations(target_ctx_socks5, server_certificate_filename_socks5, server_certificate_file_directory_path_socks5);
		SSL_CTX_set_verify(target_ctx_socks5, SSL_VERIFY_PEER, NULL);
		
		target_ssl_socks5 = SSL_new(target_ctx_socks5);
		if(target_ssl_socks5 == NULL){
#ifdef _DEBUG
			printf("[E] SSL_new error.\n");
#endif
			fini_ssl(&ssl_param);
			close_socket(target_sock);
			close_socket(client_sock);
			return -2;
		}
		ssl_param.target_ssl_socks5 = target_ssl_socks5;

		if(SSL_set_fd(target_ssl_socks5, target_sock) == 0){
#ifdef _DEBUG
			printf("[E] SSL_set_fd error.\n");
#endif
			fini_ssl(&ssl_param);
			close_socket(target_sock);
			close_socket(client_sock);
			return -2;
		}
		
#ifdef _DEBUG
		printf("[I] Try Socks5 over TLS connection. (SSL_connect)\n");
#endif
		ret = SSL_connect(target_ssl_socks5);
		if(ret <= 0){
			err = SSL_get_error(target_ssl_socks5, ret);
#ifdef _DEBUG
			printf("[E] SSL_connect error:%d:%s.\n", err, ERR_error_string(ERR_peek_last_error(), NULL));
#endif
			fini_ssl(&ssl_param);
			close_socket(target_sock);
			close_socket(client_sock);
			return -2;
		}

#ifdef _DEBUG
		printf("[I] Succeed Socks5 over TLS connection. (SSL_connect)\n");
#endif
	}


	// socks selection_request	client -> server
	if((rec = recv_data(client_sock, buffer, BUFFER_SIZE, tv_sec, tv_usec)) <= 0){
#ifdef _DEBUG
		printf("[E] Receive selection request. client -> server\n");
#endif
		fini_ssl(&ssl_param);
		close_socket(target_sock);
		close_socket(client_sock);
		return -1;
	}
#ifdef _DEBUG
	printf("[I] Receive selection request:%d bytes. client -> server\n", rec);
#endif


	// socks selection_request	server -> target
	if(socks5_over_tls_flag == 0){
		sen = send_data_aes(target_sock, buffer, rec, aes_key, aes_iv, tv_sec, tv_usec);
	}else{
		sen = send_data_tls(target_sock, target_ssl_socks5, buffer, rec, tv_sec, tv_usec);
	}
	if(sen <= 0){
#ifdef _DEBUG
		printf("[E] Send selection request. server -> target.\n");
#endif
		fini_ssl(&ssl_param);
		close_socket(target_sock);
		close_socket(client_sock);
		return -1;
	}
#ifdef _DEBUG
	printf("[I] Send selection request:%d bytes. server -> target\n", sen);	
#endif


	// socks selection_response	server <- target
	if(socks5_over_tls_flag == 0){
		rec = recv_data_aes(target_sock, buffer, BUFFER_SIZE, aes_key, aes_iv, tv_sec, tv_usec);
	}else{
		rec = recv_data_tls(target_sock, target_ssl_socks5, buffer, BUFFER_SIZE, tv_sec, tv_usec);
	}
	if(rec != sizeof(selection_response)){
#ifdef _DEBUG
		printf("[E] Receive selection response. server <- target\n");
#endif
		fini_ssl(&ssl_param);
		close_socket(target_sock);
		close_socket(client_sock);
		return -1;
	}
#ifdef _DEBUG
	printf("[I] Receive selection response:%d bytes. server <- target\n", rec);
#endif


	// socks selection_response	client <- server
	sen = send_data(client_sock, buffer, rec, tv_sec, tv_usec);
	if(sen <= 0){
#ifdef _DEBUG
		printf("[E] Send selection response. client <- server\n");
#endif
		fini_ssl(&ssl_param);
		close_socket(target_sock);
		close_socket(client_sock);
		return -1;
	}
#ifdef _DEBUG
	printf("[I] Send selection response:%d bytes. client <- server\n", sen);
#endif
	selection_response *selection_response = (struct selection_response *)&buffer;
	if((unsigned char)selection_response->method == 0xFF){
#ifdef _DEBUG
		printf("[E] Target socks5server Authentication Method error.\n");
#endif
	}

	if(selection_response->method == 0x2){	// username_password_authentication
		// socks username_password_authentication_request		client -> server
		if((rec = recv_data(client_sock, buffer, BUFFER_SIZE, tv_sec, tv_usec)) <= 0){
#ifdef _DEBUG
			printf("[E] Receive username password authentication request. client -> server\n");
#endif
			fini_ssl(&ssl_param);
			close_socket(target_sock);
			close_socket(client_sock);
			return -1;
		}
#ifdef _DEBUG
		printf("[I] Receive username password authentication request:%d bytes. client -> server\n", rec);
#endif


		// socks username_password_authentication_request		server -> target
		if(socks5_over_tls_flag == 0){
			sen = send_data_aes(target_sock, buffer, rec, aes_key, aes_iv, tv_sec, tv_usec);
		}else{
			sen = send_data_tls(target_sock, target_ssl_socks5, buffer, rec, tv_sec, tv_usec);
		}
		if(sen <= 0){
#ifdef _DEBUG
			printf("[E] Send username password authentication request. server -> target\n");
#endif
			fini_ssl(&ssl_param);
			close_socket(target_sock);
			close_socket(client_sock);
			return -1;
		}
#ifdef _DEBUG
		printf("[I] Send username password authentication request:%d bytes. server -> target\n", sen);	
#endif
		

		// socks username_password_authentication_response	server <- target
		if(socks5_over_tls_flag == 0){
			rec = recv_data_aes(target_sock, buffer, BUFFER_SIZE, aes_key, aes_iv, tv_sec, tv_usec);
		}else{
			rec = recv_data_tls(target_sock, target_ssl_socks5, buffer, BUFFER_SIZE, tv_sec, tv_usec);
		}
		if(rec <= 0){
#ifdef _DEBUG
			printf("[E] Receive username password authentication response. server <- target\n");
#endif
			fini_ssl(&ssl_param);
			close_socket(target_sock);
			close_socket(client_sock);
			return -1;
		}
#ifdef _DEBUG
		printf("[I] Receive username password authentication response:%d bytes. server <- target\n", rec);
#endif


		// socks username_password_authentication_response	client <- server
		sen = send_data(client_sock, buffer, rec, tv_sec, tv_usec);
		if(sen <= 0){
#ifdef _DEBUG
			printf("[E] Send username password authentication response. client <- server\n");
#endif
			fini_ssl(&ssl_param);
			close_socket(target_sock);
			close_socket(client_sock);
			return -1;
		}
#ifdef _DEBUG
		printf("[I] Send username password authentication response:%d bytes. client <- server\n", sen);
#endif
	}


	// socks socks_request	client -> server
	if((rec = recv_data(client_sock, buffer, BUFFER_SIZE, tv_sec, tv_usec)) <= 0){
#ifdef _DEBUG
		printf("[E] Receive socks request. client -> server\n");
#endif
		fini_ssl(&ssl_param);
		close_socket(target_sock);
		close_socket(client_sock);
		return -1;
	}
#ifdef _DEBUG
	printf("[I] Receive socks request:%d bytes. client -> server\n", rec);
#endif


	// socks socks_request	server -> target
	if(socks5_over_tls_flag == 0){
		sen = send_data_aes(target_sock, buffer, rec, aes_key, aes_iv, tv_sec, tv_usec);
	}else{
		sen = send_data_tls(target_sock, target_ssl_socks5, buffer, rec, tv_sec, tv_usec);
	}
	if(sen <= 0){
#ifdef _DEBUG
		printf("[E] Send socks request. server -> target\n");
#endif
		fini_ssl(&ssl_param);
		close_socket(target_sock);
		close_socket(client_sock);
		return -1;
	}
#ifdef _DEBUG
	printf("[I] Send socks request:%d bytes. server -> target\n", sen);	
#endif
	

	// socks socks_response	server <- target
	if(socks5_over_tls_flag == 0){
		rec = recv_data_aes(target_sock, buffer, BUFFER_SIZE, aes_key, aes_iv, tv_sec, tv_usec);
	}else{
		rec = recv_data_tls(target_sock, target_ssl_socks5, buffer, BUFFER_SIZE, tv_sec, tv_usec);
	}
	if(rec <= 0){
#ifdef _DEBUG
		printf("[E] Receive socks response. server <- target\n");
#endif
		fini_ssl(&ssl_param);
		close_socket(target_sock);
		close_socket(client_sock);
		return -1;
	}
#ifdef _DEBUG
	printf("[I] Receive socks response:%d bytes. server <- target\n", rec);
#endif


	// socks socks_response	client <- server
	sen = send_data(client_sock, buffer, rec, tv_sec, tv_usec);
	if(sen <= 0){
#ifdef _DEBUG
		printf("[E] Send socks response. client <- server\n");
#endif
		fini_ssl(&ssl_param);
		close_socket(target_sock);
		close_socket(client_sock);
		return -1;
	}
#ifdef _DEBUG
	printf("[I] Send socks response:%d bytes. client <- server\n", sen);
#endif


	iMode = 1;	// non-blocking mode
	err = ioctlsocket(client_sock, FIONBIO, &iMode);
	if(err != NO_ERROR){
#ifdef _DEBUG
		printf("[E] ioctlsocket error:%d\n.", err);
#endif
		fini_ssl(&ssl_param);
		close_socket(target_sock);
		close_socket(client_sock);
		return -1;
	}

	err = ioctlsocket(target_sock, FIONBIO, &iMode);
	if(err != NO_ERROR){
#ifdef _DEBUG
		printf("[E] ioctlsocket error:%d\n.", err);
#endif
		fini_ssl(&ssl_param);
		close_socket(target_sock);
		close_socket(client_sock);
		return -1;
	}


	// forwarder
#ifdef _DEBUG
	printf("[I] Forwarder.\n");
#endif
	if(socks5_over_tls_flag == 0){
		err = forwarder_aes(client_sock, target_sock, aes_key, aes_iv, forwarder_tv_sec, forwarder_tv_usec);
	}else{
		err = forwarder_tls(client_sock, target_sock, target_ssl_socks5, forwarder_tv_sec, forwarder_tv_usec);
	}


#ifdef _DEBUG
	printf("[I] Worker exit.\n");
#endif
	Sleep(5);
	fini_ssl(&ssl_param);
	close_socket(target_sock);
	close_socket(client_sock);

	return 0;
}


void worker_thread(void *ptr)
{
	int err = 0;

	err = worker(ptr);

	_endthread();
}


void usage(char *filename)
{
	printf("usage   : %s -h listen_ip -p listen_port -H target_socks5server_domainname -P target_socks5server_port [-s (HTTPS)] [-t (Socks5 over TLS)] [-A recv/send tv_sec(timeout 0-10 sec)] [-B recv/send tv_usec(timeout 0-1000000 microsec)] [-C forwarder tv_sec(timeout 0-300 sec)] [-D forwarder tv_usec(timeout 0-1000000 microsec)]\n", filename);
	printf("example : %s -h 127.0.0.1 -p 9050 -H 192.168.0.10 -P 80\n", filename);
	printf("        : %s -h 127.0.0.1 -p 9050 -H foobar.test -P 80 -t\n", filename);
	printf("        : %s -h 127.0.0.1 -p 9050 -H foobar.test -P 80 -t -A 3 -B 0 -C 3 -D 0\n", filename);
	printf("        : %s -h 127.0.0.1 -p 9050 -H 192.168.0.10 -P 443 -s\n", filename);
	printf("        : %s -h 127.0.0.1 -p 9050 -H foobar.test -P 443 -s -t\n", filename);
	printf("        : %s -h 127.0.0.1 -p 9050 -H foobar.test -P 443 -s -t -A 3 -B 0 -C 3 -D 0\n", filename);
}


int getopt(int argc, char **argv, char *optstring)
{
	unsigned char opt = '\0';
	unsigned char next = '\0';
	char *argtmp = NULL;

	while(1){
		opt = *(optstring + optstringIndex);
		optstringIndex++;
		if(opt == '\0'){
			break;
		}

		next = *(optstring + optstringIndex);
		if(next == ':'){
			optstringIndex++;
		}

		for(int i=1; i<argc; i++){
			argtmp = argv[i];
			if(argtmp[0] == '-'){
				if(argtmp[1] == opt){
					if(next == ':'){
						optarg = argv[i+1];
						return (int)opt;
					}else{
						return (int)opt;
					}
				}
			}
		}
	}

	return 0;
}


int main(int argc, char **argv)
{
	int opt;
	char optstring[] = "h:p:H:P:stA:B:C:D:";
	long tv_sec = 3;	// recv send
	long tv_usec = 0;	// recv send
	long forwarder_tv_sec = 3;
	long forwarder_tv_usec = 0;
	
	while((opt=getopt(argc, argv, optstring)) > 0){
		switch(opt){
		case 'h':
			socks5_server_ip = optarg;
			break;
			
		case 'p':
			socks5_server_port = optarg;
			break;
		
		case 'H':
			socks5_target_ip = optarg;
			break;
			
		case 'P':
			socks5_target_port = optarg;
			break;
			
		case 's':
			https_flag = 1;
			break;
			
		case 't':
			socks5_over_tls_flag = 1;
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

	if(socks5_server_ip == NULL || socks5_server_port == NULL || socks5_target_ip == NULL || socks5_target_port == NULL){
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
	
	if(https_flag == 0){	// HTTP
#ifdef _DEBUG
		printf("[I] HTTPS:off\n");
#endif
	}else{	// HTTPS
#ifdef _DEBUG
		printf("[I] HTTPS:on\n");
#endif
	}
	
	if(socks5_over_tls_flag == 0){	// Socks5 over AES
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
	
	
	WSADATA wsaData;
	SOCKET server_sock = INVALID_SOCKET;
	SOCKET client_sock = INVALID_SOCKET;
	sockaddr_in server_addr, client_addr;
	int err = 0;

	err = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if(err != 0){
#ifdef _DEBUG
		printf("[E] WSAStartup error:%d.\n", err);
#endif
		return -1;
	}

	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = inet_addr(socks5_server_ip);
	server_addr.sin_port = htons(atoi(socks5_server_port));
	
	server_sock = socket(AF_INET, SOCK_STREAM, 0);
	if(server_sock == INVALID_SOCKET){
#ifdef _DEBUG
		printf("[E] Socket error:%d.\n", WSAGetLastError());
#endif
		WSACleanup();
		return -1;
	}
	
	// bind
	if(bind(server_sock, (sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
#ifdef _DEBUG
		printf("[E] bind error.\n");
#endif
		WSACleanup();
		return -1;
	}
	
	// listen
	listen(server_sock, 5);
#ifdef _DEBUG
	printf("[I] Listenning port %d on %s.\n", ntohs(server_addr.sin_port), inet_ntoa(server_addr.sin_addr));
#endif

	// accept
	int client_addr_length = sizeof(client_addr);
	while((client_sock = accept(server_sock, (sockaddr *)&client_addr, (socklen_t *)&client_addr_length))){
#ifdef _DEBUG
		printf("[I] Connected from %s.\n", inet_ntoa(client_addr.sin_addr));
#endif
		
		worker_param *worker_param = (struct worker_param *)calloc(1, sizeof(struct worker_param));
		worker_param->client_sock = client_sock;
		worker_param->tv_sec = tv_sec;
		worker_param->tv_usec = tv_usec;
		worker_param->forwarder_tv_sec = forwarder_tv_sec;
		worker_param->forwarder_tv_usec = forwarder_tv_usec;
		
		_beginthread(worker_thread, 0, worker_param);
	}

	close_socket(server_sock);
	WSACleanup();

	return 0;
}
