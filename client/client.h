/*
 * Title:  socks5 client header (nginx module)
 * Author: Shuichiro Endo
 */

#define BUFFER_SIZE 8192

int aesEncrypt(unsigned char *plaintext, int plaintext_length, unsigned char *aes_key, unsigned char *aes_iv, unsigned char *ciphertext);
int aesDecrypt(unsigned char *ciphertext, int ciphertext_length, unsigned char *aes_key, unsigned char *aes_iv, unsigned char *plaintext);
int recvData(int sock, void *buffer, int length, long tv_sec, long tv_usec);
int recvDataAes(int sock, void *buffer, int length, unsigned char *aes_key, unsigned char *aes_iv, long tv_sec, long tv_usec);
int recvDataTls(int sock, SSL *ssl ,void *buffer, int length, long tv_sec, long tv_usec);
int sendData(int sock, void *buffer, int length, long tv_sec, long tv_usec);
int sendDataAes(int sock, void *buffer, int length, unsigned char *aes_key, unsigned char *aes_iv, long tv_sec, long tv_usec);
int sendDataTls(int sock, SSL *ssl, void *buffer, int length, long tv_sec, long tv_usec);
int forwarder(int clientSock, int targetSock, long tv_sec, long tv_usec);
int forwarderAes(int clientSock, int targetSock, unsigned char *aes_key, unsigned char *aes_iv, long tv_sec, long tv_usec);
int forwarderTls(int clientSock, int targetSock, SSL *targetSsl, long tv_sec, long tv_usec);
int sslConnectNonBlock(int sock, SSL *ssl, long tv_sec, long tv_usec);
int worker(void *ptr);
void usage(char *filename);

typedef struct {
	int clientSock;
	long tv_sec;		// recv send
	long tv_usec;		// recv send
	long forwarder_tv_sec;
	long forwarder_tv_usec;
} PARAM, *pPARAM;

typedef struct {
	SSL_CTX *targetCtxHttp;
	SSL *targetSslHttp;
	SSL_CTX *targetCtxSocks5;
	SSL *targetSslSocks5;
} SSLPARAM, *pSSLPARAM;

void finiSsl(pSSLPARAM pSslParam);

typedef struct {
	unsigned char encryptDataLength[16];
	unsigned char encryptData[BUFFER_SIZE*2];
} SEND_RECV_DATA, *pSEND_RECV_DATA;

typedef struct {
	unsigned char encryptDataLength[16];
	unsigned char encryptData[BUFFER_SIZE*10];
} FORWARDER_DATA, *pFORWARDER_DATA;

