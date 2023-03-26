/*
 * Title:  socks5 client header (nginx module)
 * Author: Shuichiro Endo
 */

int recvData(int sock, void *buffer, int length, long tv_sec, long tv_usec);
int recvDataTls(int sock, SSL *ssl ,void *buffer, int length, long tv_sec, long tv_usec);
int sendData(int sock, void *buffer, int length, long tv_sec, long tv_usec);
int sendDataTls(int sock, SSL *ssl, void *buffer, int length, long tv_sec, long tv_usec);
int forwarder(int clientSock, int targetSock, long tv_sec, long tv_usec);
int forwarderTls(int clientSock, int targetSock, SSL *targetSsl, long tv_sec, long tv_usec);
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

