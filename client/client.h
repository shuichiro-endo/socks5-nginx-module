/*
 * Title:  socks5 client header (nginx module)
 * Author: Shuichiro Endo
 */

int recvData(int sock, void *buffer, int length);
int recvDataTls(SSL *ssl ,void *buffer, int length);
int sendData(int sock, void *buffer, int length);
int sendDataTls(SSL *ssl, void *buffer, int length);
int forwarder(int clientSock, int targetSock);
int forwarderTls(int clientSock, int targetSock, SSL *targetSsl);
int worker(void *ptr);
void usage(char *filename);

typedef struct {
	int clientSock;
} PARAM, *pPARAM;

typedef struct {
	SSL_CTX *targetCtxHttp;
	SSL *targetSslHttp;
	SSL_CTX *targetCtxSocks5;
	SSL *targetSslSocks5;
} SSLPARAM, *pSSLPARAM;

void finiSsl(pSSLPARAM pSslParam);

