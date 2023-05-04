/*
 * Title:  socks5 server header (nginx module)
 * Author: Shuichiro Endo
 */

#define BUFFER_SIZE 8192

static ngx_table_elt_t *search_headers_in(ngx_http_request_t *r, u_char *name, size_t len);
static ngx_int_t ngx_http_socks5_header_filter(ngx_http_request_t *r);
static ngx_int_t ngx_http_socks5_body_filter(ngx_http_request_t *r, ngx_chain_t *in);
static ngx_int_t ngx_http_socks5_init(ngx_conf_t *cf);

int aesEncrypt(ngx_http_request_t *r, unsigned char *plaintext, int plaintext_length, unsigned char *aes_key, unsigned char *aes_iv, unsigned char *ciphertext);
int aesDecrypt(ngx_http_request_t *r, unsigned char *ciphertext, int ciphertext_length, unsigned char *aes_key, unsigned char *aes_iv, unsigned char *plaintext);
int recvData(ngx_http_request_t *r, int sock, void *buffer, int length, long tv_sec, long tv_usec);
int recvDataAes(ngx_http_request_t *r, int sock, void *buffer, int length, unsigned char *aes_key, unsigned char *aes_iv, long tv_sec, long tv_usec);
int recvDataTls(ngx_http_request_t *r, int sock, SSL *ssl ,void *buffer, int length, long tv_sec, long tv_usec);
int sendData(ngx_http_request_t *r, int sock, void *buffer, int length, long tv_sec, long tv_usec);
int sendDataAes(ngx_http_request_t *r, int sock, void *buffer, int length, unsigned char *aes_key, unsigned char *aes_iv, long tv_sec, long tv_usec);
int sendDataTls(ngx_http_request_t *r, int sock, SSL *ssl, void *buffer, int length, long tv_sec, long tv_usec);
int forwarder(ngx_http_request_t *r, int clientSock, int targetSock, long tv_sec, long tv_usec);
int forwarderAes(ngx_http_request_t *r, int clientSock, int targetSock, unsigned char *aes_key, unsigned char *aes_iv, long tv_sec, long tv_usec);
int forwarderTls(ngx_http_request_t *r, int clientSock, int targetSock, SSL *clientSslSocks5, long tv_sec, long tv_usec);
int sendSocksResponseIpv4(ngx_http_request_t *r, int clientSock, char ver, char req, char rsv, char atyp, long tv_sec, long tv_usec);
int sendSocksResponseIpv4Aes(ngx_http_request_t *r, int clientSock, char ver, char req, char rsv, char atyp, unsigned char *aes_key, unsigned char *aes_iv, long tv_sec, long tv_usec);
int sendSocksResponseIpv4Tls(ngx_http_request_t *r, int clientSock, SSL *clientSsl, char ver, char req, char rsv, char atyp, long tv_sec, long tv_usec);
int sendSocksResponseIpv6(ngx_http_request_t *r, int clientSock, char ver, char req, char rsv, char atyp, long tv_sec, long tv_usec);
int sendSocksResponseIpv6Aes(ngx_http_request_t *r, int clientSock, char ver, char req, char rsv, char atyp, unsigned char *aes_key, unsigned char *aes_iv, long tv_sec, long tv_usec);
int sendSocksResponseIpv6Tls(ngx_http_request_t *r, int clientSock, SSL *clientSsl, char ver, char req, char rsv, char atyp, long tv_sec, long tv_usec);
int sslAcceptNonBlock(ngx_http_request_t *r, int sock, SSL *ssl, long tv_sec, long tv_usec);
void closeSocket(int sock);
int worker(ngx_http_request_t *r, void *ptr);

typedef struct {
	int clientSock;
	SSL *clientSslSocks5;
	int socks5OverTlsFlag;	// 0:socks5 1:socks5 over tls
	unsigned char *aes_key;
	unsigned char *aes_iv;
	long tv_sec;		// recv send
	long tv_usec;		// recv send
	long forwarder_tv_sec;
	long forwarder_tv_usec;
} PARAM, *pPARAM;

typedef struct {
	SSL_CTX *clientCtxSocks5;
	SSL *clientSslSocks5;
} SSLPARAM, *pSSLPARAM;

void finiSsl(pSSLPARAM pSslParam);

typedef struct
{
	char ver;
	char ulen;
	char uname;
	// variable
} USERNAME_PASSWORD_AUTHENTICATION_REQUEST_TMP, *pUSERNAME_PASSWORD_AUTHENTICATION_REQUEST_TMP;

typedef struct {
	unsigned char encryptDataLength[16];
	unsigned char encryptData[BUFFER_SIZE*2];
} SEND_RECV_DATA, *pSEND_RECV_DATA;

typedef struct {
	unsigned char encryptDataLength[16];
	unsigned char encryptData[BUFFER_SIZE*10];
} FORWARDER_DATA, *pFORWARDER_DATA;

