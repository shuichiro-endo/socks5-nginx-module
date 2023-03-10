/*
 * Title:  socks5 server header (nginx module)
 * Author: Shuichiro Endo
 */

static ngx_table_elt_t *search_headers_in(ngx_http_request_t *r, u_char *name, size_t len);
static ngx_int_t ngx_http_socks5_header_filter(ngx_http_request_t *r);
static ngx_int_t ngx_http_socks5_body_filter(ngx_http_request_t *r, ngx_chain_t *in);
static ngx_int_t ngx_http_socks5_init(ngx_conf_t *cf);

int recvData(ngx_http_request_t *r, int sock, void *buffer, int length);
int recvDataTls(ngx_http_request_t *r, SSL *ssl ,void *buffer, int length);
int sendData(ngx_http_request_t *r, int sock, void *buffer, int length);
int sendDataTls(ngx_http_request_t *r, SSL *ssl, void *buffer, int length);
int forwarder(ngx_http_request_t *r, int clientSock, int targetSock);
int forwarderTls(ngx_http_request_t *r, int clientSock, int targetSock, SSL *clientSslSocks5);
int sendSocksResponseIpv4(ngx_http_request_t *r, int clientSock, char ver, char req, char rsv, char atyp);
int sendSocksResponseIpv4Tls(ngx_http_request_t *r, SSL *clientSsl, char ver, char req, char rsv, char atyp);
int sendSocksResponseIpv6(ngx_http_request_t *r, int clientSock, char ver, char req, char rsv, char atyp);
int sendSocksResponseIpv6Tls(ngx_http_request_t *r, SSL *clientSsl, char ver, char req, char rsv, char atyp);
int worker(ngx_http_request_t *r, void *ptr);

typedef struct {
	int clientSock;
	SSL *clientSslSocks5;
	int socks5OverTlsFlag;	// 0:socks5 1:socks5 over tls
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

