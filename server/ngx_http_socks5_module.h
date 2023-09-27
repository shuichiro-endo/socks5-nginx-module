/*
 * Title:  socks5 server header (nginx module)
 * Author: Shuichiro Endo
 */

#define BUFFER_SIZE 8192

static ngx_table_elt_t *search_headers_in(ngx_http_request_t *r, u_char *name, size_t len);
static ngx_int_t ngx_http_socks5_header_filter(ngx_http_request_t *r);
static ngx_int_t ngx_http_socks5_body_filter(ngx_http_request_t *r, ngx_chain_t *in);
static ngx_int_t ngx_http_socks5_init(ngx_conf_t *cf);

int encrypt_aes(ngx_http_request_t *r, unsigned char *plaintext, int plaintext_length, unsigned char *aes_key, unsigned char *aes_iv, unsigned char *ciphertext);
int decrypt_aes(ngx_http_request_t *r, unsigned char *ciphertext, int ciphertext_length, unsigned char *aes_key, unsigned char *aes_iv, unsigned char *plaintext);
int recv_data(ngx_http_request_t *r, int sock, void *buffer, int length, long tv_sec, long tv_usec);
int recv_data_aes(ngx_http_request_t *r, int sock, void *buffer, int length, unsigned char *aes_key, unsigned char *aes_iv, long tv_sec, long tv_usec);
int recv_data_tls(ngx_http_request_t *r, int sock, SSL *ssl ,void *buffer, int length, long tv_sec, long tv_usec);
int send_data(ngx_http_request_t *r, int sock, void *buffer, int length, long tv_sec, long tv_usec);
int send_data_aes(ngx_http_request_t *r, int sock, void *buffer, int length, unsigned char *aes_key, unsigned char *aes_iv, long tv_sec, long tv_usec);
int send_data_tls(ngx_http_request_t *r, int sock, SSL *ssl, void *buffer, int length, long tv_sec, long tv_usec);
int forwarder(ngx_http_request_t *r, int client_sock, int target_sock, long tv_sec, long tv_usec);
int forwarder_aes(ngx_http_request_t *r, int client_sock, int target_sock, unsigned char *aes_key, unsigned char *aes_iv, long tv_sec, long tv_usec);
int forwarder_tls(ngx_http_request_t *r, int client_sock, int target_sock, SSL *client_ssl_socks5, long tv_sec, long tv_usec);
int send_socks_response_ipv4(ngx_http_request_t *r, int client_sock, char ver, char req, char rsv, char atyp, long tv_sec, long tv_usec);
int send_socks_response_ipv4_aes(ngx_http_request_t *r, int client_sock, char ver, char req, char rsv, char atyp, unsigned char *aes_key, unsigned char *aes_iv, long tv_sec, long tv_usec);
int send_socks_response_ipv4_tls(ngx_http_request_t *r, int client_sock, SSL *client_ssl, char ver, char req, char rsv, char atyp, long tv_sec, long tv_usec);
int send_socks_response_ipv6(ngx_http_request_t *r, int client_sock, char ver, char req, char rsv, char atyp, long tv_sec, long tv_usec);
int send_socks_response_ipv6_aes(ngx_http_request_t *r, int client_sock, char ver, char req, char rsv, char atyp, unsigned char *aes_key, unsigned char *aes_iv, long tv_sec, long tv_usec);
int send_socks_response_ipv6_tls(ngx_http_request_t *r, int client_sock, SSL *client_ssl, char ver, char req, char rsv, char atyp, long tv_sec, long tv_usec);
int ssl_accept_non_blocking(ngx_http_request_t *r, int sock, SSL *ssl, long tv_sec, long tv_usec);
void close_socket(int sock);
int worker(ngx_http_request_t *r, void *ptr);

struct worker_param {
	int client_sock;
	SSL *client_ssl_socks5;
	int socks5_over_tls_flag;	// 0:socks5 over aes 1:socks5 over tls
	unsigned char *aes_key;
	unsigned char *aes_iv;
	long tv_sec;		// recv send
	long tv_usec;		// recv send
	long forwarder_tv_sec;
	long forwarder_tv_usec;
};

struct ssl_param {
	SSL_CTX *client_ctx_socks5;
	SSL *client_ssl_socks5;
};

void fini_ssl(struct ssl_param *param);

struct username_password_authentication_request_tmp
{
	char ver;
	char ulen;
	char uname;
	// variable
};

struct send_recv_data_aes {
	unsigned char encrypt_data_length[16];
	unsigned char encrypt_data[BUFFER_SIZE*2];
};
