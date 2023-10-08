/*
 * Title:  socks5 client header (nginx module)
 * Author: Shuichiro Endo
 */

#define BUFFER_SIZE 8192

int encrypt_aes(unsigned char *plaintext, int plaintext_length, unsigned char *aes_key, unsigned char *aes_iv, unsigned char *ciphertext);
int decrypt_aes(unsigned char *ciphertext, int ciphertext_length, unsigned char *aes_key, unsigned char *aes_iv, unsigned char *plaintext);
int encode_base64(const unsigned char *input, int length, unsigned char *output, int output_size);
int decode_base64(const unsigned char *input, int length, unsigned char *output, int output_size);
int get_md5_hash(const unsigned char *input, int input_length, unsigned char *output, int output_length);
int get_sha_256_hash(const unsigned char *input, int input_length, unsigned char *output, int output_length);
int get_sha_512_256_hash(const unsigned char *input, int input_length, unsigned char *output, int output_length);
void enable_blocking_socket(int sock);	// blocking
void disable_blocking_socket(int sock);	// non blocking
int recv_data(int sock, void *buffer, int length, long tv_sec, long tv_usec);
int recv_data_aes(int sock, void *buffer, int length, unsigned char *aes_key, unsigned char *aes_iv, long tv_sec, long tv_usec);
int recv_data_tls(int sock, SSL *ssl ,void *buffer, int length, long tv_sec, long tv_usec);
int send_data(int sock, void *buffer, int length, long tv_sec, long tv_usec);
int send_data_aes(int sock, void *buffer, int length, unsigned char *aes_key, unsigned char *aes_iv, long tv_sec, long tv_usec);
int send_data_tls(int sock, SSL *ssl, void *buffer, int length, long tv_sec, long tv_usec);
int forwarder(int client_sock, int target_sock, long tv_sec, long tv_usec);
int forwarder_aes(int client_sock, int target_sock, unsigned char *aes_key, unsigned char *aes_iv, long tv_sec, long tv_usec);
int forwarder_tls(int client_sock, int target_sock, SSL *target_ssl, long tv_sec, long tv_usec);
int ssl_connect_non_blocking(int sock, SSL *ssl, long tv_sec, long tv_usec);
void close_socket(int sock);
int worker(void *ptr);
void usage(char *filename);

struct worker_param {
	int client_sock;
	long tv_sec;		// recv send
	long tv_usec;		// recv send
	long forwarder_tv_sec;
	long forwarder_tv_usec;
};

struct ssl_param {
	SSL_CTX *target_ctx_http;
	SSL *target_ssl_http;
	SSL_CTX *target_ctx_socks5;
	SSL *target_ssl_socks5;
};

void finiSsl(struct ssl_param *param);

struct send_recv_data_aes {
	unsigned char encrypt_data_length[16];
	unsigned char encrypt_data[BUFFER_SIZE*2];
};

struct digest_parameters {
	char algorithm[10];			// MD5 or MD5-sess or SHA-256 or SHA-256-sess or SHA-512-256 or SHA-512-256-sess
	char username[256];			// forward proxy username
	char realm[100];
	char password[256];			// forward proxy password
	char a1[1000];				// username:realm:password or H(username:realm:password):nonce:cnonce
	char a1_hash[150];			// H(a1)
	char nonce[200];
	char nonce_prime[200];
	char nc[10];				// 00000001
	char cnonce[200];
	char cnonce_prime[200];
	char qop[10];				// auth or auth-int
	char entity_body[BUFFER_SIZE+1];
	char entity_body_hash[150];
	char stale[10];				// true or false
	char method[10];			// CONNECT
	char uri[500];
	char a2[1000];				// method:uri or method:uri:H(entity_body)
	char a2_hash[150];			// H(a2)
	char response[1000];		// H(A1):nonce:nc:cnonce:qop:H(A2)
	char response_hash[150];	// H(H(A1):nonce:nc:cnonce:qop:H(A2))
};

int get_http_header(const char *input, const char *key, char *output, int output_length);
int get_digest_values(const char *input, struct digest_parameters *param);
int get_digest_response(struct digest_parameters *param);

