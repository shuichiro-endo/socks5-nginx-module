/*
 * Title:  socks5 client header (nginx module)
 * Author: Shuichiro Endo
 */

#define BUFFER_SIZE 8192

int encrypt_aes(unsigned char *plaintext, int plaintext_length, unsigned char *aes_key, unsigned char *aes_iv, unsigned char *ciphertext);
int decrypt_aes(unsigned char *ciphertext, int ciphertext_length, unsigned char *aes_key, unsigned char *aes_iv, unsigned char *plaintext);
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
