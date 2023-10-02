/*
 * Title:  socks5 client header windows (nginx module)
 * Author: Shuichiro Endo
 */

#define BUFFER_SIZE 8192

int encrypt_aes(unsigned char *plaintext, int plaintext_length, unsigned char *aes_key, unsigned char *aes_iv, unsigned char *ciphertext);
int decrypt_aes(unsigned char *ciphertext, int ciphertext_length, unsigned char *aes_key, unsigned char *aes_iv, unsigned char *plaintext);
int encode_base64(const unsigned char *input, int length, unsigned char *output);
int decode_base64(const unsigned char *input, int length, unsigned char *output);
int recv_data(SOCKET sock, void *buffer, int length, long tv_sec, long tv_usec);
int recv_data_aes(SOCKET sock, void *buffer, int length, unsigned char *aes_key, unsigned char *aes_iv, long tv_sec, long tv_usec);
int recv_data_tls(SOCKET sock, SSL *ssl ,void *buffer, int length, long tv_sec, long tv_usec);
int send_data(SOCKET sock, void *buffer, int length, long tv_sec, long tv_usec);
int send_data_aes(SOCKET sock, void *buffer, int length, unsigned char *aes_key, unsigned char *aes_iv, long tv_sec, long tv_usec);
int send_data_tls(SOCKET sock, SSL *ssl, void *buffer, int length, long tv_sec, long tv_usec);
int forwarder(SOCKET client_sock, SOCKET target_sock, long tv_sec, long tv_usec);
int forwarder_aes(SOCKET client_sock, SOCKET target_sock, unsigned char *aes_key, unsigned char *aes_iv, long tv_sec, long tv_usec);
int forwarder_tls(SOCKET client_sock, SOCKET target_sock, SSL *target_ssl, long tv_sec, long tv_usec);
int ssl_connect_non_blocking(SOCKET sock, SSL *ssl, long tv_sec, long tv_usec);
void close_socket(SOCKET sock);
int worker(void *ptr);
void worker_thread(void *ptr);
void usage(char *filename);
int getopt(int argc, char **argv, char *optstring);

struct timezone {
    int tz_minuteswest;
    int tz_dsttime;
};

int gettimeofday(timeval *tv, timezone *tz);

struct worker_param {
	SOCKET client_sock;
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

void finiSsl(ssl_param *param);

struct send_recv_data_aes {
	unsigned char encrypt_data_length[16];
	unsigned char encrypt_data[BUFFER_SIZE*2];
};
