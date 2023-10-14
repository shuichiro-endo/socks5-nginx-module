# socks5 nginx module

socks5 proxy(nginx module) and client with socks5 over tls

This module hides socks5 proxy in an http server.

This supports CONNECT of the socks5 command only. (BIND and UDP ASSOCIATE are not available.)

This is the Nginx module.
Click [here](https://github.com/shuichiro-endo/socks5-apache-module) for the Apache module.

## How it works
```mermaid
sequenceDiagram
    participant A as socks5 client
    participant B as my client
    participant C as nginx server (my socks5 module)
    participant D as destination server
    loop 
        A->>+B: socks5 selection request (Socks5)
        B->>+C: HTTP GET Request (HTTP or HTTPS)
        C->>C: check HTTP Request Header Key and Value (e.g. socks5: socks5)
        note right of C: if the key and value do not match, do nothing
        note right of C: if value of tls key is on, send socks5 data with tls (Socks5 over TLS)
        note right of C: if value of tls key is off or there is no value, send socks5 data with aes (Socks5 over AES)
        C-->>B: OK (encrypt with AES)
        alt socks5 over tls flag is on
        B->>+C: SSL connect
        C-->>-B: 
        end
        B->>+C: socks5 selection request (Socks5 over AES or Socks5 over TLS)
        C-->>-B: socks5 selection response (Socks5 over AES or Socks5 over TLS)
        B-->>-A: socks5 selection response (Socks5)
        alt socks5 server authentication method is username/password authentication
        A->>+B: socks5 username/password authentication request (Socks5)
        B->>+C: socks5 username/password authentication request (Socks5 over AES or Socks5 over TLS)
        C->>C: check username and password
        C-->>-B: socks5 username/password authentication response (Socks5 over AES or Socks5 over TLS)
        B-->>-A: socks5 username/password authentication response (Socks5)
        end
        A->>+B: socks5 socks request (Socks5)
        B->>+C: socks5 socks request (Socks5 over AES or Socks5 over TLS)
        C->>+D: check connection
        D-->>-C:  
        C-->>-B: socks5 socks response (Socks5 over AES or Socks5 over TLS)
        B-->>-A: socks5 socks response (Socks5)
        loop until communication ends
            A->>+B: request
            B->>+C: request (encrypt with AES or TLS)
            C->>+D: request
            D-->>-C: response
            C-->>-B: response (encrypt with AES or TLS)
            B-->>-A: response
        end
        C-->>-B: HTTP GET Response (HTTP or HTTPS)
    end
```

## Installation
### Install dependencies
- server
    - nginx
    - openssl and libssl-dev
    ```
    sudo apt install nginx libpcre3 libpcre3-dev zlib1g zlib1g-dev openssl libssl-dev
    ```

- client
    - openssl and libssl-dev
    - krb5-user, libkrb5-3 and libkrb5-dev
    ```
    sudo apt install openssl libssl-dev krb5-user libkrb5-3 libkrb5-dev
    ```

### Version
I tested this module using the following version.
- Debian 12
- nginx 1.24.0
- openssl 3.0.10

### Install
#### 1. download the latest [socks5 nginx module](https://github.com/shuichiro-endo/socks5-nginx-module)
```
git clone https://github.com/shuichiro-endo/socks5-nginx-module.git
```

#### 2. build and install
- server
    1. get nginx version
    ```
    /usr/sbin/nginx -v
    ```
    2. download the nginx open source release
    ```
    cd socks5-nginx-module
    wget https://nginx.org/download/nginx-x.xx.x.tar.gz
    tar -xzvf nginx-x.xx.x.tar.gz
    ```
    3. build my module(dynamic module)
    ```
    cd nginx-x.xx.x
    ./configure --with-compat --add-dynamic-module=../server --with-ld-opt="-lssl -lcrypto"
    make modules
    ```
    4. copy the module library(.so file) to nginx modules directory
    ```
    sudo cp objs/ngx_http_socks5_module.so /usr/share/nginx/modules/
    ```
    5. load the module library
    ```
    sudo sh -c 'echo "load_module modules/ngx_http_socks5_module.so;" > /etc/nginx/modules-available/ngx_http_socks5_module.conf'
    sudo ln -s /etc/nginx/modules-available/ngx_http_socks5_module.conf /etc/nginx/modules-enabled/ngx_http_socks5_module.conf
    sudo systemctl restart nginx
    ```

- client
    1. build
    ```
    cd socks5-nginx-module/client
    make
    ```

## Usage
- server
    1. run nginx server
    ```
    sudo systemctl start nginx
    ```
    2. connect to my server from my client

- client
    1. copy ssl/tls server certificate to my client directory (if the client connects to the nginx server with https)
    ```
    cp xxx.crt socks5-nginx-module/client/server_https.crt
    ```
    2. modify client.c file (if you change the certificate filename or directory path)
    ```
    char server_certificate_filename_https[256] = "server_https.crt";	// server certificate filename (HTTPS)
    char server_certificate_file_directory_path_https[256] = ".";	// server certificate file directory path (HTTPS)
    ```
    3. build (if you change the certificate filename or directory path)
    ```
    cd socks5-nginx-module/client
    make
    ```
    4. run my client (if the client uses socks5 over tls, you need to change the privatekey and certificate. see [How to change socks5 server privatekey and certificate (for Socks5 over TLS)](https://github.com/shuichiro-endo/socks5-nginx-module#how-to-change-socks5-server-privatekey-and-certificate-for-socks5-over-tls).)
    ```
    usage   : ./client -h listen_ip -p listen_port -H target_socks5server_domainname -P target_socks5server_port
              [-s (target socks5 server https connection)] [-t (Socks5 over TLS)]
              [-A recv/send tv_sec(timeout 0-60 sec)] [-B recv/send tv_usec(timeout 0-1000000 microsec)] [-C forwarder tv_sec(timeout 0-300 sec)] [-D forwarder tv_usec(timeout 0-1000000 microsec)]
              [-a forward proxy domainname] [-b forward proxy port] [-c forward proxy(1:http)]
              [-d forward proxy authentication(1:basic 2:digest 3:ntlmv2 4:spnego(kerberos))]
              [-e forward proxy username] [-f forward proxy password] [-g forward proxy user domainname] [-i forward proxy workstationname] [-j forward proxy service principal name]
    example : ./client -h 0.0.0.0 -p 9050 -H 192.168.0.10 -P 80
            : ./client -h 0.0.0.0 -p 9050 -H foobar.test -P 80 -t
            : ./client -h 0.0.0.0 -p 9050 -H foobar.test -P 80 -t -A 3 -B 0 -C 3 -D 0
            : ./client -h 0.0.0.0 -p 9050 -H foobar.test -P 80 -t -a 127.0.0.1 -b 3128 -c 1
            : ./client -h 0.0.0.0 -p 9050 -H 192.168.0.10 -P 443 -s
            : ./client -h 0.0.0.0 -p 9050 -H foobar.test -P 443 -s -t
            : ./client -h 0.0.0.0 -p 9050 -H foobar.test -P 443 -s -t -A 3 -B 0 -C 3 -D 0
            : ./client -h 0.0.0.0 -p 9050 -H foobar.test -P 443 -s -t -a 127.0.0.1 -b 3128 -c 1 -d 1 -e forward_proxy_user -f forward_proxy_password
            : ./client -h 0.0.0.0 -p 9050 -H foobar.test -P 443 -s -t -a 127.0.0.1 -b 3128 -c 1 -d 2 -e forward_proxy_user -f forward_proxy_password
            : ./client -h 0.0.0.0 -p 9050 -H foobar.test -P 443 -s -t -a 127.0.0.1 -b 3128 -c 1 -d 3 -e forward_proxy_user -f forward_proxy_password -g forward_proxy_user_domainname -i forward_proxy_workstationname
            : ./client -h 0.0.0.0 -p 9050 -H foobar.test -P 443 -s -t -a 127.0.0.1 -b 3128 -c 1 -d 3 -e test01 -f p@ssw0rd -g test.local -i WORKSTATION -A 10
            : ./client -h 0.0.0.0 -p 9050 -H foobar.test -P 443 -s -t -a 127.0.0.1 -b 3128 -c 1 -d 4 -j forward_proxy_service_principal_name
            : ./client -h 0.0.0.0 -p 9050 -H foobar.test -P 443 -s -t -a 127.0.0.1 -b 3128 -c 1 -d 4 -j HTTP/proxy.test.local@TEST.LOCAL -A 10
    ```
    5. connect to my client from other clients(browser, proxychains, etc.)
    ```
    proxychains4 curl -v https://www.google.com
    curl -v -x socks5h://127.0.0.1:9050 https://www.google.com
    ```

## Troubleshooting
### How to reduce number of connections in CLOSE_WAIT state
You can check number of connections in CLOSE_WAIT state by running the following command.
```
sudo ss -p --tcp state CLOSE-WAIT
```
If there are many connections in CLOSE_WAIT state, you can do the following.
- change the value of tcp_keepalive_time, tcp_keepalive_probes and tcp_keepalive_intvl (temporary)
    1. check the value before the changes
    ```
    cat /proc/sys/net/ipv4/tcp_keepalive_time
    cat /proc/sys/net/ipv4/tcp_keepalive_probes
    cat /proc/sys/net/ipv4/tcp_keepalive_intvl
    ```
    2. change the value
    ```
    sudo sh -c "echo 10 > /proc/sys/net/ipv4/tcp_keepalive_time"
    sudo sh -c "echo 2 > /proc/sys/net/ipv4/tcp_keepalive_probes"
    sudo sh -c "echo 3 > /proc/sys/net/ipv4/tcp_keepalive_intvl"
    ```
    3. check the value after the changes
    ```
    cat /proc/sys/net/ipv4/tcp_keepalive_time
    cat /proc/sys/net/ipv4/tcp_keepalive_probes
    cat /proc/sys/net/ipv4/tcp_keepalive_intvl
    ```
    4. restart client and server

- change the value of tcp_keepalive_time, tcp_keepalive_probes and tcp_keepalive_intvl (permanent)
    1. modify /etc/sysctl.conf file
    ```
    net.ipv4.tcp_keepalive_time = 10
    net.ipv4.tcp_keepalive_intvl = 3
    net.ipv4.tcp_keepalive_probes = 2
    ```
    2. check the value
    ```
    sudo sysctl -p
    ```
    3. reboot
    4. start client and server

- restart client and server

## Notes
### How to change HTTP Request Header Key and Value
- server
    1. modify ngx_http_socks5_module.c file
    ```
    #define HTTP_REQUEST_HEADER_SOCKS5_KEY "socks5"
    #define HTTP_REQUEST_HEADER_SOCKS5_VALUE "socks5"
    #define HTTP_REQUEST_HEADER_AESKEY_KEY "aeskey"
    #define HTTP_REQUEST_HEADER_AESIV_KEY "aesiv"
    #define HTTP_REQUEST_HEADER_TLS_KEY "tls"
    #define HTTP_REQUEST_HEADER_TLS_VALUE1 "off"	// Socks5 over AES
    #define HTTP_REQUEST_HEADER_TLS_VALUE2 "on"	// Socks5 over TLS
    #define HTTP_REQUEST_HEADER_TVSEC_KEY "sec"        // recv/send tv_sec
    #define HTTP_REQUEST_HEADER_TVUSEC_KEY "usec"      // recv/send tv_usec
    #define HTTP_REQUEST_HEADER_FORWARDER_TVSEC_KEY "forwardersec"          // forwarder tv_sec
    #define HTTP_REQUEST_HEADER_FORWARDER_TVUSEC_KEY "forwarderusec"        // forwarder tv_usec
    ```
    2. build my module (dynamic module)
    ```
    cd socks5-nginx-module/nginx-x.xx.x
    ./configure --with-compat --add-dynamic-module=../server --with-ld-opt="-lssl -lcrypto"
    make modules
    ```
    3. copy the module library(.so file) to nginx modules directory
    ```
    sudo cp objs/ngx_http_socks5_module.so /usr/share/nginx/modules/
    ```
    4. restart nginx
    ```
    sudo systemctl restart nginx
    ```

- client
    1. modify client.c file
    ```
    #define HTTP_REQUEST_HEADER_SOCKS5_KEY "socks5"
    #define HTTP_REQUEST_HEADER_SOCKS5_VALUE "socks5"
    #define HTTP_REQUEST_HEADER_AESKEY_KEY "aeskey"
    #define HTTP_REQUEST_HEADER_AESIV_KEY "aesiv"
    #define HTTP_REQUEST_HEADER_TLS_KEY "tls"
    #define HTTP_REQUEST_HEADER_TLS_VALUE1 "off"	// Socks5 over AES
    #define HTTP_REQUEST_HEADER_TLS_VALUE2 "on"	// Socks5 over TLS
    #define HTTP_REQUEST_HEADER_TVSEC_KEY "sec"        // recv/send tv_sec
    #define HTTP_REQUEST_HEADER_TVUSEC_KEY "usec"      // recv/send tv_usec
    #define HTTP_REQUEST_HEADER_FORWARDER_TVSEC_KEY "forwardersec"          // forwarder tv_sec
    #define HTTP_REQUEST_HEADER_FORWARDER_TVUSEC_KEY "forwarderusec"        // forwarder tv_usec
    
    ...
    
    if(socks5_over_tls_flag == 0){	// Socks5 over AES
        http_request_length = snprintf(http_request, BUFFER_SIZE+1, "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\n%s: %s\r\n%s: %s\r\n%s: %s\r\n%s: %ld\r\n%s: %ld\r\n%s: %ld\r\n%s: %ld\r\nConnection: close\r\n\r\n", target_domainname, HTTP_REQUEST_HEADER_SOCKS5_KEY, HTTP_REQUEST_HEADER_SOCKS5_VALUE, HTTP_REQUEST_HEADER_AESKEY_KEY, aes_key_b64, HTTP_REQUEST_HEADER_AESIV_KEY, aes_iv_b64, HTTP_REQUEST_HEADER_TVSEC_KEY, tv_sec, HTTP_REQUEST_HEADER_TVUSEC_KEY, tv_usec, HTTP_REQUEST_HEADER_FORWARDER_TVSEC_KEY, forwarder_tv_sec, HTTP_REQUEST_HEADER_FORWARDER_TVUSEC_KEY, forwarder_tv_usec);
    }else{	// Socks5 over TLS
        http_request_length = snprintf(http_request, BUFFER_SIZE+1, "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\n%s: %s\r\n%s: %s\r\n%s: %s\r\n%s: %s\r\n%s: %ld\r\n%s: %ld\r\n%s: %ld\r\n%s: %ld\r\nConnection: close\r\n\r\n", target_domainname, HTTP_REQUEST_HEADER_SOCKS5_KEY, HTTP_REQUEST_HEADER_SOCKS5_VALUE, HTTP_REQUEST_HEADER_AESKEY_KEY, aes_key_b64, HTTP_REQUEST_HEADER_AESIV_KEY, aes_iv_b64, HTTP_REQUEST_HEADER_TLS_KEY, HTTP_REQUEST_HEADER_TLS_VALUE2, HTTP_REQUEST_HEADER_TVSEC_KEY, tv_sec, HTTP_REQUEST_HEADER_TVUSEC_KEY, tv_usec, HTTP_REQUEST_HEADER_FORWARDER_TVSEC_KEY, forwarder_tv_sec, HTTP_REQUEST_HEADER_FORWARDER_TVUSEC_KEY, forwarder_tv_usec);
    }
    ```
    2. build
    ```
    cd socks5-nginx-module/client
    make
    ```

### How to change socks5 server Authentication Method
- server
    1. modify ngx_http_socks5_module.c file
    ```
    static char authentication_method = 0x0;	// 0x0:No Authentication Required	0x2:Username/Password Authentication
    static char username[256] = "socks5user";
    static char password[256] = "supersecretpassword";
    ```
    2. build my module(dynamic module)
    ```
    cd socks5-nginx-module/nginx-x.xx.x
    ./configure --with-compat --add-dynamic-module=../server --with-ld-opt="-lssl -lcrypto"
    make modules
    ```
    2. copy the module library(.so file) to nginx modules directory
    ```
    sudo cp objs/ngx_http_socks5_module.so /usr/share/nginx/modules/
    ```
    3. restart nginx
    ```
    sudo systemctl restart nginx
    ```

### How to change socks5 server privatekey and certificate (for Socks5 over TLS)
- server
    1. generate server privatekey, publickey and certificate
    ```
    openssl ecparam -genkey -name prime256v1 -out server-key-pair.pem
    
    openssl ec -in server-key-pair.pem -outform PEM -out server-private.pem
    
    openssl ec -in server-key-pair.pem -outform PEM -pubout -out server-public.pem
    
    openssl req -new -sha256 -key server-key-pair.pem -out server.csr
    openssl x509 -days 3650 -req -signkey server-private.pem < server.csr > server.crt
    openssl x509 -text -noout -in server.crt
    ```
    2. copy the server privatekey and certificate
    ```
    cat server-private.pem | sed -e 's/^/"/g' -e 's/$/\\n"\\/g' -e 's/"-----END EC PRIVATE KEY-----\\n"\\/"-----END EC PRIVATE KEY-----\\n";/g'
    cat server.crt | sed -e 's/^/"/g' -e 's/$/\\n"\\/g' -e 's/"-----END CERTIFICATE-----\\n"\\/"-----END CERTIFICATE-----\\n";/g'
    ```
    3. paste the privatekey and certificate into serverkey.h file
    ```
    char server_privatekey_socks5[] = "-----BEGIN EC PRIVATE KEY-----\n"\
    "MHcCAQEEIPAB7VXkdlfWvOL1YKr+cxGLhx69g/eqUjncU1D9hkUdoAoGCCqGSM49\n"\
    "AwEHoUQDQgAErAWMtToIcsL5fGF+DKZhMRy9m1WR3ViC7nrLokou9A/TMPr2DMz9\n"\
    "O7kldBsGkxFXSbXcUfjk6wyrgarKndpK0A==\n"\
    "-----END EC PRIVATE KEY-----\n";
    
    char server_certificate_socks5[] = "-----BEGIN CERTIFICATE-----\n"\
    "MIIBhTCCASsCFB47Pqx2Ko4ZXD5bCsGaaTP1Zjh8MAoGCCqGSM49BAMCMEUxCzAJ\n"\
    "BgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5l\n"\
    "dCBXaWRnaXRzIFB0eSBMdGQwHhcNMjMwMTE1MTIwODA3WhcNMzMwMTEyMTIwODA3\n"\
    "WjBFMQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwY\n"\
    "SW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcD\n"\
    "QgAErAWMtToIcsL5fGF+DKZhMRy9m1WR3ViC7nrLokou9A/TMPr2DMz9O7kldBsG\n"\
    "kxFXSbXcUfjk6wyrgarKndpK0DAKBggqhkjOPQQDAgNIADBFAiEAqknImSukXNY+\n"\
    "fkuuFbDFkte9mZM3Xy/ArE7kDIMt4nwCIHdlJRn0Cf18VQbpLessgklsk/gX59uo\n"\
    "jrsksbPHQ50h\n"\
    "-----END CERTIFICATE-----\n";
    ```
    4. build my module(dynamic module)
    ```
    cd socks5-nginx-module/nginx-x.xx.x
    ./configure --with-compat --add-dynamic-module=../server --with-ld-opt="-lssl -lcrypto"
    make modules
    ```
    5. copy the module library(.so file) to nginx modules directory
    ```
    sudo cp objs/ngx_http_socks5_module.so /usr/share/nginx/modules/
    ```
    6. restart nginx
    ```
    sudo systemctl restart nginx
    ```

- client
    1. copy server.crt file to my client directory
    ```
    cp server.crt socks5-nginx-module/client/server_socks5.crt
    ```
    2. modify client.c file (if you change the certificate filename or directory path)
    ```
    char server_certificate_filename_socks5[256] = "server_socks5.crt";	// server certificate filename (Socks5 over TLS)
    char server_certificate_file_directory_path_socks5[256] = ".";	// server certificate file directory path (Socks5 over TLS)
    ```
    3. build (if you change the certificate filename or directory path)
    ```
    cd socks5-nginx-module/client
    make
    ```

### How to change socks5 server cipher suite TLS1.2, TLS1.3 (for Socks5 over TLS)
- server
    1. select cipher suite(TLS1.2) and check
    ```
    openssl ciphers -v "AESGCM+ECDSA:CHACHA20+ECDSA:+AES256"
    ```
    2. select cipher suite(TLS1.3) [https://www.openssl.org/docs/man3.0/man3/SSL_CTX_set_ciphersuites.html](https://www.openssl.org/docs/man3.0/man3/SSL_CTX_set_ciphersuites.html)
    ```
    TLS_AES_128_GCM_SHA256
    TLS_AES_256_GCM_SHA384
    TLS_CHACHA20_POLY1305_SHA256
    TLS_AES_128_CCM_SHA256
    TLS_AES_128_CCM_8_SHA256
    ```
    3. modify ngx_http_socks5_module.c file
    ```
    char cipher_suite_tls_1_2[1000] = "AESGCM+ECDSA:CHACHA20+ECDSA:+AES256";	// TLS1.2
    char cipher_suite_tls_1_3[1000] = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256";	// TLS1.3
    ```
    4. build my module(dynamic module)
    ```
    cd socks5-nginx-module/nginx-x.xx.x
    ./configure --with-compat --add-dynamic-module=../server --with-ld-opt="-lssl -lcrypto"
    make modules
    ```
    5. copy the module library(.so file) to nginx modules directory
    ```
    sudo cp objs/ngx_http_socks5_module.so /usr/share/nginx/modules/
    ```
    6. restart nginx
    ```
    sudo systemctl restart nginx
    ```

## License
This project is licensed under the MIT License.

See the [LICENSE](https://github.com/shuichiro-endo/socks5-nginx-module/blob/main/LICENSE) file for details.

