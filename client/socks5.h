/*
 * Title:  socks5 header
 * Author: Shuichiro Endo
 */

/*
 * Reference: 
 * https://www.ietf.org/rfc/rfc1928.txt
 * https://www.ietf.org/rfc/rfc1929.txt
 */

#ifndef SOCKS5_H
#define SOCKS5_H

#define DATASIZE 2000


/*
   The client connects to the server, and sends a version identifier/method selection message:

                   +-----+-------------+-------------+
              |VER | NMETHODS | METHODS  |
                   +----+--------------+-------------+
              | 1  |    1     | 1 to 255 |
                   +-----+-------------+-------------+
*/
typedef struct
{
	char ver;
	char nmethods;
	char methods[255];
} SELECTION_REQUEST, *pSELECTION_REQUEST;



/*
   The server selects from one of the methods given in METHODS, and sends a METHOD selection message:

                         +-----+----------+
                   |VER | METHOD |
                         +-----+----------+
                         | 1   |   1      |
                         +-----+----------+

   If the selected METHOD is X'FF', none of the methods listed by the
   client are acceptable, and the client MUST close the connection.

   The values currently defined for METHOD are:

          o  X'00' NO AUTHENTICATION REQUIRED
          o  X'01' GSSAPI
          o  X'02' USERNAME/PASSWORD
          o  X'03' to X'7F' IANA ASSIGNED
          o  X'80' to X'FE' RESERVED FOR PRIVATE METHODS
          o  X'FF' NO ACCEPTABLE METHODS

*/
typedef struct
{
	char ver;
	char method;
} SELECTION_RESPONSE, *pSELECTION_RESPONSE;



/*
   Once the SOCKS V5 server has started, and the client has selected the
   Username/Password Authentication protocol, the Username/Password
   subnegotiation begins.  This begins with the client producing a
   Username/Password request:

           +-----+--------+-------------+--------+-------------+
        |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
           +-----+--------+-------------+--------+-------------+
        | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
           +-----+--------+-------------+--------+-------------+


   The VER field contains the current version of the subnegotiation,
   which is X'01'. The ULEN field contains the length of the UNAME field
   that follows. The UNAME field contains the username as known to the
   source operating system. The PLEN field contains the length of the
   PASSWD field that follows. The PASSWD field contains the password
   association with the given UNAME.
*/
typedef struct
{
	char ver;
	char ulen;
	char uname[256];
	char plen;
	char passwd[256];
} USERNAME_PASSWORD_AUTHENTICATION_REQUEST, *pUSERNAME_PASSWORD_AUTHENTICATION_REQUEST;


/*
   The server verifies the supplied UNAME and PASSWD, and sends the
   following response:

                        +-----+----------+
                  |VER | STATUS |
                        +-----+----------+
                        | 1   |   1      |
                        +-----+----------+

   A STATUS field of X'00' indicates success. If the server returns a
   `failure' (STATUS value other than X'00') status, it MUST close the
   connection.
*/
typedef struct
{
	char ver;
	char status;
} USERNAME_PASSWORD_AUTHENTICATION_RESPONSE, *pUSERNAME_PASSWORD_AUTHENTICATION_RESPONSE;


/*
   The SOCKS request is formed as follows:

        +-----+-------+---------+--------+-------------+-------------+
      |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
        +-----+-------+---------+--------+-------------+-------------+
      | 1  |  1  | X'00' |  1   | Variable |    2     |
        +-----+-------+---------+--------+-------------+-------------+

     Where:

          o  VER    protocol version: X'05'
          o  CMD
             o  CONNECT X'01'
             o  BIND X'02'
             o  UDP ASSOCIATE X'03'
          o  RSV    RESERVED
          o  ATYP   address type of following address
             o  IP V4 address: X'01'
             o  DOMAINNAME: X'03'
             o  IP V6 address: X'04'
          o  DST.ADDR       desired destination address
          o  DST.PORT desired destination port in network octet
             order
*/
typedef struct
{
	char ver;
	char cmd;
	char rsv;
	char atyp;
	char dstAddr;
	// variable
} SOCKS_REQUEST, *pSOCKS_REQUEST;

typedef struct
{
	char ver;
	char cmd;
	char rsv;
	char atyp;
	char dstAddr[4];
	char dstPort[2];
} SOCKS_REQUEST_IPV4, *pSOCKS_REQUEST_IPV4;

typedef struct
{
	char ver;
	char cmd;
	char rsv;
	char atyp;
	char dstAddrLen;
	char dstAddr[256];	// the maximum length of FQDN is 255.
	char dstPort[2];
} SOCKS_REQUEST_DOMAINNAME, *pSOCKS_REQUEST_DOMAINNAME;

typedef struct
{
	char ver;
	char cmd;
	char rsv;
	char atyp;
	char dstAddr[16];
	char dstPort[2];
} SOCKS_REQUEST_IPV6, *pSOCKS_REQUEST_IPV6;



/*
   The SOCKS request information is sent by the client as soon as it has
   established a connection to the SOCKS server, and completed the
   authentication negotiations.  The server evaluates the request, and
   returns a reply formed as follows:

        +-----+-------+---------+--------+-------------+-------------+
      |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
        +-----+-------+---------+--------+-------------+-------------+
      | 1  |  1  | X'00' |  1   | Variable |    2     |
        +-----+-------+---------+--------+-------------+-------------+

     Where:

          o  VER    protocol version: X'05'
          o  REP    Reply field:
             o  X'00' succeeded
             o  X'01' general SOCKS server failure
             o  X'02' connection not allowed by ruleset
             o  X'03' Network unreachable
             o  X'04' Host unreachable
             o  X'05' Connection refused
             o  X'06' TTL expired
             o  X'07' Command not supported
             o  X'08' Address type not supported
             o  X'09' to X'FF' unassigned
          o  RSV    RESERVED
          o  ATYP   address type of following address
             o  IP V4 address: X'01'
             o  DOMAINNAME: X'03'
             o  IP V6 address: X'04'
          o  BND.ADDR       server bound address
          o  BND.PORT       server bound port in network octet order
*/
typedef struct
{
	char ver;
	char req;
	char rsv;
	char atyp;
	char bndAddr;
	// variable
} SOCKS_RESPONSE, *pSOCKS_RESPONSE;

typedef struct
{
	char ver;
	char req;
	char rsv;
	char atyp;
	char bndAddr[4];
	char bndPort[2];
} SOCKS_RESPONSE_IPV4, *pSOCKS_RESPONSE_IPV4;

typedef struct
{
	char ver;
	char req;
	char rsv;
	char atyp;
	char bndAddr[256];	// the maximum length of FQDN is 255.
	char bndPort[2];
} SOCKS_RESPONSE_DOMAINNAME, *pSOCKS_RESPONSE_DOMAINNAME;

typedef struct
{
	char ver;
	char req;
	char rsv;
	char atyp;
	char bndAddr[16];
	char bndPort[2];
} SOCKS_RESPONSE_IPV6, *pSOCKS_RESPONSE_IPV6;


/*
   A UDP-based client MUST send its datagrams to the UDP relay server at
   the UDP port indicated by BND.PORT in the reply to the UDP ASSOCIATE
   request.  If the selected authentication method provides
   encapsulation for the purposes of authenticity, integrity, and/or
   confidentiality, the datagram MUST be encapsulated using the
   appropriate encapsulation.  Each UDP datagram carries a UDP request
   header with it:

      +----+--------+--------+-------------+--------------+-------------+
    |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
      +----+--------+--------+-------------+--------------+-------------+
    | 2  |  1   |  1   | Variable |    2     | Variable |
      +----+--------+--------+-------------+--------------+-------------+

     The fields in the UDP request header are:

          o  RSV  Reserved X'0000'
          o  FRAG    Current fragment number
          o  ATYP    address type of following addresses:
             o  IP V4 address: X'01'
             o  DOMAINNAME: X'03'
             o  IP V6 address: X'04'
          o  DST.ADDR       desired destination address
          o  DST.PORT       desired destination port
          o  DATA     user data
*/
typedef struct
{
	char rsv[2];
	char flag;
	char atyp;
	char dstAddr;
	// variable
} SOCKS_UDP_ASSOCIATE_RESPONSE, *pSOCKS_UDP_ASSOCIATE_RESPONSE;

typedef struct
{
	char rsv[2];
	char flag;
	char atyp;
	char dstAddr[4];
	char dstPort[2];
	char data[DATASIZE];
} SOCKS_UDP_ASSOCIATE_RESPONSE_IPV4, *pSOCKS_UDP_ASSOCIATE_RESPONSE_IPV4;

typedef struct
{
	char rsv[2];
	char flag;
	char atyp;
	char dstAddr[256];	// the maximum length of FQDN is 255.
	char dstPort[2];
	char data[DATASIZE];
} SOCKS_UDP_ASSOCIATE_RESPONSE_DOMAINNAME, *pSOCKS_UDP_ASSOCIATE_RESPONSE_DOMAINNAME;

typedef struct
{
	char rsv[2];
	char flag;
	char atyp;
	char dstAddr[16];
	char dstPort[2];
	char data[DATASIZE];
} SOCKS_UDP_ASSOCIATE_RESPONSE_IPV6, *pSOCKS_UDP_ASSOCIATE_RESPONSE_IPV6;

#endif /* SOCKS5_H */






