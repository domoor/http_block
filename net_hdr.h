#include <stdint.h>                 // uintN_t

#define IPPROTO_IPV4	4
//#define IPPROTO_TCP	6
#define IPPORT_HTTP	80

#define FIN		1
#define SYN		2
#define RST		4
#define PSH		8
#define ACK		16

struct ipv4_hdr
{
    uint8_t HL  : 4,                /* header length */
            Ver : 4;                /* version */
    uint8_t tos;                    /* type of service */
    uint16_t len;                   /* total length */
    uint16_t id;                    /* identification */
    uint16_t off;                   /* offset */
    uint8_t ttl;                    /* time to live */
    uint8_t protocol;               /* protocol */
    uint16_t chk;                   /* checksum */
    uint32_t src, dst;              /* source and dest address */

    ipv4_hdr() {
	Ver	 = 4;
	HL	 = 5;
	len	 = htons(40);
	ttl	 = 128;
	protocol = IPPROTO_TCP;
    }
};

struct tcp_hdr
{
    uint16_t s_port;                /* source port */
    uint16_t d_port;                /* destination port */
    uint32_t seq;                   /* sequence number */
    uint32_t ack;                   /* acknowledgement number */
    uint8_t reservation : 4,        /* (unused) */
            off : 4;                /* data offset */
    uint8_t  flag;                  /* control flags */
    uint16_t windows;               /* window */
    uint16_t chk;                   /* checksum */
    uint16_t urgent_P;              /* urgent pointer */

    tcp_hdr() {
	off	 = 5;
    }
};
