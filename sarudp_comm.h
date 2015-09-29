#ifndef __YH_SARUDP_COMM_H__
#define __YH_SARUDP_COMM_H__

/* common use */

#include "unprtt.h"
#include "wrapfunc.h"
#include "list.h"

#include "yherror.h"
#include "yhevent.h"
#include "yhrbtree.h"

#include <pthread.h>
#include <sys/socket.h>
#include <setjmp.h>
#include <unistd.h>
#include <fcntl.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>

#define REALDATAMAX  1024       /* datagram max size */
#define CACHETIMEOUT 40         /* reliable request-result cached seconds */

#define ColorRed    "\e[31m"
#define ColorGre    "\e[32m"
#define ColorYel    "\e[33m"
#define ColorBlue   "\e[34m"
#define ColorEnd    "\e[m"

#pragma pack(push)
#pragma pack(1)

/* protocol header */
typedef struct hdr {
    /* packet action  */
#define     SU_SYN      0xff    /* request */
#define     SU_ACK      0xfe    /* respnose */
    uint8_t act;                /* protocol action */
    
    /* packet type */
#define     SU_ORDINARY 0       /* ordinary, foreign host Don't need to reply */
#define     SU_RELIABLE 1       /* reliable, foreign host Must reply */
    uint8_t type;               /* protocol type */

    uint16_t sid;               /* service id */
    uint32_t seq;               /* sequence # */
    uint32_t ts;                /* timestamp when sent */
} suhdr_t;

#pragma pack(pop)

typedef struct sockaddr     SA;
typedef struct sockaddr_in  SA4;
typedef struct sockaddr_in6 SA6;

typedef union {
    SA  addr;
#define sfamily addr.sa_family
    SA4 addr4;
#define s4addr  addr4.sin_addr
#define s4port  addr4.sin_port
    SA6 addr6;
#define s6addr  addr6.sin6_addr
#define s6port  addr6.sin6_port
} SAUN;

/* recv storage data, list node */
typedef struct frames {
    struct list node;
    SAUN        srcaddr;
    socklen_t   srclen;
    suhdr_t     recvhdr;
    int         len;
    uint8_t     data[];
} frames_t;

typedef struct cache {
    time_t    ts;
    struct rb_node rbn;
    frames_t  frame;
} cache_t;

typedef struct rb_key_cache {
    SAUN destaddr;
    socklen_t destlen;
    uint16_t  sid;
    uint32_t  seq;
} rb_key_cache_t;

static uint8_t ipv4lead[12] =  {
    0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0xff,0xff};

inline int sockaddr_in6_cmp( struct sockaddr_in6 *p1, struct sockaddr_in6 *p2);
inline int sockaddr_in4_cmp( struct sockaddr_in *p1,  struct sockaddr_in *p2);
inline const void* cache_getkey(const void *pnode);

inline int search_cache_key_in6_addr_seq_cmp( rb_key_cache_t *r1, rb_key_cache_t *r2);
inline int insert_cache_in6_addr_seq_cmp(cache_t *r1, cache_t *r2);

inline const int search_cache_cmp( const void * nodes_cache, const void* rb_search_key);
inline const int insert_cache_cmp(const void * node1, const void* node2);

inline struct   rb_node * rb_search(rb_root_t *root, const void *key);
inline int      rb_insert(struct rb_root *root, struct rb_node *new_node);

void su_get_ip_port(SAUN *s, char *ipbuff, int len, int *port);
void su_get_ip(SAUN *s, char *ipbuff, int len);
void su_get_port(SAUN *s, int *port);

void su_get_ip_port_f(SAUN *s, char *ipbuff, int len, int *port);
void su_get_ip_f(SAUN *s, char *ipbuff, int len);

void showaddr6_8_16(SA6 *ps);
void showaddr6_16_8(SA6 *ps);
void showaddr6_32_4(SA6 *ps);


#endif /* __YH_SARUDP_COMM_H__ */
