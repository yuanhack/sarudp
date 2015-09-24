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
#define CACHETIMEOUT 10         /* reliable request-result cached seconds */

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

    uint32_t seq;               /* sequence # */
    uint32_t ts;                /* timestamp when sent */
} suhdr_t;

#pragma pack(pop)

typedef struct sockaddr     SA;
typedef struct sockaddr_in  SA4;
typedef struct sockaddr_in6 SA6;
typedef union { SA4 addr4; SA6 addr6; } SAUN;

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
    uint32_t  seq;
} rb_key_cache_t;

/* *
 * Not only compare the address and port also offers rbtree node sorting
 * */
static inline int sockaddr_in6_cmp(
        struct sockaddr_in6 *p1, struct sockaddr_in6 *p2)
{
    struct in6_addr *in1 = &p1->sin6_addr; /* only address is not port */
    struct in6_addr *in2 = &p2->sin6_addr;

    if (p1->sin6_port == p2->sin6_port) {
#if defined __USE_MISC || defined __USE_GNU
        /* #define __in6_u.__u6_addr32 s6_addr32
         *      in the /usr/include/netinet/in.h */
        if (in1->s6_addr32[0] == in2->s6_addr32[0]) {
            if (in1->s6_addr32[1] == in2->s6_addr32[1]) {
                if (in1->s6_addr32[2] == in2->s6_addr32[2]) {
                    return (in1->s6_addr32[3] - in2->s6_addr32[3]);
                } return (in1->s6_addr32[2] - in2->s6_addr32[2]);
            } return (in1->s6_addr32[1] - in2->s6_addr32[1]);
        } return (in1->s6_addr32[0] - in2->s6_addr32[0]);
#else
        return memcmp(in1, in2, sizeof(struct in6_addr));
#endif
    } return p1->sin6_port - p2->sin6_port;
}

static inline int search_in4_addr_seq_cmp(
        rb_key_cache_t *r1, rb_key_cache_t *r2)
{
#ifndef promiscuous_mode
    return (r1->seq - r2->seq);
#else
    struct sockaddr_in *i1 = (SA4*)&r1->destaddr;		/* IPv4 address and port  */
    struct sockaddr_in *i2 = (SA4*)&r2->destaddr;		

    if (i1->sin_addr.s_addr == i2->sin_addr.s_addr) {
        if (i1->sin_port == i2->sin_port) {
            return (r1->seq - r2->seq);
        } return (i1->sin_port - i2->sin_port) ;
    } return (i1->sin_addr.s_addr - i2->sin_addr.s_addr);
#endif
}
static inline int search_cache_key_in6_addr_seq_cmp(
        rb_key_cache_t *r1, rb_key_cache_t *r2)
{
#ifndef promiscuous_mode
    return (r1->seq - r2->seq);
#else
    struct in6_addr *i1 = &((SA6*)&r1->destaddr)->sin6_addr; /* IPv6 only address */
    struct in6_addr *i2 = &((SA6*)&r2->destaddr)->sin6_addr; 
    int ret;

    if ((ret = sockaddr_in6_cmp((SA6*)&r1->destaddr, (SA6*)&r2->destaddr)))
        return (r1->seq - r2->seq);
    return (ret);
#endif
}

static inline const void* cache_getkey(const void *pnode)
{
    return rb_entry(pnode, cache_t, rbn);
}
static inline const int search_cache_cmp(
        const void * nodes_cache, const void* rb_search_key)
{
    rb_key_cache_t  *kk = (rb_key_cache_t*) rb_search_key;
    cache_t         *cache = (cache_t*) nodes_cache;

    rb_key_cache_t con;
    memcpy(&con.destaddr, &cache->frame.srcaddr, cache->frame.srclen);
    con.destlen = cache->frame.srclen;
    con.seq = cache->frame.recvhdr.seq;

    if (kk->destlen == sizeof(SA4)) {
        return search_in4_addr_seq_cmp(&con, kk);
    } else if ( kk->destlen == sizeof(SA6)) {
        return search_cache_key_in6_addr_seq_cmp(&con, kk);
    } else {
        ERR_QUIT("Protocol stack processing error");
    }
    abort();
}
inline static struct rb_node * rb_search(rb_root_t *root, const void *key)
{
    struct rb_node *node = root->rb_node;

    while (node) 
    {
        //int result = root->cmp(root->getkey(node), key);
        int result = search_cache_cmp(root->getkey(node), key);

        if (result < 0)
            node = node->rb_left;
        else if (result > 0)
            node = node->rb_right;
        else
            return node;
    }
    return 0;
}
static inline int insert_cache_in4_addr_seq_cmp(cache_t *r1, cache_t *r2)
{
#ifndef promiscuous_mode
    return (r1->frame.recvhdr.seq - r2->frame.recvhdr.seq);
#else
    struct sockaddr_in *i1 = (SA4*)&r1->frame.srcaddr;
    struct sockaddr_in *i2 = (SA4*)&r2->frame.srcaddr;

    if (i1->sin_addr.s_addr == i2->sin_addr.s_addr) {
        if (i1->sin_port == i2->sin_port) {
            return (r1->frame.recvhdr.seq - r2->frame.recvhdr.seq);
        } return (i1->sin_port - i2->sin_port) ;
    } return (i1->sin_addr.s_addr - i2->sin_addr.s_addr);
#endif
}
static inline int insert_cache_in6_addr_seq_cmp(cache_t *r1, cache_t *r2)
{
#ifndef promiscuous_mode
    return (r1->frame.recvhdr.seq - r2->frame.recvhdr.seq);
#else
    struct in6_addr *i1 = &((SA6*)&r1->frame.srcaddr)->sin6_addr;
    struct in6_addr *i2 = &((SA6*)&r2->frame.srcaddr)->sin6_addr;
    int ret;

    if ((ret = sockaddr_in6_cmp((SA6*)&r1->frame.srcaddr,(SA6*)&r2->frame.srcaddr)))
        return (r1->frame.recvhdr.seq - r2->frame.recvhdr.seq);
    return (ret);

#endif
}

static inline const int insert_cache_cmp(const void * node1, const void* node2)
{
    cache_t  *k1 = (cache_t*) node1;
    cache_t  *k2 = (cache_t*) node2;

    if (k2->frame.srclen == sizeof(SA4)) {
        return insert_cache_in4_addr_seq_cmp(k1, k2);
    } else if ( k2->frame.srclen == sizeof(SA6)) {
        return insert_cache_in6_addr_seq_cmp(k1, k2);
    }
    abort();
}
inline static int rb_insert(struct rb_root *root, struct rb_node *new_node)
{
    struct rb_node **now = &(root->rb_node); 
    struct rb_node  *parent = 0;

    /* Figure out where to put now node */
    while (*now) 
    {
        int result = insert_cache_cmp(root->getkey(*now), root->getkey(new_node));

        parent = *now;

        if (result < 0)
            now = &((*now)->rb_left);
        else if (result > 0)
            now = &((*now)->rb_right);
        else
            return -1; /* the key is already exists */
    }

    /* Add new node and rebalance tree. */
    rb_link_node(new_node, parent, now);
    rb_insert_color(new_node, root);

    return 0;
}

#endif /* __YH_SARUDP_COMM_H__ */
