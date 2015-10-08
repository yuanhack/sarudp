#include "sarudp_comm.h"

static uint8_t ipv4lead[12] =  {
    0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0xff,0xff};

/* *
 * Not only compare the address and port also offers rbtree node sorting
 * */
inline int sockaddr_in6_cmp(
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
inline int sockaddr_in4_cmp(
        struct sockaddr_in *p1, struct sockaddr_in *p2)
{
    if (p1->sin_port == p2->sin_port) {
        return p1->sin_addr.s_addr - p2->sin_addr.s_addr;
    } return p1->sin_port - p2->sin_port;
}

inline int search_cache_key_in6_addr_seq_cmp(
        rb_key_cache_t *r1, rb_key_cache_t *r2)
{
#ifndef promiscuous_mode
    if (r1->sid == r2->sid)
        return (r1->seq - r2->seq);
    return (r1->sid - r2->sid);
#else
    int ret = sockaddr_in6_cmp(&r1->destaddr.addr6, &r2->destaddr.addr6);

    if (r1->sid == r2->sid) {
        if (0 == ret) {
            return (r1->seq - r2->seq);
        } return (ret);
    } return (r1->sid - r2->sid);
#endif
}

inline const void* cache_getkey(const void *pnode)
{
    return rb_entry(pnode, cache_t, rbn);
}
inline const int search_cache_cmp(
        const void * nodes_cache, const void* rb_search_key)
{
    rb_key_cache_t  *kk = (rb_key_cache_t*) rb_search_key;
    cache_t         *cache = (cache_t*) nodes_cache;

    rb_key_cache_t con;
    memcpy(&con.destaddr, &cache->frame.srcaddr, sizeof(SAUN));
    con.destlen = cache->frame.srclen;
    con.seq = cache->frame.recvhdr.seq;
    con.sid = cache->frame.recvhdr.sid;

    return search_cache_key_in6_addr_seq_cmp(&con, kk);
}
inline struct rb_node * rb_search(rb_root_t *root, const void *key)
{
    struct rb_node *node = root->rb_node;

    while (node) 
    {
        int result = search_cache_cmp(rb_entry(node, cache_t, rbn), key);

        if (result < 0)
            node = node->rb_left;
        else if (result > 0)
            node = node->rb_right;
        else
            return node;
    }
    return 0;
}
inline int insert_cache_in6_addr_seq_cmp(cache_t *r1, cache_t *r2)
{
#ifndef promiscuous_mode
    if (r1->frame.recvhdr.sid == r2->frame.recvhdr.sid)
        return (r1->frame.recvhdr.seq - r2->frame.recvhdr.seq);
    return (r1->frame.recvhdr.sid - r2->frame.recvhdr.sid);
#else
    int ret =
        sockaddr_in6_cmp(&r1->frame.srcaddr.addr6, &r2->frame.srcaddr.addr6);

    if (r1->frame.recvhdr.sid == r2->frame.recvhdr.sid) {
        if (0 == ret) {
            return (r1->frame.recvhdr.seq - r2->frame.recvhdr.seq);
        } return (ret);
    } return (r1->frame.recvhdr.sid - r2->frame.recvhdr.sid);

#endif
}

inline const int insert_cache_cmp(const void * node1, const void* node2)
{
    cache_t  *k1 = (cache_t*) node1;
    cache_t  *k2 = (cache_t*) node2;

    return insert_cache_in6_addr_seq_cmp(k1, k2);
}
inline int rb_insert(struct rb_root *root, struct rb_node *new_node)
{
    struct rb_node **now = &(root->rb_node); 
    struct rb_node  *parent = 0;

    /* Figure out where to put now node */
    while (*now) 
    {
        //int result = insert_cache_cmp(root->getkey(*now), root->getkey(new_node));
        int result = insert_cache_cmp(rb_entry(*now, cache_t, rbn),
                rb_entry(new_node, cache_t, rbn));

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

void su_get_ip_port(SAUN *s, char *ipbuff, int len, int *port)
{
    if (s->sfamily == PF_INET) {
        inet_ntop(PF_INET, &s->s4addr, ipbuff, len);
        if (port)
            *port = ntohs(s->s4port);
    } else if (s->sfamily == PF_INET6) {
        if (memcmp(s->addr6.sin6_addr.s6_addr, ipv4lead, 12) == 0)
            inet_ntop(PF_INET, &s->s6addr.s6_addr[12], ipbuff,len);
        else
            inet_ntop(PF_INET6,&s->s6addr.s6_addr, ipbuff, len);
        if (port)
            *port = ntohs(s->s6port);
    } else {
        snprintf(ipbuff, len, "su_get_ip_port unknown protocol");
    }
}
void su_get_ip_port_f(SAUN *s, char *ipbuff, int len, int *port)
{
    if (s->sfamily == PF_INET) {
        inet_ntop(PF_INET, &s->s4addr, ipbuff, len);
        if (port)
            *port = ntohs(s->s4port);
    } else if (s->sfamily == PF_INET6) {
        inet_ntop(PF_INET6,&s->s6addr.s6_addr, ipbuff, len);
        if (port)
            *port = ntohs(s->s6port);
    } else {
        snprintf(ipbuff, len, "su_get_ip_port_f unknown protocol");
    }
}
void su_get_ip(SAUN *s, char *ipbuff, int len)
{
    if (s->sfamily == PF_INET) {
        inet_ntop(PF_INET, &s->s4addr, ipbuff, len);
    } else if (s->sfamily == PF_INET6) {
        if (memcmp(s->addr6.sin6_addr.s6_addr, ipv4lead, 12) == 0)
            inet_ntop(PF_INET, &s->s6addr.s6_addr[12], ipbuff,len);
        else
            inet_ntop(PF_INET6,&s->s6addr.s6_addr, ipbuff, len);
    } else {
        snprintf(ipbuff, len, "su_get_ip unknown protocol");
    }
}
void su_get_ip_f(SAUN *s, char *ipbuff, int len)
{
    if (s->sfamily == PF_INET) {
        inet_ntop(PF_INET, &s->s4addr, ipbuff, len);
    } else if (s->sfamily == PF_INET6) {
        inet_ntop(PF_INET6,&s->s6addr.s6_addr, ipbuff, len);
    } else {
        snprintf(ipbuff, len, "su_get_ip_f unknown protocol");
    }
}
void su_get_port(SAUN *s, int *port)
{
    if (!port)
        return;
    if (s->sfamily == PF_INET) {
        *port = ntohs(s->s4port);
    } else if (s->sfamily == PF_INET6) {
        *port = ntohs(s->s6port);
    } else {
        *port = -1;
    }
}

void showaddr6_8_16(SA6 *ps)
{
    log_msg("%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
            ps->sin6_addr.s6_addr[0],  ps->sin6_addr.s6_addr[1],
            ps->sin6_addr.s6_addr[2],  ps->sin6_addr.s6_addr[3],
            ps->sin6_addr.s6_addr[4],  ps->sin6_addr.s6_addr[5],
            ps->sin6_addr.s6_addr[6],  ps->sin6_addr.s6_addr[7],
            ps->sin6_addr.s6_addr[8],  ps->sin6_addr.s6_addr[9],
            ps->sin6_addr.s6_addr[10], ps->sin6_addr.s6_addr[11],
            ps->sin6_addr.s6_addr[12], ps->sin6_addr.s6_addr[13],
            ps->sin6_addr.s6_addr[14], ps->sin6_addr.s6_addr[15]);
}
void showaddr6_16_8(SA6 *ps)
{
    log_msg("%04x %04x %04x %04x %04x %04x %04x %04x",
            ps->sin6_addr.s6_addr16[0],
            ps->sin6_addr.s6_addr16[1],
            ps->sin6_addr.s6_addr16[2],
            ps->sin6_addr.s6_addr16[3],
            ps->sin6_addr.s6_addr16[4],
            ps->sin6_addr.s6_addr16[5],
            ps->sin6_addr.s6_addr16[6],
            ps->sin6_addr.s6_addr16[7]);
}
void showaddr6_32_4(SA6 *ps)
{
    log_msg("%08x %08x %08x %08x",
            ps->sin6_addr.s6_addr32[0],
            ps->sin6_addr.s6_addr32[1],
            ps->sin6_addr.s6_addr32[2],
            ps->sin6_addr.s6_addr32[3]);
}

