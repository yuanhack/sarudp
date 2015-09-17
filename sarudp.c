#include "sarudp.h"

#include "yherror.h"
#include "yhevent.h"
#include "yhservice.h"
#include "yhtime.h"
#include "yhrbtree.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <string.h>

pthread_mutex_t emutex = PTHREAD_MUTEX_INITIALIZER;
em_t * sugem = 0;
char rejectbuff[1024*10] = {0};


static inline int search_in4_addr_seq_cmp(rb_key_cache_t *r1, rb_key_cache_t *r2)
{
    struct sockaddr_in *i1 = (SA4*)&r1->destaddr;		/* Internet 4 address, port  */
    struct sockaddr_in *i2 = (SA4*)&r2->destaddr;		

#ifdef module_exact_match_address
    return (r1->seq - r2->seq);
#else
    if (i1->sin_addr.s_addr == i2->sin_addr.s_addr) {
        if (i1->sin_port == i2->sin_port) {
            return (r1->seq - r2->seq);
        } return (i1->sin_port - i1->sin_port) ;
    } return (i1->sin_addr.s_addr - i1->sin_addr.s_addr);
#endif
}
static inline int search_cache_key_in6_addr_seq_cmp_onebyone(rb_key_cache_t *r1, rb_key_cache_t *r2)
{
    struct in6_addr *i1 = &((SA6*)&r1->destaddr)->sin6_addr; /* Internet 6 only address */
    struct in6_addr *i2 = &((SA6*)&r2->destaddr)->sin6_addr; 

#ifndef module_exact_match_address
    if (i1->__in6_u.__u6_addr32[0] == i2->__in6_u.__u6_addr32[0]) {
        if (i1->__in6_u.__u6_addr32[1] == i2->__in6_u.__u6_addr32[1]) {
            if (i1->__in6_u.__u6_addr32[2] == i2->__in6_u.__u6_addr32[2]) {
                if (i1->__in6_u.__u6_addr32[3] == i2->__in6_u.__u6_addr32[3]) {
                    if (((SA6*)&r1->destaddr)->sin6_port == ((SA6*)&r2->destaddr)->sin6_port) {
#endif
                        return r1->seq - r2->seq;
#ifndef module_exact_match_address
                    } return (((SA6*)&r1->destaddr)->sin6_port - ((SA6*)&r2->destaddr)->sin6_port);
                } return (i1->__in6_u.__u6_addr32[3] - i2->__in6_u.__u6_addr32[3]);
            } return (i1->__in6_u.__u6_addr32[2] - i2->__in6_u.__u6_addr32[2]);
        } return (i1->__in6_u.__u6_addr32[1] - i2->__in6_u.__u6_addr32[1]);
    } return (i1->__in6_u.__u6_addr32[0] - i2->__in6_u.__u6_addr32[0]);
#endif
}
static inline int search_cache_key_in6_addr_seq_cmp(rb_key_cache_t *r1, rb_key_cache_t *r2)
{
    struct in6_addr *i1 = &((SA6*)&r1->destaddr)->sin6_addr; /* Internet 6 only address */
    struct in6_addr *i2 = &((SA6*)&r2->destaddr)->sin6_addr; 

    if (((SA6*)&r1->destaddr)->sin6_port == ((SA6*)&r2->destaddr)->sin6_port) {
        if (r1->seq == r2->seq) {
            return memcmp(i1, i2, sizeof(struct in6_addr));
        } return (r1->seq - r2->seq);
    } return (((SA6*)&r1->destaddr)->sin6_port - ((SA6*)&r2->destaddr)->sin6_port);
}

static inline const void* cache_getkey(const void *pnode)
{
    return rb_entry(pnode, cache_t, rbn);
}
static inline const int search_cache_cmp(const void * nodes_cache, const void* rb_search_key)
{
    rb_key_cache_t  *kk = (rb_key_cache_t*) rb_search_key;
    cache_t         *kc = (cache_t*) nodes_cache;

    rb_key_cache_t con;
    memcpy(&con.destaddr, &kc->pack.srcaddr, kc->pack.srclen);
    con.destlen = kc->pack.srclen;
    con.seq = kc->pack.recvhdr.seq;

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
    struct sockaddr_in *i1 = (SA4*)&r1->pack.srcaddr;		/* Internet 4 address, port  */
    struct sockaddr_in *i2 = (SA4*)&r2->pack.srcaddr;		

    if (i1->sin_addr.s_addr == i2->sin_addr.s_addr) {
        if (i1->sin_port == i2->sin_port) {
            return (r1->pack.recvhdr.seq - r2->pack.recvhdr.seq);
        } return (i1->sin_port - i1->sin_port) ;
    } return (i1->sin_addr.s_addr - i1->sin_addr.s_addr);
}
static inline int insert_cache_in6_addr_seq_cmp_onebyone(cache_t *r1, cache_t *r2)
{
    struct in6_addr *i1 = &((SA6*)&r1->pack.srcaddr)->sin6_addr; /* Internet 6 only address */
    struct in6_addr *i2 = &((SA6*)&r2->pack.srcaddr)->sin6_addr; 
#ifndef module_exact_match_address
    if (i1->__in6_u.__u6_addr32[0] == i2->__in6_u.__u6_addr32[0]) {
        if (i1->__in6_u.__u6_addr32[1] == i2->__in6_u.__u6_addr32[1]) {
            if (i1->__in6_u.__u6_addr32[2] == i2->__in6_u.__u6_addr32[2]) {
                if (i1->__in6_u.__u6_addr32[3] == i2->__in6_u.__u6_addr32[3]) {
                    if (((SA6*)&r1->pack.srcaddr)->sin6_port == ((SA6*)&r2->pack.srcaddr)->sin6_port) {
#endif
                        return r1->pack.recvhdr.seq - r2->pack.recvhdr.seq;
#ifndef module_exact_match_address
                    } return (((SA6*)&r1->pack.srcaddr)->sin6_port - ((SA6*)&r2->pack.srcaddr)->sin6_port);
                } return (i1->__in6_u.__u6_addr32[3] - i2->__in6_u.__u6_addr32[3]);
            } return (i1->__in6_u.__u6_addr32[2] - i2->__in6_u.__u6_addr32[2]);
        } return (i1->__in6_u.__u6_addr32[1] - i2->__in6_u.__u6_addr32[1]);
    } return (i1->__in6_u.__u6_addr32[0] - i2->__in6_u.__u6_addr32[0]);
#endif
}
static inline int insert_cache_in6_addr_seq_cmp(cache_t *r1, cache_t *r2)
{
    struct in6_addr *i1 = &((SA6*)&r1->pack.srcaddr)->sin6_addr; /* Internet 6 only address */
    struct in6_addr *i2 = &((SA6*)&r2->pack.srcaddr)->sin6_addr; 

#ifdef module_exact_match_address
    return (r1->pack.recvhdr.seq - r2->pack.recvhdr.seq);
#else
    if (((SA6*)&r1->pack.srcaddr)->sin6_port == ((SA6*)&r2->pack.srcaddr)->sin6_port) {
        if (r1->pack.recvhdr.seq == r2->pack.recvhdr.seq) {
            return memcmp(i1, i2, sizeof(struct in6_addr));
        } return (r1->pack.recvhdr.seq - r2->pack.recvhdr.seq);
    } return (((SA6*)&r1->pack.srcaddr)->sin6_port - ((SA6*)&r2->pack.srcaddr)->sin6_port);
#endif
}
static inline const int insert_cache_cmp(const void * node1, const void* node2)
{
    cache_t  *k1 = (cache_t*) node1;
    cache_t  *k2 = (cache_t*) node2;

    if (k2->pack.srclen == sizeof(SA4)) {
        return insert_cache_in4_addr_seq_cmp(k1, k2);
    } else if ( k2->pack.srclen == sizeof(SA6)) {
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
            return -1; // the key is already exists
    }

    /* Add new node and rebalance tree. */
    rb_link_node(new_node, parent, now);
    rb_insert_color(new_node, root);

    return 0;
}

static inline void reliable_ack___save (supeer_t *psar, const void *outbuff, size_t outbytes)
{
    cache_t * newack = calloc(1, sizeof(cache_t) + outbytes);
    if (newack == 0)
        return;
    time(&newack->ts);
    memcpy(&newack->pack, psar->synnowpack, sizeof(frames_t));
    memcpy(newack->pack.data, outbuff, outbytes);
    newack->pack.len = outbytes;

    /* Adding associated */
    list_append(&psar->lsackcache, &newack->pack.node);
    rb_insert(&psar->rbackcache, &newack->rbn);

#if defined SU_DEBUG_LIST || defined SU_DEBUG_RBTREE 
    LOG_MSG("peer %x add. cache_t ack node " ColorRed "%p" ColorEnd " time %u", 
            psar, newack, newack->ts);
#endif

    return;
}
static inline void reliable_ack_unsave (supeer_t *psar)
{
    time_t nowtime;

    cache_t *frees, *cache = container_of 
        ( list_head(&psar->lsackcache, frames_t, node), cache_t, pack );

    time(&nowtime);

    while ( &psar->lsackcache != &cache->pack.node ) {
        if ( abs(nowtime - cache->ts) < CACHETIMEOUT ) break;
        frees = cache;
        cache = container_of
            ( list_next(&cache->pack, frames_t, node), cache_t, pack );

        /* Disconnect associated */
        list_remove(&frees->pack.node);
        rb_erase(&frees->rbn, &psar->rbackcache);

#if defined SU_DEBUG_LIST || defined SU_DEBUG_RBTREE 
        LOG_MSG("peer %x free cache_t ack node " ColorRed "%p" ColorEnd " timeout[%u %u]",
                psar, frees, nowtime, frees->ts+CACHETIMEOUT);
#endif

        free(frees);
    }
}
static void su_peer_list_empty(supeer_t *psar, struct list *l)
{
    frames_t *realnode;
    struct list *node = l->next;
    while ( node != l ) {
        list_remove(node);
        realnode = container_of(node, frames_t, node);
        node = node->next;
        free(realnode);

#ifdef SU_DEBUG_LIST
        LOG_MSG("peer %x free frames_t node " ColorRed "%p" ColorEnd, 
                psar, realnode);
#endif

    }
}


void request_handle(supeer_t *psar)
{
    frames_t *pack = psar->synnowpack;
    suhdr_t *phdr = &pack->recvhdr;
    SA4 *psrc, *pdst;
    psrc = (SA4*)&pack->srcaddr;
    pdst = (SA4*)&psar->destaddr;

#ifdef module_exact_match_address
    /* TODO: important * Check filter address and port */
    if ( psrc->sin_addr.s_addr != pdst->sin_addr.s_addr ||
            psrc->sin_port != pdst->sin_port ) {
#ifdef SU_DEBUG_PEER_RECV
        log_msg(ColorYel"peer %x reject from %s:%d data len %d"ColorEnd, psar,
                inet_ntoa(psrc->sin_addr), ntohs(psrc->sin_port), pack->len);
#endif
        free(pack);
        return;
    }
#endif

    switch (phdr->type) {
        case SU_RELIABLE:
            if (psar->reliable_request_handle) {
                psar->reliable_request_handle(psar, (char*)pack->data, pack->len);
            } break;
        case SU_ORDINARY:
            if (psar->ordinary_request_handle) {
                psar->ordinary_request_handle(psar, (char*)pack->data, pack->len);
            } break;
        default:
#ifdef SU_DEBUG_PEER_RECV
            LOG_MSG("peer %x recv request type unknown %d", psar, phdr->type);
#endif
            free(pack);
            return;
    }
    free(pack);
}

static void *thread_request_handle(void *v)
{
    supeer_t *psar = (supeer_t*)v;
    struct list *synnode;
    frames_t *packet;
    suhdr_t *phdr;

    struct timeval now;
    int ret;
    struct timespec abstime = {0};

    for (;;) {
        pthread_mutex_lock(&psar->lock);
        while ((synnode = psar->synrecvls.next) == &psar->synrecvls) {
            maketimeout_seconds(&abstime, 1);
            ret = pthread_cond_timedwait(&psar->syncond, &psar->lock, &abstime);
            if ( ret == ETIMEDOUT ) {
                pthread_mutex_lock(&psar->cachelock);
                reliable_ack_unsave(psar);
                pthread_mutex_unlock(&psar->cachelock);
            }
        }
        list_remove(synnode);
        pthread_mutex_unlock(&psar->lock);

        // TODO: Have a request
        packet = container_of(synnode, frames_t, node);
        phdr = &packet->recvhdr;

        rb_key_cache_t key;
        memcpy(&key.destaddr, &packet->srcaddr, packet->srclen);
        key.destlen = packet->srclen;
        key.seq = packet->recvhdr.seq;

        struct rb_node *cachenode;
        cache_t *cache;

        /* If multi-threaded processing request, protect the synnowpack */
        pthread_mutex_lock(&psar->cachelock);

        reliable_ack_unsave(psar);

        if (packet->recvhdr.type == SU_RELIABLE && 
                (cachenode = rb_search(&psar->rbackcache, &key))) {
#ifdef SU_DEBUG_RBTREE
            LOG_MSG("find cache_t node ....");
#endif
            free(packet);
            cache = rb_entry(cachenode, cache_t, rbn);

            struct iovec	iovsend[2] = {{0}};
            struct msghdr	msgsend = {0};	/* assumed init to 0 */
            frames_t *pack = &cache->pack;
            suhdr_t answerhdr = pack->recvhdr;

            answerhdr.act  = SU_ACK;
            msgsend.msg_name = (void*)&pack->srcaddr;
            msgsend.msg_namelen = pack->srclen;
            msgsend.msg_iov = &iovsend[0];
            msgsend.msg_iovlen = 2;

            iovsend[0].iov_base = &answerhdr;
            iovsend[0].iov_len = sizeof(suhdr_t);
            iovsend[1].iov_base = (void*)pack->data;
            iovsend[1].iov_len = pack->len;

            sendmsg(psar->fd, &msgsend, 0);

            pthread_mutex_unlock(&psar->cachelock);
            continue;
        }

        psar->synnowpack = packet;
        request_handle(psar);
        psar->synnowpack = 0;
        pthread_mutex_unlock(&psar->cachelock);
    }

    return (void*)0;
}

static int thread_install(void *v)
{
    supeer_t *psar = (supeer_t*)v;

    if (psar->tid)
        return 0;

    pthread_attr_t attr;

    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 1024*1024); //set stack size 1M
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    if ((errno = pthread_create(&psar->tid, &attr, thread_request_handle, psar)) != 0) {
#ifdef SU_DEBUG_PEER
        err_ret("peer %x pthread_create error");
#endif
        pthread_attr_destroy(&attr);
        return (-1);
    }

    pthread_attr_destroy(&attr);

#ifdef SU_DEBUG_PEER
    log_msg("peer %x Install the asynchronous request processing thread", psar, (unsigned)psar->tid);
#endif

    return 0;
}

int su_peer_reliable_request_handle_install(supeer_t *psar,
        cb_su_peer_receiver_t* reliable_request_handle)
{
    int ret;

    pthread_mutex_lock(&psar->lock);
    psar->reliable_request_handle = reliable_request_handle;
    ret = thread_install(psar);
    pthread_mutex_unlock(&psar->lock);

    return ret;
}
int su_peer_ordinary_request_handle_install(supeer_t *psar,
        cb_su_peer_receiver_t* ordinary_request_handle)
{
    int ret;

    pthread_mutex_lock(&psar->lock);
    psar->ordinary_request_handle = ordinary_request_handle;
    ret = thread_install(psar);
    pthread_mutex_unlock(&psar->lock);

    return ret;
}
void su_peer_reliable_request_handle_uninstall(supeer_t *psar)
{
    pthread_mutex_lock(&psar->lock);
    psar->reliable_request_handle = 0;
    pthread_mutex_unlock(&psar->lock);
}
void su_peer_ordinary_request_handle_uninstall(supeer_t *psar)
{
    pthread_mutex_lock(&psar->lock);
    psar->ordinary_request_handle = 0;
    pthread_mutex_unlock(&psar->lock);
}

static void su_peer_recv_handle(fe_t * fe)
{
    int ret;
    SA4 addr;
    socklen_t socklen = sizeof(SA4);
    supeer_t *psar = container_of(fe, supeer_t, fe);
    struct iovec    iovrecv[2] = {{0}}; /* assumed init to 0 */
    struct msghdr   msgrecv = {0};  /* assumed init to 0 */
    frames_t *packet;
recvagain:
    packet = calloc(1, sizeof(frames_t) + REALDATAMAX);
    if (packet == 0) {
        log_msg("peer %x ENOMEM", psar);
        ret = recvfrom(fe->fd, rejectbuff, sizeof(rejectbuff), 0, (SA*)&addr, &socklen); // reject data
        if (ret < 0 && errno == EAGAIN) {
            return;
        }
#ifdef SU_DEBUG_PEER_RECV
        ERR_RET("peer %x %d recv %s:%d bytes %d, but reject datas", psar,
                fe->fd, inet_ntoa(addr.sin_addr), ntohs(addr.sin_port), ret);
#endif
        return;
    }

    packet->srclen      = sizeof(SA4);

    msgrecv.msg_name    = & packet->srcaddr;
    msgrecv.msg_namelen = packet->srclen;
    msgrecv.msg_iov     = iovrecv;
    msgrecv.msg_iovlen  = 2;

    iovrecv[0].iov_base = & packet->recvhdr;
    iovrecv[0].iov_len  = sizeof(suhdr_t);
    iovrecv[1].iov_base = packet->data;
    iovrecv[1].iov_len  = REALDATAMAX;

    if ((ret = recvmsg(fe->fd, &msgrecv, 0)) < 0) {
        if (ret < 0 && errno == EAGAIN) {
            free(packet);
            return;
        }
        ERR_QUIT("recvmsg error");
    }

    if (ret <= sizeof(suhdr_t)) {
#ifdef SU_DEBUG_PEER_RECV
        errno = EBADMSG;
        err_ret("peer %x recv %s:%d raw bytes %d less than the protocol header %d", psar,
                inet_ntoa(((SA4*)&packet->srcaddr)->sin_addr),
                ntohs(((SA4*)&packet->srcaddr)->sin_port), ret, sizeof(suhdr_t));
#endif
        free(packet);
        goto recvagain;
    }

#ifdef SU_DEBUG_PEER_RECV
    log_msg("peer %x recv %s:%d raw bytes %d", psar,
            inet_ntoa(((SA4*)&packet->srcaddr)->sin_addr),
            ntohs(((SA4*)&packet->srcaddr)->sin_port), ret);
#endif


    suhdr_t *r = &packet->recvhdr;
    uint8_t act  = r->act;
    uint8_t type = r->type;

    packet->len = ret - sizeof(suhdr_t);

    SA4 *psrc, *pdst;
    psrc = (SA4*)&packet->srcaddr;
    pdst = (SA4*)&psar->destaddr;

    pthread_mutex_lock(&psar->lock);
    if (act == SU_SYN) {
        if (psar->tid == 0) {
            // There reject datas, not callback handler
            pthread_mutex_unlock(&psar->lock);
            free(packet);
            goto recvagain;
        }
#ifdef SU_DEBUG_LIST
        log_msg("peer %x append syn list "ColorRed"%p"ColorEnd" seq %d data len=%d",
                psar, packet, r->seq, packet->len);
#endif
        list_append(&psar->synrecvls, &packet->node);
        pthread_cond_broadcast(&psar->syncond);

    } else if (act == SU_ACK && type == SU_RELIABLE
            && psrc->sin_addr.s_addr == pdst->sin_addr.s_addr
            && psrc->sin_port == pdst->sin_port) {
#ifdef SU_DEBUG_LIST
        log_msg("peer %x append ack list "ColorRed"%p"ColorEnd" seq %d data len=%d",
                psar, packet, r->seq, packet->len);
#endif
        list_append(&psar->ackrecvls, &packet->node);
        pthread_cond_broadcast(&psar->ackcond);

    } else {
        pthread_mutex_unlock(&psar->lock);
#ifdef SU_DEBUG_PEER_RECV
        errno = EBADMSG;
        err_ret("peer %x recv %s:%d raw bytes %d protocol format error", psar,
                inet_ntoa(((SA4*)&packet->srcaddr)->sin_addr),
                ntohs(((SA4*)&packet->srcaddr)->sin_port), ret);
#endif
        free(packet);
        return;

    }
    pthread_mutex_unlock(&psar->lock);

    goto recvagain;
}

int su_peer_create_bind(supeer_t *psar, int port, const SA *ptoaddr, socklen_t servlen)
{
    psar->fd = socket(ptoaddr->sa_family, SOCK_DGRAM, 0);
    if (psar->fd < 0) {
#ifdef SU_DEBUG_PEER
        ERR_RET("peer %x create failed, socket error", psar);
#endif
        return -1;
    }
    
    if (port > 0 && port <= 65535) {
        void *paddr;
        SA4 s4;
        SA6 s6;
        if (servlen == sizeof(SA4)) {
            memcpy(&s4, ptoaddr, servlen);
            s4.sin_port = htons(port);
            inet_pton(PF_INET, "0.0.0.0", &s4.sin_addr.s_addr);
            paddr = &s4;
        } else if (servlen == sizeof(SA6)) {
            memcpy(&s6, ptoaddr, servlen);
            s6.sin6_port = htons(port);
            inet_pton(PF_INET6, "::", &s6.sin6_addr.__in6_u); // Uncorroborated
            paddr = &s6;
        } else {
            close(psar->fd);
            psar->fd = -1;
            errno = EINVAL;
            return -1;
        }
        if (bind(psar->fd, paddr, servlen) < 0) {
            close(psar->fd);
            psar->fd = -1;
            return -1;
        }
    }

    if (setfd_nonblock(psar->fd) < 0) {
        close(psar->fd);
        psar->fd = -1;
        return -1;
    }

    memcpy(&psar->destaddr, ptoaddr, servlen);
    psar->destlen = servlen;

    psar->seq = 0;
    psar->rttinit = 0;
    psar->retry = 2; //RTT_MAXNREXMT;

    psar->ackwaitnum = 0;
    list_init(&psar->ackrecvls);
    list_init(&psar->synrecvls);
    list_init(&psar->lsackcache);
    rbt_init(&psar->rbackcache, cache_getkey, search_cache_cmp);

    pthread_mutex_init(&psar->lock, 0);
    pthread_cond_init(&psar->ackcond, 0);
    pthread_cond_init(&psar->syncond, 0);
    pthread_mutex_init(&psar->cachelock, 0);

    psar->tid = 0;
    psar->synnowpack = 0;
    psar->reliable_request_handle = 0;
    psar->ordinary_request_handle = 0;

    pthread_mutex_lock(&emutex);
    if (sugem == 0) {
        sugem = Em_open(100, -1, 0, 0, 0);
        Em_run(sugem);
    }
    pthread_mutex_unlock(&emutex);

    memset(&psar->fe, 0, sizeof(fe_t));
    fe_init(&psar->fe, sugem, psar->fd);
    fe_set(&psar->fe, EPOLLIN, su_peer_recv_handle);
    fe_set(&psar->fe, EPOLLET, 0);
    Fe_em_add(&psar->fe);

#ifdef SU_DEBUG_PEER
    log_msg("peer %x create successful, socket %d", psar, psar->fd);
#endif
    return 0;
}

int su_peer_create(supeer_t *psar, const SA *ptoaddr, socklen_t servlen)
{
    return su_peer_create_bind(psar, 0, ptoaddr, servlen);
}

void su_peer_destroy(supeer_t *psar)
{
    if (psar->fd >= 0) {
        close(psar->fd);
        psar->fd = -1;
        return;
    }
    pthread_mutex_destroy(&psar->lock);
    pthread_cond_destroy(&psar->ackcond);
}

uint32_t get_new_seq(supeer_t *psar)
{
    uint32_t nseq;
    pthread_mutex_lock(&psar->lock);
    nseq = ++psar->seq;
    pthread_mutex_unlock(&psar->lock);
    return nseq;
}

static ssize_t su_peer_send_act(supeer_t *psar, const void *outbuff, size_t outbytes)
{
    ssize_t			n;
    struct iovec	iovsend[2] = {{0}};
    struct msghdr	msgsend = {0};	/* assumed init to 0 */
    suhdr_t sendhdr = {0};   /* SU_RELIABLE Request protocol head */

    pthread_mutex_lock(&psar->lock);
    sendhdr.act  = SU_SYN;
    sendhdr.type = SU_ORDINARY;
    sendhdr.seq = ++psar->seq;
    sendhdr.ts = 0;
    msgsend.msg_name = (void*)&psar->destaddr;
    msgsend.msg_namelen = psar->destlen;
    msgsend.msg_iov = &iovsend[0];
    msgsend.msg_iovlen = 2;

    iovsend[0].iov_base = &sendhdr;
    iovsend[0].iov_len = sizeof(suhdr_t);
    iovsend[1].iov_base = (void*)outbuff;
    iovsend[1].iov_len = outbytes;

    n = sendmsg(psar->fd, &msgsend, 0);
    pthread_mutex_unlock(&psar->lock);

    if (n != sizeof(suhdr_t) + outbytes)
        return(-1);

    return(outbytes);
}

static int su_cmp_ack_SU_RELIABLE(suhdr_t *syn, suhdr_t *ack)
{
    if (
            SU_ACK    == ack->act  &&
            syn->type == ack->type &&
            syn->seq  == ack->seq  &&
            syn->ts   == ack->ts
       )
        return 1;
    return 0;
}

static ssize_t su_peer_send_recv_act(supeer_t *psar, 
        const void *outbuff, size_t outbytes,
        void *inbuff, size_t inbytes, int retransmit)
{
    ssize_t			n;
    struct iovec	iovsend[2]={{0}};
    struct msghdr	msgsend = {0};	/* assumed init to 0 */
    suhdr_t sendhdr = {0};   /* SU_RELIABLE Request protocol head */
    suhdr_t *r;
    int ret, waitsec;

    struct list *node = 0;
    frames_t *packet = 0;

    pthread_mutex_lock(&psar->lock);
    if (psar->rttinit == 0) {
        rtt_init(&psar->rttinfo, psar->retry);       /* first time we're called */
        psar->rttinit = 1;
    }

    if (retransmit == 0)
        psar->seq++;

    sendhdr.act  = SU_SYN;
    sendhdr.type = SU_RELIABLE;
    sendhdr.seq  = psar->seq;
    msgsend.msg_name = (void*)&psar->destaddr;
    msgsend.msg_namelen = psar->destlen;
    msgsend.msg_iov = iovsend;
    msgsend.msg_iovlen = 2;

    iovsend[0].iov_base = (void*)&sendhdr;
    iovsend[0].iov_len = sizeof(suhdr_t);
    iovsend[1].iov_base = (void*)outbuff;
    iovsend[1].iov_len = outbytes;

    struct timespec abstime = {0};
    suhdr_t *precvhdr;

    rtt_newpack(&psar->rttinfo);		/* initialize for this packet */
    psar->ackwaitnum ++;

sendagain:
    sendhdr.ts = rtt_ts(&psar->rttinfo);
    if (sendmsg(psar->fd, &msgsend, 0) < 0) {
        ERR_RET("su_peer_send_recv_act sendmsg error");
        goto error_ret;
    }

    waitsec = rtt_start(&psar->rttinfo);	/* calc timeout value & start timer */
#ifdef	RTT_DEBUG
    fprintf(stderr, ColorRed "send seq %4d: " ColorEnd, sendhdr.seq);
    rtt_debug(&psar->rttinfo);
#endif

    /* set timed wait time-point */
    maketimeout_seconds(&abstime, waitsec);

#ifdef SU_DEBUG_TIMEVERBOSE
    struct timeval now;
    gettimeofday(&now, 0);
    log_msg( ColorBlue "pthread_cond_timedwait : %u.%u time expire" ColorEnd, 
            abstime.tv_sec, abstime.tv_nsec);
    log_msg( ColorBlue "pthread_cond_timedwait : %d.%d now time" ColorEnd, 
            now.tv_sec, now.tv_usec*1000);
#endif

timedwaitagain:
    ret = pthread_cond_timedwait(&psar->ackcond, &psar->lock, &abstime);
    if (ret == 0) {
#ifdef SU_DEBUG_TIMEVERBOSE
        struct timeval now;
        gettimeofday(&now, 0);
        log_msg(ColorBlue "pthread_cond_timedwait : %d.%d ack cond interrupt" ColorEnd,
                now.tv_sec, now.tv_usec*1000);
#endif
        node = psar->ackrecvls.next;
        for (; node != &psar->ackrecvls; node = node->next) {
            packet = container_of(node, frames_t, node);
            r = &packet->recvhdr;
            if (su_cmp_ack_SU_RELIABLE(&sendhdr, r)) { break; }
        }
        if ( node == &psar->ackrecvls ) {
            /* Be careful of the lock, locked -> timedwait -> unlock */
#ifdef SU_DEBUG_LIST
            log_msg("peer %x no found seq %d ack, timed wait again", psar, sendhdr.seq);
#endif
            goto timedwaitagain;
        }

        /* Find response packet node */
        list_remove(&packet->node);

        n = packet->len;
        precvhdr = &packet->recvhdr;

#ifdef SU_DEBUG_PEER_RECV
        log_msg("peer %x recv addr %p seq %d len = %d", psar, packet, r->seq, packet->len);
#endif

#ifdef	RTT_DEBUG
        fprintf(stderr, ColorRed "recv seq %4d \n" ColorEnd, precvhdr->seq);
#endif
        // TODO: SU_RELIABLE received response, copy to user's buffer
        memcpy(inbuff, packet->data, n > inbytes ? inbytes : n);

    } else if (ret == EINTR) {
#ifdef SU_DEBUG_TIMEDWAIT
        log_msg("pthread_cond_timedwait system EINTR, timed wait again");
#endif
        goto timedwaitagain;
    } else if (ret == ETIMEDOUT) {
#ifdef SU_DEBUG_TIMEVERBOSE
        struct timeval now;
        gettimeofday(&now, 0);
        log_msg(ColorBlue "pthread_cond_timedwait : %u.%u ETIMEOUT have expired" ColorEnd,
                now.tv_sec, now.tv_usec*1000);
#endif
        if (rtt_timeout(&psar->rttinfo) < 0) {
            err_msg(ColorYel "no response from server, giving up" ColorEnd);
            psar->rttinit = 0;	/* reinit in case we're called again */
            errno = ETIMEDOUT;
            goto error_ret;
        }
#ifdef	RTT_DEBUG
        err_msg(ColorRed "     seq %4d timeout, retransmitting %d" ColorEnd, 
                sendhdr.seq, ++retransmit);
#endif
        goto sendagain;
    } else {
        errno = ret;
        ERR_RET(" su_peer_send_recv_act unknown error[%d]", ret);
        goto error_ret;
    }

    /* calculate & store new RTT estimator values */
    rtt_stop(&psar->rttinfo, rtt_ts(&psar->rttinfo) - precvhdr->ts);

    if (--psar->ackwaitnum == 0) {
        su_peer_list_empty(psar, &psar->ackrecvls);
    }
    pthread_mutex_unlock(&psar->lock);

#ifdef SU_DEBUG_LIST
    log_msg("peer %x free node " ColorRed "%p seq %d" ColorEnd, psar, packet, sendhdr.seq);
#endif

    free(packet);

    return(n);	/* return size of received datagram */

error_ret:
    if (--psar->ackwaitnum == 0) {
        su_peer_list_empty(psar, &psar->ackrecvls);
    }
    pthread_mutex_unlock(&psar->lock);
    return(-1);
}

static ssize_t su_peer_reply_act(supeer_t *psar, 
        const void *outbuff, size_t outbytes)
{
    if (psar->synnowpack == 0) {
        err_msg("peer %x is no request data");
        return -1;
    }

    ssize_t			n;
    struct iovec	iovsend[2] = {{0}};
    struct msghdr	msgsend = {0};	/* assumed init to 0 */
    frames_t *pack = psar->synnowpack;
    suhdr_t answerhdr = pack->recvhdr;

    answerhdr.act  = SU_ACK;
    msgsend.msg_name = (void*)&pack->srcaddr;
    msgsend.msg_namelen = pack->srclen;
    msgsend.msg_iov = &iovsend[0];
    msgsend.msg_iovlen = 2;

    iovsend[0].iov_base = &answerhdr;
    iovsend[0].iov_len = sizeof(suhdr_t);
    iovsend[1].iov_base = (void*)outbuff;
    iovsend[1].iov_len = outbytes;

    n = sendmsg(psar->fd, &msgsend, 0);
    if (n != sizeof(suhdr_t) + outbytes)
        return(-1);

    if (answerhdr.type == SU_RELIABLE)
        reliable_ack___save(psar, outbuff, outbytes);

    return(outbytes);
}

ssize_t su_peer_reply(supeer_t *psar, const void *outbuff, size_t outbytes)
{
    if (outbytes > REALDATAMAX) { errno = EMSGSIZE; return -1; }
    if (outbytes <= 0 || outbuff == 0) { errno = EINVAL; return -1;}
    return su_peer_reply_act(psar, outbuff, outbytes);
}

ssize_t su_peer_send(supeer_t *psar, const void *outbuff, size_t outbytes)
{
    if (outbytes > REALDATAMAX) { errno = EMSGSIZE; return -1; }
    if (outbytes <= 0 || outbuff == 0) { errno = EINVAL; return -1;}
    return su_peer_send_act(psar, outbuff, outbytes);
}

ssize_t su_peer_request(supeer_t *psar, const void *outbuff, size_t outbytes,
        void *inbuff, size_t inbytes)
{
    if (outbytes > REALDATAMAX) { errno = EMSGSIZE; return -1; }
    if (outbytes <= 0 || outbuff == 0) { errno = EINVAL; return -1;}
    if (inbytes  <= 0 || inbuff== 0) { errno = EINVAL; return -1;}
    return su_peer_send_recv_act(psar, outbuff, outbytes, inbuff, inbytes, 0);
}

ssize_t su_peer_request_retry(supeer_t *psar, const void *outbuff, size_t outbytes,
        void *inbuff, size_t inbytes)
{
    if (outbytes > REALDATAMAX) { errno = EMSGSIZE; return -1; }
    if (outbytes <= 0 || outbuff == 0) { errno = EINVAL; return -1;}
    if (inbytes  <= 0 || inbuff== 0) { errno = EINVAL; return -1;}
    return su_peer_send_recv_act(psar, outbuff, outbytes, inbuff, inbytes, 1);
}

