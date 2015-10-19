#include "sarudp_peer.h"

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

static inline int reliable_ack___save(su_peer_t *psar,
        const void *outbuff, int outbytes)
{
    cache_t * newack;
    newack = calloc(1, sizeof(cache_t) + outbytes);
    if (newack == 0) {
        errno = ENOBUFS;
        return -1;
    }
    time(&newack->ts);
    memcpy(&newack->frame, psar->nowsynframe, sizeof(frames_t));
    memcpy(newack->frame.data, outbuff, outbytes);
    newack->frame.len = outbytes;

    /* Adding associated */
    if (rb_insert(&psar->rbackcache, &newack->rbn) < 0) {
#if defined SU_DEBUG_LIST || defined SU_DEBUG_RBTREE 
        char ipbuff[INET6_ADDRSTRLEN];
        int port;
#ifdef SU_DEBUG_IP6FULL
        su_get_ip_port_f(&newack->frame.srcaddr, ipbuff, sizeof(ipbuff), &port);
#else
        su_get_ip_port(&newack->frame.srcaddr, ipbuff, sizeof(ipbuff), &port);
#endif
        log_msg("peer %x time %u key(%s:%d:%u:%u)" ColorRed " +ACK cache %p failed" ColorEnd,
                psar, newack->ts, ipbuff, port,
                newack->frame.recvhdr.sid, newack->frame.recvhdr.seq, newack);
#endif
        free(newack);
        errno = EALREADY;
        return -1;
    } else {
#if defined SU_DEBUG_LIST || defined SU_DEBUG_RBTREE
        char ipbuff[INET6_ADDRSTRLEN];
        int port;
#ifdef SU_DEBUG_IP6FULL
        su_get_ip_port_f(&newack->frame.srcaddr, ipbuff, sizeof(ipbuff), &port);
#else
        su_get_ip_port(&newack->frame.srcaddr, ipbuff, sizeof(ipbuff), &port);
#endif
        log_msg("peer %x time %u key(%s:%d:%u:%u)" ColorRed " +ACK cache %p" ColorEnd,
                psar, newack->ts, ipbuff, port,
                newack->frame.recvhdr.sid, newack->frame.recvhdr.seq, newack);
#endif
        list_append(&psar->lsackcache, &newack->frame.node);
    }
    return 0;
}
static inline void reliable_ack_unsave (su_peer_t *psar)
{
    time_t nowtime;

    cache_t *frees, *cache = container_of 
        ( list_head(&psar->lsackcache, frames_t, node), cache_t, frame );

    time(&nowtime);

    while ( &psar->lsackcache != &cache->frame.node ) {
        if ( abs(nowtime - cache->ts) < CACHETIMEOUT ) break;
        frees = cache;
        cache = container_of
            ( list_next(&cache->frame, frames_t, node), cache_t, frame );

        /* Disconnect associated */
        list_remove(&frees->frame.node);
        rb_erase(&frees->rbn, &psar->rbackcache);
#if defined SU_DEBUG_LIST || defined SU_DEBUG_RBTREE
        char ipbuff[INET6_ADDRSTRLEN];
        int port;
#ifdef SU_DEBUG_IP6FULL
        su_get_ip_port_f(&frees->frame.srcaddr, ipbuff, sizeof(ipbuff), &port);
#else
        su_get_ip_port(&frees->frame.srcaddr, ipbuff, sizeof(ipbuff), &port);
#endif
        LOG_MSG("peer %x time %u key(%s:%d:%u:%u)" ColorRed " -ACK cache %p" ColorEnd,
                psar, frees->ts, ipbuff, ntohs(port),
                frees->frame.recvhdr.sid, frees->frame.recvhdr.seq, frees);
#endif
        free(frees);
    }
}
static void su_peer_list_empty(su_peer_t *psar, struct list *l)
{
    frames_t *realnode;
    struct list *node = l->next;

    while ( node != l ) {
        list_remove(node);
        realnode = container_of(node, frames_t, node);
        node = node->next;
        free(realnode);
#ifdef SU_DEBUG_LIST
        LOG_MSG("peer %x free frames_t node " ColorRed "%p" ColorEnd, psar, realnode);
#endif
    }
}

void request_handle(su_peer_t *psar)
{
    frames_t *frame = psar->nowsynframe;
    suhdr_t *phdr = &frame->recvhdr;

    switch (phdr->type) {
        case SU_RELIABLE:
            if (psar->reliable_request_handle) {
                psar->reliable_request_handle(psar, (char*)frame->data, frame->len);
            } break;
        case SU_ORDINARY:
            if (psar->ordinary_request_handle) {
                psar->ordinary_request_handle(psar, (char*)frame->data, frame->len);
            } break;
        default:
            LOG_MSG("peer %x recv request type unknown %d", psar, phdr->type);
            return;
    }
}

static void *thread_request_handle(void *v)
{
    su_peer_t *psar = (su_peer_t*)v;
    struct list *synnode;
    frames_t *frame;

    int ret;
    struct timespec abstime = {0};

    for (;psar->run;) {
        pthread_mutex_lock(&psar->lock);
        while ((synnode = psar->synrecvls.next) == &psar->synrecvls) {
            maketimeout_seconds(&abstime, 1);
            pthread_testcancel();
            ret = pthread_cond_timedwait(&psar->syncond, &psar->lock, &abstime);
            if (!psar->run) {
                pthread_mutex_unlock(&psar->lock);
                goto quit;
            }
            pthread_testcancel();
            if ( ret == ETIMEDOUT ) {
                pthread_mutex_lock(&psar->cachelock);
                reliable_ack_unsave(psar);
                pthread_mutex_unlock(&psar->cachelock);
            }
        }
        list_remove(synnode);
        pthread_mutex_unlock(&psar->lock);

        // TODO: Have a request
        frame = container_of(synnode, frames_t, node);

        rb_key_cache_t key;
        memcpy(&key.destaddr, &frame->srcaddr, sizeof(SAUN));
        key.destlen = frame->srclen;
        key.seq = frame->recvhdr.seq;
        key.sid = frame->recvhdr.sid;

        struct rb_node *cachenode;
        cache_t *cache;

        pthread_mutex_lock(&psar->cachelock);
        reliable_ack_unsave(psar);
        if (frame->recvhdr.type == SU_RELIABLE &&
                (cachenode = rb_search(&psar->rbackcache, &key))) {
            cache = rb_entry(cachenode, cache_t, rbn);

#ifdef SU_DEBUG_RBTREE
            char ipbuff[INET6_ADDRSTRLEN];
            int port;
#ifdef SU_DEBUG_IP6FULL
            su_get_ip_port_f(&frame->srcaddr, ipbuff, sizeof(ipbuff), &port);
#else
            su_get_ip_port(&frame->srcaddr, ipbuff, sizeof(ipbuff), &port);
#endif
            log_msg("peer %x time %u key(%s:%d:%u:%u)" ColorRed " @ACK cache %p" ColorEnd,
                    psar,cache->ts, ipbuff, port,
                    cache->frame.recvhdr.sid,
                    cache->frame.recvhdr.seq,
                    cache);
#endif

            struct iovec	iovsend[2] = {{0}};
            struct msghdr	msgsend = {0};	/* assumed init to 0 */

            frame->recvhdr.act = SU_ACK;
            msgsend.msg_name = (void*)&cache->frame.srcaddr;
            msgsend.msg_namelen = cache->frame.srclen;
            msgsend.msg_iov = &iovsend[0];
            msgsend.msg_iovlen = 2;

            iovsend[0].iov_base = &frame->recvhdr;
            iovsend[0].iov_len = sizeof(suhdr_t);
            iovsend[1].iov_base = (void*)cache->frame.data;  /* get the cache results */
            iovsend[1].iov_len = cache->frame.len;

            if (sendmsg(psar->fd, &msgsend, 0) != sizeof(suhdr_t) + cache->frame.len) {
                char ipbuff[INET6_ADDRSTRLEN];
                int port;
#ifdef SU_DEBUG_IP6FULL
                su_get_ip_port_f(&frame->srcaddr, ipbuff, sizeof(ipbuff), &port);
#else
                su_get_ip_port(&frame->srcaddr, ipbuff, sizeof(ipbuff), &port);
#endif
                err_ret("retransmit sendmsg %s:%d:%u:%u:%u error",
                        ipbuff, port, frame->recvhdr.sid,
                        frame->recvhdr.seq, frame->recvhdr.ts);
            } 
#ifdef SU_DEBUG_PEER_RESEND
            else {
                char ipbuff[INET6_ADDRSTRLEN];
                int port;
#ifdef SU_DEBUG_IP6FULL
                su_get_ip_port_f(&frame->srcaddr, ipbuff, sizeof(ipbuff), &port);
#else
                su_get_ip_port(&frame->srcaddr, ipbuff, sizeof(ipbuff), &port);
#endif
                log_msg("retransmit sendmsg %s:%d:%u:%u:%u",
                        ipbuff, port, frame->recvhdr.sid,
                        frame->recvhdr.seq, frame->recvhdr.ts);
            }
#endif
            pthread_mutex_unlock(&psar->cachelock);
            free(frame);
            continue;
        }

        psar->nowsynframe = frame;
        request_handle(psar);
#if defined SU_DEBUG_PEER_RECV || defined SU_DEBUG_LIST
        log_msg("peer %x delete syn "ColorRed"%p"ColorEnd" seq %d datagram len %d",
                psar, frame, frame->recvhdr.seq, frame->len);
#endif
        free(frame);
        psar->nowsynframe = 0;
        pthread_mutex_unlock(&psar->cachelock);
    }

quit:
    return (void*)0;
}

static int su_peer_thread_install(su_peer_t *psar)
{
    pthread_attr_t attr;

    psar->run = 0;
    psar->reliable_request_handle = 0;
    psar->ordinary_request_handle = 0;

    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 1024*1024);

    errno = pthread_create(&psar->tid, &attr, thread_request_handle, psar);
    if (errno != 0) {
        pthread_attr_destroy(&attr);
        return (-1);
    }
    pthread_attr_destroy(&attr);
    psar->run = 1;
    return 0;
}
static int su_peer_thread_uninstall(su_peer_t *psar)
{
    void *ret;

    psar->run = 0;
    errno = pthread_join(psar->tid, &ret);
    if (errno != 0)
        err_sys("peer %x can't join with thread %x error");
    log_msg("peer %x join with thread %x code %d", psar, psar->tid, ret);
    return 0;
}

void su_peer_reliable_request_handle_install(su_peer_t *psar,
        cb_su_peer_receiver_t* reliable_request_handle)
{
    pthread_mutex_lock(&psar->lock);
    psar->reliable_request_handle = reliable_request_handle;
    pthread_mutex_unlock(&psar->lock);
}
void su_peer_ordinary_request_handle_install(su_peer_t *psar,
        cb_su_peer_receiver_t* ordinary_request_handle)
{
    pthread_mutex_lock(&psar->lock);
    psar->ordinary_request_handle = ordinary_request_handle;
    pthread_mutex_unlock(&psar->lock);
}
void su_peer_reliable_request_handle_uninstall(su_peer_t *psar)
{
    pthread_mutex_lock(&psar->lock);
    psar->reliable_request_handle = 0;
    pthread_mutex_unlock(&psar->lock);
}
void su_peer_ordinary_request_handle_uninstall(su_peer_t *psar)
{
    pthread_mutex_lock(&psar->lock);
    psar->ordinary_request_handle = 0;
    pthread_mutex_unlock(&psar->lock);
}

static void handle_su_peer_recv(fe_t * fe)
{
    int ret, port;
    char ipbuff[INET6_ADDRSTRLEN];
    SAUN saddr;
    socklen_t socklen;
    su_peer_t *psar = container_of(fe, su_peer_t, fe);
    struct iovec    iovrecv[2] = {{0}}; /* assumed init to 0 */
    struct msghdr   msgrecv = {0};  /* assumed init to 0 */
    frames_t *frame;
recvagain:
    socklen = psar->destlen;
    frame = calloc(1, sizeof(frames_t) + REALDATAMAX);
    if (frame == 0) {
        errno = ENOBUFS; // ENOMEM
        log_msg("peer %x ENOBUFS", psar);
        /* reject datagram */
        ret = recvfrom(fe->fd, rejectbuff, sizeof(rejectbuff), 0, (SA*)&saddr, &socklen);
        if (ret < 0 && errno == EAGAIN) {
            return;
        }
#ifdef SU_DEBUG_PEER_RECV
        switch (saddr.sfamily) {
            case PF_INET:
            case PF_INET6:
#ifdef SU_DEBUG_IP6FULL
                su_get_ip_port_f(&saddr, ipbuff, sizeof(ipbuff), &port);
#else
                su_get_ip_port(&saddr, ipbuff, sizeof(ipbuff), &port);
#endif
                break;
            default:
                log_msg("peer %x reject unknown protocol raw bytes %d", psar, ret);
                free(frame);
                goto recvagain;
        };
        ERR_RET("peer %x recv %s:%d bytes %d, but reject datas",
                psar, ipbuff, port, ret);
#endif
        return;
    }

    frame->srclen       = psar->destlen;

    msgrecv.msg_name    = & frame->srcaddr;
    msgrecv.msg_namelen = frame->srclen;
    msgrecv.msg_iov     = iovrecv;
    msgrecv.msg_iovlen  = 2;

    iovrecv[0].iov_base = & frame->recvhdr;
    iovrecv[0].iov_len  = sizeof(suhdr_t);
    iovrecv[1].iov_base = frame->data;
    iovrecv[1].iov_len  = REALDATAMAX;

    if ((ret = recvmsg(fe->fd, &msgrecv, 0)) < 0) {
        if (ret < 0 && errno == EAGAIN) {
            free(frame);
            return;
        }
        ERR_RET("recvmsg error");
    }

    if (ret < sizeof(suhdr_t)) {
#ifdef SU_DEBUG_PEER_RECV
        errno = EBADMSG;
        err_ret("peer %x recv %s:%d raw bytes %d less than the protocol header %d", psar,
                ipbuff, port, ret, sizeof(suhdr_t));
#endif
        free(frame);
        goto recvagain;
    }

#ifdef SU_DEBUG_PEER_RECV
    LOG_MSG("peer %x recv %s:%d raw bytes %d", psar,
            ipbuff, port, ret);
#endif

    suhdr_t *r = &frame->recvhdr;
    uint8_t act  = r->act;
    uint8_t type = r->type;

    frame->len = ret - sizeof(suhdr_t);

    switch (frame->srcaddr.sfamily) {
        case PF_INET:
        case PF_INET6:
#ifdef SU_DEBUG_IP6FULL
            su_get_ip_port_f(&frame->srcaddr, ipbuff, sizeof(ipbuff), &port);
#else
            su_get_ip_port(&frame->srcaddr, ipbuff, sizeof(ipbuff), &port);
#endif
            break;
        default:
            log_msg("peer %x reject unknown protocol type %d raw bytes %d",
                    psar, frame->srcaddr.sfamily, ret);
            free(frame);
            goto recvagain;
    };

    SAUN *psrc, *pdst;
    psrc = &frame->srcaddr; // foreign host
    pdst = &psar->destaddr; // localhost

#ifndef promiscuous_mode
    /*  Filter: Check address and port
     *  compare datagram source and peer destination */
    if (    (pdst->sfamily == PF_INET6 &&
                sockaddr_in6_cmp(&psrc->addr6, &pdst->addr6 ) != 0)
            || (pdst->sfamily == PF_INET &&
                sockaddr_in4_cmp(&psrc->addr4, &pdst->addr4 ) != 0)  ){
#ifdef SU_DEBUG_PEER_RECV
        log_msg(ColorYel"peer %x reject act[0x%02x] from %s:%d datagram len %d"ColorEnd,
                act, psar, ipbuff, port, frame->len);
#endif
        free(frame);
        goto recvagain;
    }
#endif /* #ifndef promiscuous_mode */

    pthread_mutex_lock(&psar->lock);
    if (act == SU_SYN && frame->len > 0) {
        if (!psar->run) {
            log_msg("peer %x thread handle no run");
            pthread_mutex_unlock(&psar->lock);
            free(frame);
            goto recvagain;
        }
#if defined SU_DEBUG_PEER_RECV || defined SU_DEBUG_LIST
        log_msg("peer %x append syn "ColorRed"%p"ColorEnd" seq %d datagram len %d",
                psar, frame, r->seq, frame->len);
#endif
        list_append(&psar->synrecvls, &frame->node);
        pthread_cond_broadcast(&psar->syncond);

    } else if (act == SU_ACK && type == SU_RELIABLE) {
#ifdef promiscuous_mode
        /* Filter: receive response from self request */
        if (    (pdst->sfamily == PF_INET6 &&
                    sockaddr_in6_cmp(&psrc->addr6, &pdst->addr6 ) != 0)
                || (pdst->sfamily == PF_INET &&
                    sockaddr_in4_cmp(&psrc->addr4, &pdst->addr4 ) != 0)  ){
#ifdef SU_DEBUG_PEER_RECV
            log_msg(ColorYel "peer %x reject ack from %s:%d datagram len %d" ColorEnd, psar,
                    ipbuff, port, frame->len);
#endif
            pthread_mutex_unlock(&psar->lock);
            free(frame);
            goto recvagain;
        }
#endif /* #ifdef promiscuous_mode */
        if (psar->ackwaitnum <= 0) {
            pthread_mutex_unlock(&psar->lock);
            free(frame);
            goto recvagain;
        }
#if defined SU_DEBUG_PEER_RECV || defined SU_DEBUG_LIST
        log_msg("peer %x append ack "ColorRed"%p"ColorEnd" seq %d datagram len %d",
                psar, frame, r->seq, frame->len);
#endif
        list_append(&psar->ackrecvls, &frame->node);
        pthread_cond_broadcast(&psar->ackcond);

    } else {
        pthread_mutex_unlock(&psar->lock);
#ifdef SU_DEBUG_PEER_RECV
        errno = EBADMSG;
        err_ret("peer %x recv %s:%d raw bytes %d protocol format error", psar, ipbuff, port, ret);
#endif
        free(frame);
        return;

    }
    pthread_mutex_unlock(&psar->lock);

    goto recvagain;
}

int su_peer_create_bind(su_peer_t *psar, int port, const SA *destaddr, socklen_t destlen)
{
    psar->fd = socket(destaddr->sa_family, SOCK_DGRAM, 0);
    if (psar->fd < 0) {
        err_ret("peer %x create failed, socket error", psar);
        return -1;
    }

    if (port > 0 && port <= 65535) {
        void *paddr;
        SA4 s4;
        SA6 s6;
        switch (destaddr->sa_family) {
            case PF_INET:
                memcpy(&s4, destaddr, destlen);  /* for sin_family and more... */
                s4.sin_port = htons(port);
                inet_pton(PF_INET, "0.0.0.0", &s4.sin_addr.s_addr);
                paddr = &s4;
                break;
            case PF_INET6:
                memcpy(&s6, destaddr, destlen); /* for sin6_family and more...  */
                s6.sin6_port = htons(port);
                inet_pton(PF_INET6, "::", &s6.sin6_addr.__in6_u);
                paddr = &s6;
                break;
            default:
                close(psar->fd);
                psar->fd = -1;
                errno = EINVAL;
                return -1;
        }
        if (bind(psar->fd, paddr, destlen) < 0) {
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

    memset(&psar->destaddr, 0, sizeof(SAUN));
    memcpy(&psar->destaddr, destaddr, destlen);
    psar->destlen = destlen;

    psar->seq = 0;
    psar->rttinit = 0;
    psar->retry = RTT_MAXNREXMT;

    psar->ackwaitnum = 0;
    list_init(&psar->ackrecvls);
    list_init(&psar->synrecvls);
    list_init(&psar->lsackcache);
    rbt_init(&psar->rbackcache, cache_getkey, search_cache_cmp);

    psar->nowsynframe = 0;

    pthread_mutex_init(&psar->mutex, 0);
    pthread_mutex_init(&psar->lock, 0);
    pthread_cond_init(&psar->ackcond, 0);
    pthread_cond_init(&psar->syncond, 0);
    pthread_mutex_init(&psar->cachelock, 0);

    if (su_peer_thread_install(psar) < 0) {
        pthread_mutex_destroy(&psar->mutex);
        pthread_mutex_destroy(&psar->lock);
        pthread_cond_destroy(&psar->ackcond);
        pthread_cond_destroy(&psar->syncond);
        pthread_mutex_destroy(&psar->cachelock);

        close(psar->fd);
        psar->fd = -1;
        return -1;
    }

    pthread_mutex_lock(&emutex);
    if (sugem == 0) {
        sugem = Em_open(100, -1, 0, 0, 0);
        Em_run(sugem);

        struct timeval now;
        gettimeofday(&now, 0);
        srand(now.tv_sec % 1000 + now.tv_usec);
    }
    psar->sid = rand() % 65535;
    pthread_mutex_unlock(&emutex);

    memset(&psar->fe, 0, sizeof(fe_t));
    fe_init(&psar->fe, sugem, psar->fd);
    fe_set(&psar->fe, EPOLLIN, handle_su_peer_recv);
    fe_set(&psar->fe, EPOLLET, 0);
    Fe_em_add(&psar->fe);

    return psar->fd;
}

int su_peer_create(su_peer_t *psar, const SA *ptoaddr, socklen_t servlen)
{
    return su_peer_create_bind(psar, 0, ptoaddr, servlen);
}

void su_peer_destroy(su_peer_t *psar)
{
    su_peer_thread_uninstall(psar);

    pthread_mutex_destroy(&psar->mutex);
    pthread_mutex_destroy(&psar->lock);
    pthread_cond_destroy(&psar->ackcond);
    pthread_cond_destroy(&psar->syncond);
    pthread_mutex_destroy(&psar->cachelock);

    close(psar->fd);
    psar->fd = -1;

    su_peer_list_empty(psar, &psar->ackrecvls);
    su_peer_list_empty(psar, &psar->synrecvls);

    cache_t *frees, *cache = container_of 
        ( list_head(&psar->lsackcache, frames_t, node), cache_t, frame );

    while ( &psar->lsackcache != &cache->frame.node ) {
        frees = cache;
        cache = container_of
            ( list_next(&cache->frame, frames_t, node), cache_t, frame );

        /* Disconnect associated And Cleanup All */
        list_remove(&frees->frame.node);
        rb_erase(&frees->rbn, &psar->rbackcache);
#if defined SU_DEBUG_LIST || defined SU_DEBUG_RBTREE 
        char ipbuff[INET6_ADDRSTRLEN];
        int port;
        su_get_ip_port_f(&frees->frame.srcaddr, ipbuff, sizeof(ipbuff), &port);
        log_msg("peer %x time %u key(%s:%d:%u:%u)" ColorRed " _ACK cache %p" ColorEnd,
                psar, frees->ts, ipbuff, port,
                frees->frame.recvhdr.sid, frees->frame.recvhdr.seq, frees);
#endif
        free(frees);
    }

    LOG_MSG("peer %x finish destroyed", psar);
}

static int su_peer_send_act(su_peer_t *psar, const void *outbuff, int outbytes)
{
    int			n;
    struct iovec	iovsend[2] = {{0}};
    struct msghdr	msgsend = {0};	/* assumed init to 0 */
    suhdr_t sendhdr = {0};   /* SU_RELIABLE Request protocol head */

    pthread_mutex_lock(&psar->lock);
    sendhdr.act  = SU_SYN;
    sendhdr.type = SU_ORDINARY;
    sendhdr.sid  = psar->sid;
    sendhdr.seq  = ++psar->seq;
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

static int su_peer_send_recv_act(su_peer_t *psar,
        const void *outbuff, int outbytes,
        void *inbuff, int inbytes, int retransmit)
{
    int             n;
    struct iovec    iovsend[2]={{0}};
    struct msghdr   msgsend = {0};	    /* assumed init to 0 */
    suhdr_t *r, sendhdr = {0};          /* protocol header */
    int ret, waitsec;

    struct list *node = 0;
    frames_t *packet = 0;

    pthread_mutex_lock(&psar->mutex);
    pthread_mutex_lock(&psar->lock);

    if (retransmit == 0) {
        psar->seq++;
        psar->retransmission = 1;
    } else {
        if (psar->retransmission == 0) {
            pthread_mutex_unlock(&psar->mutex);
            pthread_mutex_unlock(&psar->lock);
            errno = ETIMEDOUT;
            return -1;
        }
        psar->retransmission --;
    }

    if (psar->rttinit == 0) {
        rtt_init(&psar->rttinfo, psar->retry); /* first time we're called */
        psar->rttinit = 1;
    }

    sendhdr.act  = SU_SYN;
    sendhdr.type = SU_RELIABLE;
    sendhdr.sid  = psar->sid;
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
        ERR_RET("sendmsg error");
        goto error_ret;
    }

    waitsec = rtt_start(&psar->rttinfo);	/* calc timeout value & start timer */
#ifdef	SU_DEBUG_RTT
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

#if defined SU_DEBUG_PEER_RECV || defined SU_DEBUG_LIST
        log_msg("peer %x finded ack " ColorRed "%p" ColorEnd " seq %d datagram len %d",
                psar, packet, r->seq, packet->len);
#endif

#ifdef	SU_DEBUG_RTT
        fprintf(stderr, ColorRed "recv seq %4d \n" ColorEnd, precvhdr->seq);
#endif
        // TODO: SU_RELIABLE received response, copy to user's buffer
        memcpy(inbuff, packet->data, n > inbytes ? inbytes : n);

    } else if (ret == EINTR) {
        log_msg("pthread_cond_timedwait system EINTR");
        goto timedwaitagain;
    } else if (ret == ETIMEDOUT) {
#ifdef SU_DEBUG_TIMEVERBOSE
        struct timeval now;
        gettimeofday(&now, 0);
        log_msg(ColorBlue "pthread_cond_timedwait : %u.%u ETIMEOUT have expired" ColorEnd,
                now.tv_sec, now.tv_usec*1000);
#endif
        if (rtt_timeout(&psar->rttinfo) < 0) {
#ifdef	SU_DEBUG_RTT
            err_msg(ColorYel "no response from server, giving up" ColorEnd);
#endif
            psar->rttinit = 0;	/* reinit in case we're called again */
            errno = ETIMEDOUT;
            goto error_ret;
        }
#ifdef	SU_DEBUG_RTT
        err_msg(ColorRed "     seq %4d timeout, retransmitting %d" ColorEnd, 
                sendhdr.seq, ++retransmit);
#endif
        goto sendagain;
    } else {
        errno = ret;
        ERR_RET("unknown error[%d]", ret);
        goto error_ret;
    }

    /* calculate & store new RTT estimator values */
    rtt_stop(&psar->rttinfo, rtt_ts(&psar->rttinfo) - precvhdr->ts);

    if (--psar->ackwaitnum == 0) {
        su_peer_list_empty(psar, &psar->ackrecvls);
    }
    pthread_mutex_unlock(&psar->mutex);
    pthread_mutex_unlock(&psar->lock);

#ifdef SU_DEBUG_LIST
    log_msg("peer %x free node  " ColorRed "%p"ColorEnd" seq %d", psar, packet, sendhdr.seq);
#endif

    free(packet);

    return(n);	/* return size of received datagram */

error_ret:
    if (--psar->ackwaitnum == 0) {
        su_peer_list_empty(psar, &psar->ackrecvls);
    }
    pthread_mutex_unlock(&psar->mutex);
    pthread_mutex_unlock(&psar->lock);
    return(-1);
}

static int su_peer_reply_act(su_peer_t *psar,
        const void *outbuff, int outbytes)
{
    if (psar->nowsynframe == 0) {
        err_msg("peer %x is no request data");
        return -1;
    }

    int			n;
    struct iovec	iovsend[2] = {{0}};
    struct msghdr	msgsend = {0};	/* assumed init to 0 */
    frames_t *frame = psar->nowsynframe;
    suhdr_t answerhdr = frame->recvhdr;

    answerhdr.act  = SU_ACK;
    msgsend.msg_name = (void*)&frame->srcaddr;
    msgsend.msg_namelen = frame->srclen;
    msgsend.msg_iov = &iovsend[0];
    msgsend.msg_iovlen = 2;

    iovsend[0].iov_base = &answerhdr;
    iovsend[0].iov_len = sizeof(suhdr_t);
    iovsend[1].iov_base = (void*)outbuff;
    iovsend[1].iov_len = outbytes;

    if (answerhdr.type == SU_RELIABLE) {
        if (reliable_ack___save(psar, outbuff, outbytes) < 0) {
            err_ret("reliable_ack___save error");
            return -1;
        }
    }

    n = sendmsg(psar->fd, &msgsend, 0);
    if (n != sizeof(suhdr_t) + outbytes) {
        err_ret("sendmsg error");
        return(-1);
    }

    return(outbytes);
}
int su_peer_getsrcaddr_act(su_peer_t *psar, SAUN *addr)
{
    if (psar->nowsynframe == 0) {
        err_msg("peer %x is no request source");
        return -1;
    }
    memcpy(addr, &psar->nowsynframe->srcaddr, sizeof(SAUN));
    return 0;
}

int su_peer_reply(su_peer_t *psar, const void *outbuff, int outbytes)
{
    if (psar == 0) { errno = EINVAL; return -1;}
    if (outbytes > REALDATAMAX) { errno = EMSGSIZE; return -1; }
    if (    (outbytes <  0) ||
            (outbytes == 0 &&  outbuff) ||
            (outbytes >  0 && !outbuff)    )
    { errno = EINVAL; return -1; }
    return su_peer_reply_act(psar, outbuff, outbytes);
}
int su_peer_reply_ack(su_peer_t *psar)
{
    if (psar == 0) { errno = EINVAL; return -1;}
    return su_peer_reply_act(psar, 0, 0);
}

int su_peer_send(su_peer_t *psar, const void *outbuff, int outbytes)
{
    if (psar == 0) { errno = EINVAL; return -1;}
    if (outbytes > REALDATAMAX) { errno = EMSGSIZE; return -1; }
    if (outbytes <= 0 || outbuff == 0) { errno = EINVAL; return -1;}
    return su_peer_send_act(psar, outbuff, outbytes);
}

int su_peer_request(su_peer_t *psar, const void *outbuff, int outbytes,
        void *inbuff, int inbytes)
{
    if (psar == 0) { errno = EINVAL; return -1;}
    if (outbytes > REALDATAMAX) { errno = EMSGSIZE; return -1; }
    if (outbytes <= 0 || outbuff == 0) { errno = EINVAL; return -1;}
    if (inbytes  <= 0 || inbuff== 0) { errno = EINVAL; return -1;}
    return su_peer_send_recv_act(psar, outbuff, outbytes, inbuff, inbytes, 0);
}

int su_peer_request_retry(su_peer_t *psar, const void *outbuff, int outbytes,
        void *inbuff, int inbytes)
{
    if (psar == 0) { errno = EINVAL; return -1;}
    if (outbytes > REALDATAMAX) { errno = EMSGSIZE; return -1; }
    if (outbytes <= 0 || outbuff == 0) { errno = EINVAL; return -1;}
    if (inbytes  <= 0 || inbuff== 0) { errno = EINVAL; return -1;}
    return su_peer_send_recv_act(psar, outbuff, outbytes, inbuff, inbytes, 1);
}
int su_peer_getsrcaddr(su_peer_t *psar, SAUN *addr)
{
    if (psar == 0) { errno = EINVAL; return -1;}
    if (addr == 0) { errno = EINVAL; return -1;}
    return su_peer_getsrcaddr_act(psar, addr);
}
