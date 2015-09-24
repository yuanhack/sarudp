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

static inline void reliable_ack___save(supeer_t *psar, const void *outbuff, int outbytes)
{
    cache_t * newack = calloc(1, sizeof(cache_t) + outbytes);
    if (newack == 0)
        return;
    time(&newack->ts);
    memcpy(&newack->frame, psar->nowsynframe, sizeof(frames_t));
    memcpy(newack->frame.data, outbuff, outbytes);
    newack->frame.len = outbytes;

    /* Adding associated */
    if (rb_insert(&psar->rbackcache, &newack->rbn) < 0) {
#if defined SU_DEBUG_LIST || defined SU_DEBUG_RBTREE 
        SA6 * p6src = (SA6*)&newack->frame.srcaddr;
        if (newack->frame.srclen == sizeof(SA6)) {
            char ip6buff[INET6_ADDRSTRLEN];
            inet_ntop(PF_INET6, &p6src->sin6_addr, ip6buff, sizeof(ip6buff));
            LOG_MSG("peer 0x%x time %u key(%s:%d:%d)" ColorRed " +ACK cache %p failed" ColorEnd,
                    psar, newack->ts, ip6buff, ntohs(((SA4*)&newack->frame.srcaddr)->sin_port),
                    newack->frame.recvhdr.seq, newack);
        } else {
            LOG_MSG("peer 0x%x time %u key(%s:%d:%d)" ColorRed " +ACK cache %p failed" ColorEnd,
                    psar, newack->ts, inet_ntoa(((SA4*)&newack->frame.srcaddr)->sin_addr),
                    ntohs(((SA4*)&newack->frame.srcaddr)->sin_port), newack->frame.recvhdr.seq, 
                    newack);
        }
#endif
        free(newack);
        return;
    } else {
#if defined SU_DEBUG_LIST || defined SU_DEBUG_RBTREE
        SA6 * p6src = (SA6*)&newack->frame.srcaddr;
        if (newack->frame.srclen == sizeof(SA6)) {
            char ip6buff[INET6_ADDRSTRLEN];
            inet_ntop(PF_INET6, &p6src->sin6_addr, ip6buff, sizeof(ip6buff));
            LOG_MSG("peer 0x%x time %u key(%s:%d:%d)" ColorRed " +ACK cache %p" ColorEnd,
                    psar, newack->ts, ip6buff, ntohs(((SA4*)&newack->frame.srcaddr)->sin_port),
                    newack->frame.recvhdr.seq, newack);
        } else {
            LOG_MSG("peer 0x%x time %u key(%s:%d:%d)" ColorRed " +ACK cache %p" ColorEnd,
                    psar, newack->ts, inet_ntoa(((SA4*)&newack->frame.srcaddr)->sin_addr),
                    ntohs(((SA4*)&newack->frame.srcaddr)->sin_port), newack->frame.recvhdr.seq, 
                    newack);
        }
#endif
        list_append(&psar->lsackcache, &newack->frame.node);
    }
    return;
}
static inline void reliable_ack_unsave (supeer_t *psar)
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
        if (frees->frame.srclen == sizeof(SA6)) {
            SA6 * p6src = (SA6*)&frees->frame.srcaddr;
            char ip6buff[INET6_ADDRSTRLEN];
            inet_ntop(PF_INET6, &p6src->sin6_addr, ip6buff, sizeof(ip6buff));
            LOG_MSG("peer 0x%x time %u key(%s:%d:%d)" ColorRed " -ACK cache %p" ColorEnd,
                    psar, frees->ts, ip6buff, ntohs(((SA4*)&frees->frame.srcaddr)->sin_port),
                    frees->frame.recvhdr.seq, frees);
        } else {
            LOG_MSG("peer 0x%x time %u key(%s:%d:%d)" ColorRed " -ACK cache %p" ColorEnd,
                    psar, frees->ts, inet_ntoa(((SA4*)&frees->frame.srcaddr)->sin_addr),
                    ntohs(((SA4*)&frees->frame.srcaddr)->sin_port),
                    frees->frame.recvhdr.seq, frees);
        }
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
        LOG_MSG("peer 0x%x free frames_t node " ColorRed "%p" ColorEnd, psar, realnode);
#endif

    }
}

void request_handle(supeer_t *psar)
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
#ifdef SU_DEBUG_PEER_RECV
            LOG_MSG("peer 0x%x recv request type unknown %d", psar, phdr->type);
#endif
            free(frame);
            return;
    }
#if defined SU_DEBUG_PEER_RECV || defined SU_DEBUG_LIST
    log_msg("peer 0x%x delete syn "ColorRed"%p"ColorEnd" seq %d datagram len %d",
            psar, frame, phdr->seq, frame->len);
#endif
    free(frame);
}

static void *thread_request_handle(void *v)
{
    supeer_t *psar = (supeer_t*)v;
    struct list *synnode;
    frames_t *frame;

    int ret;
    struct timespec abstime = {0};

    for (;psar->run;) {
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
        frame = container_of(synnode, frames_t, node);

        rb_key_cache_t key;
        memcpy(&key.destaddr, &frame->srcaddr, frame->srclen);
        key.destlen = frame->srclen;
        key.seq = frame->recvhdr.seq;

        struct rb_node *cachenode;
        cache_t *cache;

        /* If multi-threaded processing request, protect the nowsynframe */
        pthread_mutex_lock(&psar->cachelock);

        reliable_ack_unsave(psar);

        if (frame->recvhdr.type == SU_RELIABLE &&
                (cachenode = rb_search(&psar->rbackcache, &key))) {
            cache = rb_entry(cachenode, cache_t, rbn);

#ifdef SU_DEBUG_RBTREE
            LOG_MSG("peer 0x%x "ColorRed"finded ack cache %p" ColorEnd " time %u %s:%d:%d",
                    psar, cache, cache->ts, inet_ntoa(((SA4*)&cache->frame.srcaddr)->sin_addr),
                    ntohs(((SA4*)&cache->frame.srcaddr)->sin_port), cache->frame.recvhdr.seq);
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
                ERR_RET("retransmit sendmsg to %s:%d:%u:%u error",
                        inet_ntoa(((SA4*)&frame->srcaddr)->sin_addr),
                        ntohs(((SA4*)&frame->srcaddr)->sin_port),
                        frame->recvhdr.seq, frame->recvhdr.ts);
            } 
#ifdef SU_DEBUG_PEER_RESEND
            else {
                log_msg("retransmit sendmsg to %s:%d:%u:%u",
                        inet_ntoa(((SA4*)&frame->srcaddr)->sin_addr),
                        ntohs(((SA4*)&frame->srcaddr)->sin_port),
                        frame->recvhdr.seq, frame->recvhdr.ts);
            }
#endif
            free(frame);
            pthread_mutex_unlock(&psar->cachelock);
            continue;
        }

        psar->nowsynframe = frame;
        request_handle(psar);
        psar->nowsynframe = 0;
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
    //pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    psar->run = 1;
    if ((errno = pthread_create(&psar->tid, &attr,
                    thread_request_handle, psar)) != 0) {
        pthread_attr_destroy(&attr);
        return (-1);
    }

    pthread_attr_destroy(&attr);

    return 0;
}

int su_peer_reliable_request_handle_install(supeer_t *psar,
        cb_supeer_recv_t* reliable_request_handle)
{
    int ret;

    pthread_mutex_lock(&psar->lock);
    psar->reliable_request_handle = reliable_request_handle;
    ret = thread_install(psar);
    pthread_mutex_unlock(&psar->lock);

    return ret;
}
int su_peer_ordinary_request_handle_install(supeer_t *psar,
        cb_supeer_recv_t* ordinary_request_handle)
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

static void handle_su_peer_recv(fe_t * fe)
{
    int ret;
    SA4 addr;
    socklen_t socklen = sizeof(SA4);
    supeer_t *psar = container_of(fe, supeer_t, fe);
    struct iovec    iovrecv[2] = {{0}}; /* assumed init to 0 */
    struct msghdr   msgrecv = {0};  /* assumed init to 0 */
    frames_t *frame;
recvagain:
    frame = calloc(1, sizeof(frames_t) + REALDATAMAX);
    if (frame == 0) {
        log_msg("peer 0x%x ENOMEM", psar);
        /* reject datagram */
        ret = recvfrom(fe->fd, rejectbuff, sizeof(rejectbuff), 0, (SA*)&addr, &socklen);
        if (ret < 0 && errno == EAGAIN) {
            return;
        }
#ifdef SU_DEBUG_PEER_RECV
        ERR_RET("peer 0x%x %d recv %s:%d bytes %d, but reject datas", psar,
                fe->fd, inet_ntoa(addr.sin_addr), ntohs(addr.sin_port), ret);
#endif
        return;
    }

    frame->srclen       = sizeof(SA4);

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

    if (ret <= sizeof(suhdr_t)) {
#ifdef SU_DEBUG_PEER_RECV
        errno = EBADMSG;
        err_ret("peer 0x%x recv %s:%d raw bytes %d less than the protocol header %d", psar,
                inet_ntoa(((SA4*)&frame->srcaddr)->sin_addr),
                ntohs(((SA4*)&frame->srcaddr)->sin_port), ret, sizeof(suhdr_t));
#endif
        free(frame);
        goto recvagain;
    }

#ifdef SU_DEBUG_PEER_RECV
    log_msg("peer 0x%x recv %s:%d raw bytes %d", psar,
            inet_ntoa(((SA4*)&frame->srcaddr)->sin_addr),
            ntohs(((SA4*)&frame->srcaddr)->sin_port), ret);
#endif

    suhdr_t *r = &frame->recvhdr;
    uint8_t act  = r->act;
    uint8_t type = r->type;

    frame->len = ret - sizeof(suhdr_t);

    SA4 *psrc, *pdst;
    psrc = (SA4*)&frame->srcaddr;
    pdst = (SA4*)&psar->destaddr;

#ifndef promiscuous_mode
    /*  Filter: Check address and port
     *  compare datagram source and peer destination */
    if( psrc->sin_addr.s_addr != pdst->sin_addr.s_addr
            || psrc->sin_port != pdst->sin_port ) {
#ifdef SU_DEBUG_PEER_RECV
        log_msg(ColorYel"peer 0x%x reject act[0x%02x] from %s:%d datagram len %d"ColorEnd,
                r->act,psar, inet_ntoa(psrc->sin_addr), ntohs(psrc->sin_port), frame->len);
#endif
        free(frame);
        goto recvagain;
    }
#endif /* #ifndef promiscuous_mode */

    pthread_mutex_lock(&psar->lock);
    if (act == SU_SYN) {
        if (!psar->run) {
            pthread_mutex_unlock(&psar->lock);
            free(frame);
            goto recvagain;
        }
#if defined SU_DEBUG_PEER_RECV || defined SU_DEBUG_LIST
        log_msg("peer 0x%x append syn "ColorRed"%p"ColorEnd" seq %d datagram len %d",
                psar, frame, r->seq, frame->len);
#endif
        list_append(&psar->synrecvls, &frame->node);
        pthread_cond_broadcast(&psar->syncond);

    } else if (act == SU_ACK && type == SU_RELIABLE) {
#ifdef promiscuous_mode
        /* Filter: receive response from self request */
        if( psrc->sin_addr.s_addr != pdst->sin_addr.s_addr
                || psrc->sin_port != pdst->sin_port ) {
#ifdef SU_DEBUG_PEER_RECV
            log_msg(ColorYel "peer 0x%x reject ack from %s:%d datagram len %d" ColorEnd, psar,
                    inet_ntoa(psrc->sin_addr), ntohs(psrc->sin_port), frame->len);
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
        log_msg("peer 0x%x append ack "ColorRed"%p"ColorEnd" seq %d datagram len %d",
                psar, frame, r->seq, frame->len);
#endif
        list_append(&psar->ackrecvls, &frame->node);
        pthread_cond_broadcast(&psar->ackcond);

    } else {
        pthread_mutex_unlock(&psar->lock);
#ifdef SU_DEBUG_PEER_RECV
        errno = EBADMSG;
        err_ret("peer 0x%x recv %s:%d raw bytes %d protocol format error", psar,
                inet_ntoa(((SA4*)&frame->srcaddr)->sin_addr),
                ntohs(((SA4*)&frame->srcaddr)->sin_port), ret);
#endif
        free(frame);
        return;

    }
    pthread_mutex_unlock(&psar->lock);

    goto recvagain;
}

int su_peer_create_bind(supeer_t *psar, int port, const SA *destaddr, socklen_t destlen)
{
    psar->fd = socket(destaddr->sa_family, SOCK_DGRAM, 0);
    if (psar->fd < 0) {
        err_ret("peer 0x%x create failed, socket error", psar);
        return -1;
    }

    if (port > 0 && port <= 65535) {
        void *paddr;
        SA4 s4;
        SA6 s6;
        if (destlen == sizeof(SA4)) {
            memcpy(&s4, destaddr, destlen);  /* for sin_family and more... */
            s4.sin_port = htons(port);
            inet_pton(PF_INET, "0.0.0.0", &s4.sin_addr.s_addr);
            paddr = &s4;
        } else if (destlen == sizeof(SA6)) {
            memcpy(&s6, destaddr, destlen); /* for sin6_family and more...  */
            s6.sin6_port = htons(port);
            inet_pton(PF_INET6, "::", &s6.sin6_addr.__in6_u); // Uncorroborated
            paddr = &s6;
        } else {
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

    pthread_mutex_init(&psar->mutex, 0);
    pthread_mutex_init(&psar->lock, 0);
    pthread_cond_init(&psar->ackcond, 0);
    pthread_cond_init(&psar->syncond, 0);
    pthread_mutex_init(&psar->cachelock, 0);

    psar->tid = 0;
    psar->run = 0;
    psar->nowsynframe = 0;
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
    fe_set(&psar->fe, EPOLLIN, handle_su_peer_recv);
    fe_set(&psar->fe, EPOLLET, 0);
    Fe_em_add(&psar->fe);

    return psar->fd;
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

    // unfinished ...
}

static int su_peer_send_act(supeer_t *psar, const void *outbuff, int outbytes)
{
    int			n;
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

static int su_peer_send_recv_act(supeer_t *psar,
        const void *outbuff, int outbytes,
        void *inbuff, int inbytes, int retransmit)
{
    int			n;
    struct iovec	iovsend[2]={{0}};
    struct msghdr	msgsend = {0};	    /* assumed init to 0 */
    suhdr_t *r, sendhdr = {0};          /* protocol header */
    int ret, waitsec;

    struct list *node = 0;
    frames_t *packet = 0;

    pthread_mutex_lock(&psar->mutex);
    pthread_mutex_lock(&psar->lock);
    if (psar->rttinit == 0) {
        rtt_init(&psar->rttinfo, psar->retry); /* first time we're called */
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
            log_msg("peer 0x%x no found seq %d ack, timed wait again", psar, sendhdr.seq);
#endif
            goto timedwaitagain;
        }

        /* Find response packet node */
        list_remove(&packet->node);

        n = packet->len;
        precvhdr = &packet->recvhdr;

#if defined SU_DEBUG_PEER_RECV || defined SU_DEBUG_LIST
        log_msg("peer 0x%x finded ack " ColorRed "%p" ColorEnd " seq %d datagram len %d",
                psar, packet, r->seq, packet->len);
#endif

#ifdef	SU_DEBUG_RTT
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
    log_msg("peer 0x%x free node  " ColorRed "%p"ColorEnd" seq %d", psar, packet, sendhdr.seq);
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

static int su_peer_reply_act(supeer_t *psar,
        const void *outbuff, int outbytes)
{
    if (psar->nowsynframe == 0) {
        err_msg("peer 0x%x is no request data");
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

    n = sendmsg(psar->fd, &msgsend, 0);
    if (n != sizeof(suhdr_t) + outbytes)
        return(-1);

    if (answerhdr.type == SU_RELIABLE)
        reliable_ack___save(psar, outbuff, outbytes);

    return(outbytes);
}
int su_peer_getsrcaddr_act(supeer_t *psar, SA *addr, socklen_t *addrlen)
{
    if (psar->nowsynframe == 0) {
        err_msg("peer 0x%x is no request source");
        return -1;
    }
    memcpy(addr, &psar->nowsynframe->srcaddr, psar->nowsynframe->srclen);
    *addrlen = psar->nowsynframe->srclen;
    return 0;
}

int su_peer_reply(supeer_t *psar, const void *outbuff, int outbytes)
{
    if (outbytes > REALDATAMAX) { errno = EMSGSIZE; return -1; }
    if (outbytes <= 0 || outbuff == 0) { errno = EINVAL; return -1;}
    return su_peer_reply_act(psar, outbuff, outbytes);
}

int su_peer_send(supeer_t *psar, const void *outbuff, int outbytes)
{
    if (outbytes > REALDATAMAX) { errno = EMSGSIZE; return -1; }
    if (outbytes <= 0 || outbuff == 0) { errno = EINVAL; return -1;}
    return su_peer_send_act(psar, outbuff, outbytes);
}

int su_peer_request(supeer_t *psar, const void *outbuff, int outbytes,
        void *inbuff, int inbytes)
{
    if (outbytes > REALDATAMAX) { errno = EMSGSIZE; return -1; }
    if (outbytes <= 0 || outbuff == 0) { errno = EINVAL; return -1;}
    if (inbytes  <= 0 || inbuff== 0) { errno = EINVAL; return -1;}
    return su_peer_send_recv_act(psar, outbuff, outbytes, inbuff, inbytes, 0);
}

int su_peer_request_retry(supeer_t *psar, const void *outbuff, int outbytes,
        void *inbuff, int inbytes)
{
    if (outbytes > REALDATAMAX) { errno = EMSGSIZE; return -1; }
    if (outbytes <= 0 || outbuff == 0) { errno = EINVAL; return -1;}
    if (inbytes  <= 0 || inbuff== 0) { errno = EINVAL; return -1;}
    return su_peer_send_recv_act(psar, outbuff, outbytes, inbuff, inbytes, 1);
}
int su_peer_getsrcaddr(supeer_t *psar, SA *addr, socklen_t *addrlen)
{
    if (addr == 0 || addrlen == 0) { errno = EINVAL; return -1;}
    return su_peer_getsrcaddr_act(psar, addr, addrlen);
}

