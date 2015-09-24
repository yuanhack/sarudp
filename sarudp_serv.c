#include "sarudp_serv.h"

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

static inline void reliable_ack___save (suserv_t *psvr, const frames_t *frame,
        const void *outbuff, int outbytes)
{
    cache_t * newack = calloc(1, sizeof(cache_t) + outbytes);
    if (newack == 0)
        return;
    time(&newack->ts);
    memcpy(&newack->frame, frame, sizeof(frames_t));
    memcpy(newack->frame.data, outbuff, outbytes);
    newack->frame.len = outbytes;

    /* Adding associated */
    if (rb_insert(&psvr->rbackcache, &newack->rbn) < 0) {
#if defined SU_DEBUG_LIST || defined SU_DEBUG_RBTREE 
        pthread_t tid = pthread_self();
        SA6 * p6src = (SA6*)&newack->frame.srcaddr;
        if (newack->frame.srclen == sizeof(SA6)) {
            char ip6buff[INET6_ADDRSTRLEN];
            inet_ntop(PF_INET6, &p6src->sin6_addr, ip6buff, sizeof(ip6buff));
            log_msg("serv %x %x time %u key(%s:%d:%d)" ColorRed " +ACK cache %p failed" ColorEnd ,
                    psvr, tid, newack->ts, ip6buff, ntohs(((SA4*)&newack->frame.srcaddr)->sin_port),
                    newack->frame.recvhdr.seq, newack);
        } else {
            log_msg("serv %x %x time %u key(%s:%d:%d)" ColorRed " +ACK cache %p failed" ColorEnd ,
                    psvr, tid, newack->ts, inet_ntoa(((SA4*)&newack->frame.srcaddr)->sin_addr),
                    ntohs(((SA4*)&newack->frame.srcaddr)->sin_port),newack->frame.recvhdr.seq, 
                    newack);
        }

#endif
        free(newack);
        return;
    } else {
#if defined SU_DEBUG_LIST || defined SU_DEBUG_RBTREE 
        pthread_t tid = pthread_self();
        SA6 * p6src = (SA6*)&newack->frame.srcaddr;
        if (newack->frame.srclen == sizeof(SA6)) {
            char ip6buff[INET6_ADDRSTRLEN];
            inet_ntop(PF_INET6, &p6src->sin6_addr, ip6buff, sizeof(ip6buff));
            log_msg("serv %x %x time %u key(%s:%d:%d)" ColorRed " +ACK cache %p" ColorEnd ,
                    psvr, tid, newack->ts, ip6buff, ntohs(((SA4*)&newack->frame.srcaddr)->sin_port),
                    newack->frame.recvhdr.seq, newack);
        } else {
            log_msg("serv %x %x time %u key(%s:%d:%d)" ColorRed " +ACK cache %p" ColorEnd ,
                    psvr, tid, newack->ts, inet_ntoa(((SA4*)&newack->frame.srcaddr)->sin_addr),
                    ntohs(((SA4*)&newack->frame.srcaddr)->sin_port),newack->frame.recvhdr.seq, 
                    newack);
        }

#endif
        list_append(&psvr->lsackcache, &newack->frame.node);
    }
    return;
}
static inline void reliable_ack_unsave (suserv_t *psvr)
{
    time_t nowtime;

    cache_t *frees, *cache = container_of 
        ( list_head(&psvr->lsackcache, frames_t, node), cache_t, frame );

    time(&nowtime);

    while ( &psvr->lsackcache != &cache->frame.node ) {
        if ( abs(nowtime - cache->ts) < CACHETIMEOUT ) break;
        frees = cache;
        cache = container_of
            ( list_next(&cache->frame, frames_t, node), cache_t, frame );

        /* Disconnect associated */
        list_remove(&frees->frame.node);
        rb_erase(&frees->rbn, &psvr->rbackcache);
#if defined SU_DEBUG_LIST || defined SU_DEBUG_RBTREE 
        pthread_t tid = pthread_self();
        if (frees->frame.srclen == sizeof(SA6)) {
            SA6 * p6src = (SA6*)&frees->frame.srcaddr;
            char ip6buff[INET6_ADDRSTRLEN];
            inet_ntop(PF_INET6, &p6src->sin6_addr, ip6buff, sizeof(ip6buff));
            log_msg("serv %x %x time %u key(%s:%d:%d)" ColorRed " -ACK cache %p" ColorEnd,
                    psvr, tid, frees->ts, ip6buff, ntohs(((SA4*)&frees->frame.srcaddr)->sin_port),
                    frees->frame.recvhdr.seq, frees);
        } else {
            log_msg("serv %x %x time %u key(%s:%d:%d)" ColorRed " -ACK cache %p" ColorEnd,
                    psvr, tid, frees->ts, inet_ntoa(((SA4*)&frees->frame.srcaddr)->sin_addr),
                    ntohs(((SA4*)&frees->frame.srcaddr)->sin_port),
                    frees->frame.recvhdr.seq, frees);
        }
#endif
        free(frees);
    }
}
static inline void su_serv_list_empty(suserv_t *psvr, struct list *l)
{
    frames_t *realnode;
    struct list *node = l->next;

    while ( node != l ) {
        list_remove(node);
        realnode = container_of(node, frames_t, node);
        node = node->next;
        free(realnode);

#ifdef SU_DEBUG_LIST
        log_msg("serv %x free frames_t node " ColorRed "%p" ColorEnd, psvr, realnode);
#endif

    }
}

void request_handle(suserv_t *psvr, frames_t * frame)
{
    suhdr_t *phdr = &frame->recvhdr;
    pthread_t tid = pthread_self();

    switch (phdr->type) {
        case SU_RELIABLE:
            if (psvr->reliable_request_handle) {
                psvr->reliable_request_handle(psvr, frame, (char*)frame->data, frame->len);
            } break;
        case SU_ORDINARY:
            if (psvr->ordinary_request_handle) {
                psvr->ordinary_request_handle(psvr, frame, (char*)frame->data, frame->len);
            } break;
        default:
            LOG_MSG("serv %x %x recv request type unknown %d", psvr, tid, phdr->type);
            free(frame);
            return;
    }
#if defined SU_DEBUG_PEER_RECV || defined SU_DEBUG_LIST
    log_msg("serv %x %x delete syn "ColorRed"%p"ColorEnd" seq %d datagram len %d",
            psvr, tid, frame, phdr->seq, frame->len);
#endif
    free(frame);
}

static void *thread_request_handle(void *v)
{
    suserv_t *psvr = (suserv_t*)v;
    struct list *synnode;
    frames_t *frame;

    int ret;
    struct timespec abstime = {0};

    for (;psvr->run;) {
        pthread_mutex_lock(&psvr->lock);
        while ((synnode = psvr->synrecvls.next) == &psvr->synrecvls) {
            maketimeout_seconds(&abstime, 1);
            ret = pthread_cond_timedwait(&psvr->syncond, &psvr->lock, &abstime);
            if ( ret == ETIMEDOUT ) {
                pthread_mutex_lock(&psvr->cachelock);
                reliable_ack_unsave(psvr);
                pthread_mutex_unlock(&psvr->cachelock);
            }
        }
        list_remove(synnode);
        pthread_mutex_unlock(&psvr->lock);

        /* have request datagram */
        frame = container_of(synnode, frames_t, node);

        rb_key_cache_t key;
        memcpy(&key.destaddr, &frame->srcaddr, frame->srclen);
        key.destlen = frame->srclen;
        key.seq = frame->recvhdr.seq;

        struct rb_node *cachenode;
        cache_t *cache;

        pthread_mutex_lock(&psvr->cachelock);
        reliable_ack_unsave(psvr);
        if (frame->recvhdr.type == SU_RELIABLE &&
                (cachenode = rb_search(&psvr->rbackcache, &key))) {
            cache = rb_entry(cachenode, cache_t, rbn);

#ifdef SU_DEBUG_RBTREE
            pthread_t tid = pthread_self();
            if (cache->frame.srclen == sizeof(SA6)) {
                SA6 * p6src = (SA6*)&cache->frame.srcaddr;
                char ip6buff[INET6_ADDRSTRLEN];
                inet_ntop(PF_INET6, &p6src->sin6_addr, ip6buff, sizeof(ip6buff));
                log_msg("serv %x %x time %u key(%s:%d:%d)" ColorRed " @ACK cache %p" ColorEnd,
                        psvr,tid,cache->ts, ip6buff, ntohs(((SA4*)&cache->frame.srcaddr)->sin_port),
                        cache->frame.recvhdr.seq, cache);
            } else {
                log_msg("serv %x %x time %u key(%s:%d:%d)" ColorRed " @ACK cache %p" ColorEnd ,
                        psvr,tid,cache->ts, inet_ntoa(((SA4*)&cache->frame.srcaddr)->sin_addr),
                        ntohs(((SA4*)&cache->frame.srcaddr)->sin_port), 
                        cache->frame.recvhdr.seq, cache);
            }
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

            /* resend from cache */
            if (sendmsg(psvr->fd, &msgsend, 0) != sizeof(suhdr_t) + cache->frame.len) {
                if (cache->frame.srclen == sizeof(SA6)) {
                    SA6 * p6src = (SA6*)&cache->frame.srcaddr;
                    char ip6buff[INET6_ADDRSTRLEN];
                    inet_ntop(PF_INET6, &p6src->sin6_addr, ip6buff, sizeof(ip6buff));
                    ERR_RET("retransmit sendmsg to %s:%d:%u:%u error",
                            ip6buff, ntohs(((SA4*)&frame->srcaddr)->sin_port),
                            frame->recvhdr.seq, frame->recvhdr.ts);
                } else {
                    ERR_RET("retransmit sendmsg to %s:%d:%u:%u error",
                            inet_ntoa(((SA4*)&frame->srcaddr)->sin_addr),
                            ntohs(((SA4*)&frame->srcaddr)->sin_port),
                            frame->recvhdr.seq, frame->recvhdr.ts);
                }
            } 
#ifdef SU_DEBUG_PEER_RESEND
            else {
                if (cache->frame.srclen == sizeof(SA6)) {
                    SA6 * p6src = (SA6*)&cache->frame.srcaddr;
                    char ip6buff[INET6_ADDRSTRLEN];
                    inet_ntop(PF_INET6, &p6src->sin6_addr, ip6buff, sizeof(ip6buff));
                    log_msg("retransmit sendmsg to %s:%d:%u:%u",
                            ip6buff, ntohs(((SA4*)&frame->srcaddr)->sin_port),
                            frame->recvhdr.seq, frame->recvhdr.ts);
                } else {
                    log_msg("retransmit sendmsg to %s:%d:%u:%u",
                            inet_ntoa(((SA4*)&frame->srcaddr)->sin_addr),
                            ntohs(((SA4*)&frame->srcaddr)->sin_port),
                            frame->recvhdr.seq, frame->recvhdr.ts);
                }
            }
#endif
            free(frame);
            pthread_mutex_unlock(&psvr->cachelock);
            continue;
        }
        pthread_mutex_unlock(&psvr->cachelock);
        request_handle(psvr, frame);
    }

    return (void*)0;
}

static int thread_install(void *v)
{
    suserv_t *psvr = (suserv_t*)v;

    if (psvr->run) 
        return 0;

    pthread_attr_t attr;

    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 1024*1024); //set stack size 1M
    //pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    int i, n, ret;
    psvr->run = 1;
    for (n = 0; n < psvr->tnum; n++) {
        if ((ret = pthread_create(&psvr->tid[n], &attr,
                        thread_request_handle, psvr)) != 0) {
            psvr->run = 0;
            void *retr;
            for (i = 0; i < n; i++) {
                errno = pthread_join(psvr->tid[i], &retr);
                if (errno != 0)
                    err_sys("serv %x can't join with thread %x error");
                log_msg("serv %x join with thread %x code %d", psvr, psvr->tid[i], ret);
            }

            pthread_attr_destroy(&attr);

            psvr->run = 0;
            errno = ret;
            return (-1);
        }
        log_msg("serv %x create thread %x successfully", psvr, psvr->tid[n]);
    }

    pthread_attr_destroy(&attr);

    return 0;
}

void su_serv_reliable_request_handle_install(suserv_t *psvr,
        cb_su_serv_receiver_t* reliable_request_handle)
{
    pthread_mutex_lock(&psvr->lock);
    psvr->reliable_request_handle = reliable_request_handle;
    pthread_mutex_unlock(&psvr->lock);
}
void su_serv_ordinary_request_handle_install(suserv_t *psvr,
        cb_su_serv_receiver_t* ordinary_request_handle)
{
    pthread_mutex_lock(&psvr->lock);
    psvr->ordinary_request_handle = ordinary_request_handle;
    pthread_mutex_unlock(&psvr->lock);
}
void su_serv_reliable_request_handle_uninstall(suserv_t *psvr)
{
    pthread_mutex_lock(&psvr->lock);
    psvr->reliable_request_handle = 0;
    pthread_mutex_unlock(&psvr->lock);
}
void su_serv_ordinary_request_handle_uninstall(suserv_t *psvr)
{
    pthread_mutex_lock(&psvr->lock);
    psvr->ordinary_request_handle = 0;
    pthread_mutex_unlock(&psvr->lock);
}

static void handle_su_serv_recv4(fe_t * fe)
{
    int ret;
    SAUN saddr;
    SA4 addr;
    socklen_t socklen = sizeof(SA4);
    suserv_t *psvr = container_of(fe, suserv_t, fe);
    struct iovec    iovrecv[2] = {{0}}; /* assumed init to 0 */
    struct msghdr   msgrecv = {0};  /* assumed init to 0 */
    frames_t *frame;
recvagain:
    frame = calloc(1, sizeof(frames_t) + REALDATAMAX);
    if (frame == 0) {
        log_msg("serv %x ENOMEM", psvr);
        /* reject datagram */
        ret = recvfrom(fe->fd, rejectbuff, sizeof(rejectbuff), 0, (SA*)&addr, &socklen);
        if (ret < 0 && errno == EAGAIN) {
            return;
        }
#ifdef SU_DEBUG_PEER_RECV
        ERR_RET("serv %x %d recv %s:%d bytes %d, but reject datas", psvr,
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
        err_ret("serv %x recv %s:%d raw bytes %d less than the protocol header %d", psvr,
                inet_ntoa(((SA4*)&frame->srcaddr)->sin_addr),
                ntohs(((SA4*)&frame->srcaddr)->sin_port), ret, sizeof(suhdr_t));
#endif
        free(frame);
        goto recvagain;
    }

#ifdef SU_DEBUG_PEER_RECV
    log_msg("serv %x recv %s:%d raw bytes %d", psvr,
            inet_ntoa(((SA4*)&frame->srcaddr)->sin_addr),
            ntohs(((SA4*)&frame->srcaddr)->sin_port), ret);
#endif

    suhdr_t *r = &frame->recvhdr;
    uint8_t act  = r->act;
    uint8_t type = r->type;

    frame->len = ret - sizeof(suhdr_t);

//    SA4 *psrc, *pdst;
//    psrc = (SA4*)&frame->srcaddr;
//    pdst = (SA4*)&psvr->destaddr;

    pthread_mutex_lock(&psvr->lock);
    if (act == SU_SYN) {
        if (!psvr->run) {
            pthread_mutex_unlock(&psvr->lock);
            free(frame);
            goto recvagain;
        }
#if defined SU_DEBUG_PEER_RECV || defined SU_DEBUG_LIST
        log_msg("serv %x append syn "ColorRed"%p"ColorEnd" seq %d datagram len %d",
                psvr, frame, r->seq, frame->len);
#endif
        list_append(&psvr->synrecvls, &frame->node);
        pthread_cond_broadcast(&psvr->syncond);

    } else if (act == SU_ACK && type == SU_RELIABLE) {
        if (psvr->ackwaitnum <= 0) {
            pthread_mutex_unlock(&psvr->lock);
            free(frame);
            goto recvagain;
        }
#if defined SU_DEBUG_PEER_RECV || defined SU_DEBUG_LIST
        log_msg("serv %x append ack "ColorRed"%p"ColorEnd" seq %d datagram len %d",
                psvr, frame, r->seq, frame->len);
#endif
        list_append(&psvr->ackrecvls, &frame->node);
        pthread_cond_broadcast(&psvr->ackcond);

    } else {
        pthread_mutex_unlock(&psvr->lock);
#ifdef SU_DEBUG_PEER_RECV
        errno = EBADMSG;
        err_ret("serv %x recv %s:%d raw bytes %d protocol format error", psvr,
                inet_ntoa(((SA4*)&frame->srcaddr)->sin_addr),
                ntohs(((SA4*)&frame->srcaddr)->sin_port), ret);
#endif
        free(frame);
        return;

    }
    pthread_mutex_unlock(&psvr->lock);

    goto recvagain;
}

int su_serv_create(suserv_t *psvr, int nthread, const SA *saddr, socklen_t servlen)
{
    if (nthread <= 0) {
        errno = EINVAL;
        return -1;
    }
    psvr->fd = socket(saddr->sa_family, SOCK_DGRAM, 0);
    if (psvr->fd < 0) {
        err_ret("serv %x create failed, socket error", psvr);
        return -1;
    }
    if (bind(psvr->fd, saddr, servlen) < 0) {
        close(psvr->fd);
        psvr->fd = -1;
        return -1;
    }
    if (setfd_nonblock(psvr->fd) < 0) {
        close(psvr->fd);
        psvr->fd = -1;
        return -1;
    }

    memcpy(&psvr->servaddr, saddr, servlen);
    psvr->servlen = servlen;

    psvr->seq = 0;
    psvr->rttinit = 0;
    psvr->retry = RTT_MAXNREXMT;

    psvr->ackwaitnum = 0;
    list_init(&psvr->ackrecvls);
    list_init(&psvr->synrecvls);
    list_init(&psvr->lsackcache);
    rbt_init(&psvr->rbackcache, cache_getkey, search_cache_cmp);

    pthread_mutex_init(&psvr->mutex, 0);
    pthread_mutex_init(&psvr->lock, 0);
    pthread_mutex_init(&psvr->cachelock, 0);
    pthread_cond_init(&psvr->ackcond, 0);
    pthread_cond_init(&psvr->syncond, 0);

    psvr->tid = calloc(nthread, sizeof(pthread_t));
    psvr->tnum = nthread;
    psvr->run = 0;
    psvr->reliable_request_handle = 0;
    psvr->ordinary_request_handle = 0;

    if (thread_install(psvr) < 0) {
        pthread_mutex_destroy(&psvr->mutex);
        pthread_mutex_destroy(&psvr->lock);
        pthread_mutex_destroy(&psvr->cachelock);
        pthread_cond_destroy(&psvr->ackcond);
        pthread_cond_destroy(&psvr->syncond);
        close(psvr->fd);
        psvr->fd = -1;
        return -1;
    }


    pthread_mutex_lock(&emutex);
    if (sugem == 0) {
        sugem = Em_open(100, -1, 0, 0, 0);
        Em_run(sugem);
    }
    pthread_mutex_unlock(&emutex);

    memset(&psvr->fe, 0, sizeof(fe_t));
    fe_init(&psvr->fe, sugem, psvr->fd);
    fe_set(&psvr->fe, EPOLLIN, handle_su_serv_recv4);
    fe_set(&psvr->fe, EPOLLET, 0);
    Fe_em_add(&psvr->fe);

    return psvr->fd;
}

void su_serv_destroy(suserv_t *psvr)
{
    if (psvr->fd >= 0) {
        close(psvr->fd);
        psvr->fd = -1;
        return;
    }

    int i, err;
    psvr->run = 0;
    void *ret;
    for (i = 0; i < psvr->tnum; i++) {
        errno = pthread_join(psvr->tid[i], &ret);
        if (errno != 0)
            err_sys("serv %x can't join with thread %x error");
        log_msg("serv %x join with thread %x code %d", psvr, psvr->tid[i], ret);
    }

    pthread_mutex_destroy(&psvr->mutex);
    pthread_mutex_destroy(&psvr->lock);
    pthread_mutex_destroy(&psvr->cachelock);
    pthread_cond_destroy(&psvr->ackcond);
    pthread_cond_destroy(&psvr->syncond);
    close(psvr->fd);
    psvr->fd = -1;

    // unfinished ...



    return;
}

static int su_serv_reply_act(suserv_t *psvr, const frames_t *frame,
        const void *outbuff, int outbytes)
{
    int			n;
    struct iovec	iovsend[2] = {{0}};
    struct msghdr	msgsend = {0};	/* assumed init to 0 */
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

    n = sendmsg(psvr->fd, &msgsend, 0);
    if (n != sizeof(suhdr_t) + outbytes)
        return(-1);

    if (answerhdr.type == SU_RELIABLE) {
        pthread_mutex_lock(&psvr->cachelock);
        reliable_ack___save(psvr, frame, outbuff, outbytes);
        pthread_mutex_unlock(&psvr->cachelock);
    }

    return(outbytes);
}
static int su_serv_send_act(suserv_t *psar, SA *destaddr, socklen_t destlen, const void *outbuff, int outbytes)
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
    msgsend.msg_name = (void*)destaddr;
    msgsend.msg_namelen = destlen;
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
static int su_serv_send_recv_act(suserv_t *psar, SA *destaddr, socklen_t destlen,
        const void *outbuff, int outbytes, void *inbuff, int inbytes, int retransmit)
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
    msgsend.msg_name = (void*)destaddr;
    msgsend.msg_namelen = destlen;
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
        ERR_RET("su_serv_send_recv_act sendmsg error");
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
            log_msg("serv %x no found seq %d ack, timed wait again", psar, sendhdr.seq);
#endif
            goto timedwaitagain;
        }

        /* Find response packet node */
        list_remove(&packet->node);

        n = packet->len;
        precvhdr = &packet->recvhdr;

#if defined SU_DEBUG_PEER_RECV || defined SU_DEBUG_LIST
        log_msg("serv %x finded ack " ColorRed "%p" ColorEnd " seq %d datagram len %d",
                psar, packet, r->seq, packet->len);
#endif

#ifdef	SU_DEBUG_RTT
        fprintf(stderr, ColorRed "recv seq %4d \n" ColorEnd, precvhdr->seq);
#endif
        // SU_RELIABLE received response, copy to user buffer
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
        ERR_RET(" su_serv_send_recv_act unknown error[%d]", ret);
        goto error_ret;
    }

    /* calculate & store new RTT estimator values */
    rtt_stop(&psar->rttinfo, rtt_ts(&psar->rttinfo) - precvhdr->ts);

    if (--psar->ackwaitnum == 0) {
        su_serv_list_empty(psar, &psar->ackrecvls);
    }
    pthread_mutex_unlock(&psar->mutex);
    pthread_mutex_unlock(&psar->lock);

#ifdef SU_DEBUG_LIST
    log_msg("serv %x free node  " ColorRed "%p"ColorEnd" seq %d", psar, packet, sendhdr.seq);
#endif

    free(packet);

    return(n);	/* return size of received datagram */

error_ret:
    if (--psar->ackwaitnum == 0) {
        su_serv_list_empty(psar, &psar->ackrecvls);
    }
    pthread_mutex_unlock(&psar->mutex);
    pthread_mutex_unlock(&psar->lock);
    return(-1);
}
int su_serv_getsrcaddr_act(suserv_t *psvr, frames_t *frame, SA *addr, socklen_t *addrlen)
{
    memcpy(addr, &frame->srcaddr, frame->srclen);
    *addrlen = frame->srclen;
    return 0;
}

int su_serv_reply(suserv_t *psvr, frames_t *frame, const void *outbuff, int outbytes)
{
    if (outbytes > REALDATAMAX) { errno = EMSGSIZE; return -1; }
    if (outbytes <= 0 || ! outbuff || ! frame) { errno = EINVAL; return -1;}
    return su_serv_reply_act(psvr, frame, outbuff, outbytes);
}

int su_serv_getsrcaddr(suserv_t *psvr, frames_t *frame, SA *addr, socklen_t *addrlen)
{
    if (addr == 0 || addrlen == 0) { errno = EINVAL; return -1;}
    return su_serv_getsrcaddr_act(psvr, frame, addr, addrlen);
}

int su_serv_send(suserv_t *psar, SA* destaddr, socklen_t destlen, const void *outbuff, int outbytes)
{
    if (outbytes > REALDATAMAX) { errno = EMSGSIZE; return -1; }
    if (outbytes <= 0 || outbuff == 0) { errno = EINVAL; return -1;}
    return su_serv_send_act(psar, destaddr, destlen, outbuff, outbytes);
}

int su_serv_request(suserv_t *psar, SA *destaddr, socklen_t destlen,
        const void *outbuff, int outbytes, void *inbuff, int inbytes)
{
    if (outbytes > REALDATAMAX) { errno = EMSGSIZE; return -1; }
    if (outbytes <= 0 || outbuff == 0) { errno = EINVAL; return -1;}
    if (inbytes  <= 0 || inbuff== 0) { errno = EINVAL; return -1;}
    return su_serv_send_recv_act(psar, destaddr, destlen, outbuff, outbytes, inbuff, inbytes, 0);
}

int su_serv_request_retry(suserv_t *psar, SA *destaddr, socklen_t destlen,
        const void *outbuff, int outbytes, void *inbuff, int inbytes)
{
    if (outbytes > REALDATAMAX) { errno = EMSGSIZE; return -1; }
    if (outbytes <= 0 || outbuff == 0) { errno = EINVAL; return -1;}
    if (inbytes  <= 0 || inbuff== 0) { errno = EINVAL; return -1;}
    return su_serv_send_recv_act(psar, destaddr, destlen, outbuff, outbytes, inbuff, inbytes, 1);
}
