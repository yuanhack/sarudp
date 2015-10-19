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

static inline int reliable_ack___hold(su_serv_t *psvr, const frames_t *frame)
{
    cache_t * newack;
    newack = calloc(1, sizeof(cache_t));
    if (newack == 0) {
        errno = ENOBUFS;
        return -1;
    }
    time(&newack->ts);
    memcpy(&newack->frame, frame, sizeof(frames_t));
    newack->frame.len = -1;

    /* Adding associated */
    if (rb_insert(&psvr->rbackcache, &newack->rbn) < 0) {
#if defined SU_DEBUG_LIST || defined SU_DEBUG_RBTREE 
        pthread_t tid = pthread_self();
        char ipbuff[INET6_ADDRSTRLEN];
        int port;
        su_get_ip_port_f(&newack->frame.srcaddr, ipbuff, sizeof(ipbuff), &port);
        log_msg("serv %x %x time %u key(%s:%d:%u:%u)" ColorRed " !ACK cache %p failed" ColorEnd ,
                psvr, tid, newack->ts, ipbuff, port,
                newack->frame.recvhdr.sid, newack->frame.recvhdr.seq, newack);
#endif
        free(newack);
        errno = EALREADY;
        return -1;
    } else {
#if defined SU_DEBUG_LIST || defined SU_DEBUG_RBTREE 
        pthread_t tid = pthread_self();
        char ipbuff[INET6_ADDRSTRLEN];
        int port;
        su_get_ip_port_f(&newack->frame.srcaddr, ipbuff, sizeof(ipbuff), &port);
        log_msg("serv %x %x time %u key(%s:%d:%u:%u)" ColorRed " !ACK cache %p" ColorEnd ,
                psvr, tid, newack->ts, ipbuff, port,
                newack->frame.recvhdr.sid, newack->frame.recvhdr.seq, newack);

#endif
        list_append(&psvr->lsackcache, &newack->frame.node);
    }
    return 0;
}
static inline int reliable_ack___save (su_serv_t *psvr,
        const frames_t *frame, const void *outbuff, int outbytes)
{
    /* Construct search key */
    rb_key_cache_t key;
    memcpy(&key.destaddr, &frame->srcaddr, sizeof(SAUN));
    key.destlen = frame->srclen;
    key.seq = frame->recvhdr.seq;
    key.sid = frame->recvhdr.sid;

    struct rb_node *cachenode;
    cache_t *cache;

    /* If is no reply content, only replace len value, don't replace node 
     * If have a content, must allocating and replacing new node */
    if (outbuff == 0 && outbytes == 0) {
        if ((cachenode = rb_search(&psvr->rbackcache, &key))) {
            cache = rb_entry(cachenode, cache_t, rbn);
            cache->frame.len = 0;
#if defined SU_DEBUG_LIST || defined SU_DEBUG_RBTREE
            pthread_t tid = pthread_self();
            char ipbuff[INET6_ADDRSTRLEN];
            int port;
            su_get_ip_port_f(&cache->frame.srcaddr, ipbuff, sizeof(ipbuff), &port);
            log_msg("serv %x %x time %u key(%s:%d:%u:%u) "
                    ColorRed "+ACK cache %p" ColorEnd ,
                    psvr, tid, cache->ts, ipbuff, port,
                    cache->frame.recvhdr.sid, cache->frame.recvhdr.seq, cache);
#endif
            return 0;
        }
        errno = ENOKEY;
        return -1;
    }

    cache_t * newack;
    newack = calloc(1, sizeof(cache_t) + outbytes);
    if (newack == 0) {
        errno = ENOBUFS;
        return -1;
    }

    /* Construct a new node */
    memcpy(&newack->frame, frame, sizeof(frames_t));
    memcpy(newack->frame.data, outbuff, outbytes);
    newack->frame.len = outbytes;

    /* Find and replace the hold node */
    if ((cachenode = rb_search(&psvr->rbackcache, &key))) {
        rb_replace_node(cachenode, &newack->rbn, &psvr->rbackcache);
        cache = rb_entry(cachenode, cache_t, rbn);
        newack->ts = cache->ts;
        list_remove(&cache->frame.node);
        list_append(&psvr->lsackcache, &newack->frame.node);
#if defined SU_DEBUG_LIST || defined SU_DEBUG_RBTREE
        pthread_t tid = pthread_self();
        char ipbuff[INET6_ADDRSTRLEN];
        int port;
        su_get_ip_port_f(&newack->frame.srcaddr, ipbuff, sizeof(ipbuff), &port);
        log_msg("serv %x %x time %u key(%s:%d:%u:%u) "
                ColorRed "+ACK cache %p Swap %p" ColorEnd ,
                psvr, tid, newack->ts, ipbuff, port,
                frame->recvhdr.sid, frame->recvhdr.seq, cache, newack);
#endif
        free(cache);
        return 0;
    }
    free(newack);
    errno = ENOKEY;
    return -1;
}
static inline void reliable_ack_unsave (su_serv_t *psvr)
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
        char ipbuff[INET6_ADDRSTRLEN];
        int port;
        su_get_ip_port_f(&frees->frame.srcaddr, ipbuff, sizeof(ipbuff), &port);
        log_msg("serv %x %x time %u key(%s:%d:%u:%u)" ColorRed " -ACK cache %p" ColorEnd,
                psvr, tid, frees->ts, ipbuff, port,
                frees->frame.recvhdr.sid, frees->frame.recvhdr.seq, frees);
#endif
        free(frees);
    }
}
static inline void su_serv_list_empty(su_serv_t *psvr, struct list *l)
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

void request_handle(su_serv_t *psvr, frames_t * frame)
{
    suhdr_t *phdr = &frame->recvhdr;
    pthread_t tid;

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
            tid = pthread_self();
            LOG_MSG("serv %x %x recv request type unknown %d", psvr, tid, phdr->type);
            return;
    }
}

static void *thread_request_handle(void *v)
{
    int ret;
    struct list *synnode;
    struct timespec abstime = {0};
    frames_t *frame;
    su_serv_t *psvr = (su_serv_t*)v;

    pthread_t tid __attribute__((unused)) = pthread_self();

    for (;psvr->run;) {
        pthread_mutex_lock(&psvr->lock);
        while ((synnode = psvr->synrecvls.next) == &psvr->synrecvls) {
            maketimeout_seconds(&abstime, 1);
            ret = pthread_cond_timedwait(&psvr->syncond, &psvr->lock, &abstime);
            if (!psvr->run) { 
                pthread_mutex_unlock(&psvr->lock);
                goto quit;
            }
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
        memcpy(&key.destaddr, &frame->srcaddr, sizeof(SAUN));
        key.destlen = frame->srclen;
        key.seq = frame->recvhdr.seq;
        key.sid = frame->recvhdr.sid;

        struct rb_node *cachenode;
        cache_t *cache;

        pthread_mutex_lock(&psvr->cachelock);
        reliable_ack_unsave(psvr);
        if (frame->recvhdr.type == SU_RELIABLE) {
            if ( (cachenode = rb_search(&psvr->rbackcache, &key))) {
                cache = rb_entry(cachenode, cache_t, rbn);

                if (cache->frame.len == -1) {
#ifdef SU_DEBUG_RBTREE
                    char ipbuff[INET6_ADDRSTRLEN];
                    int port;
                    su_get_ip_port_f(&cache->frame.srcaddr, ipbuff, sizeof(ipbuff), &port);
                    log_msg("serv %x %x time %u key(%s:%d:%u:%u)"
                            ColorRed " 0ACK cache %p" ColorEnd,
                            psvr, tid, cache->ts, ipbuff, port,
                            cache->frame.recvhdr.sid, cache->frame.recvhdr.seq, cache);
#endif
                    pthread_mutex_unlock(&psvr->cachelock);
                    free(frame);
                    continue;
                }

#ifdef SU_DEBUG_RBTREE
                char ipbuff[INET6_ADDRSTRLEN];
                int port;
                su_get_ip_port_f(&cache->frame.srcaddr, ipbuff, sizeof(ipbuff), &port);
                log_msg("serv %x %x time %u key(%s:%d:%u:%u)"
                        ColorRed " @ACK cache %p" ColorEnd,
                        psvr, tid, cache->ts, ipbuff, port,
                        cache->frame.recvhdr.sid, cache->frame.recvhdr.seq, cache);
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
                    char ipbuff[INET6_ADDRSTRLEN];
                    int port;
                    su_get_ip_port_f(&cache->frame.srcaddr, ipbuff, sizeof(ipbuff), &port);
                    ERR_RET("retransmit sendmsg %s:%d:%u:%u:%u error",
                            ipbuff, port,
                            frame->recvhdr.seq, frame->recvhdr.ts,
                            frame->recvhdr.sid);
                }
#ifdef SU_DEBUG_PEER_RESEND
                else {
                    char ipbuff[INET6_ADDRSTRLEN];
                    int port;
                    su_get_ip_port_f(&cache->frame.srcaddr, ipbuff, sizeof(ipbuff), &port);
                    log_msg("retransmit sendmsg %s:%d:%u:%u:%u",
                            ipbuff, port,
                            frame->recvhdr.seq, frame->recvhdr.ts,
                            frame->recvhdr.sid);
                }
#endif
                pthread_mutex_unlock(&psvr->cachelock);
                free(frame);
                continue;
            } else {
                if (reliable_ack___hold(psvr, frame) < 0) {
                    err_ret("reliable_ack___hold error");
                    pthread_mutex_unlock(&psvr->cachelock);
                    free(frame);
                    continue;
                }
            }
        }
        pthread_mutex_unlock(&psvr->cachelock);
        request_handle(psvr, frame);
#if defined SU_DEBUG_PEER_RECV || defined SU_DEBUG_LIST
        log_msg("serv %x %x delete syn "ColorRed"%p"ColorEnd" seq %d datagram len %d",
                psvr, tid, frame, frame->recvhdr.seq, frame->len);
#endif
        free(frame);
    }

quit:
    pthread_exit(0);
}

static int su_serv_thread_install(su_serv_t *psvr, int nthread)
{
    int i, n;
    void *retr;
    pthread_attr_t attr;

    psvr->tids = calloc(nthread, sizeof(pthread_t));
    if ( !psvr->tids ) return -1;

    psvr->run  = 0;
    psvr->tnum = 0;
    psvr->reliable_request_handle = 0;
    psvr->ordinary_request_handle = 0;

    /* Set stack size 1M */
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 1024*1024);

    for (n = 0; n < nthread; n++) {
        errno = pthread_create (&psvr->tids[n], &attr, thread_request_handle, psvr);
        if (errno != 0) {
            err_ret("serv %x pthread_create[%d] error", n);
            for (i = 0; i < n; i++) {
                errno = pthread_join(psvr->tids[i], &retr);
                if (errno != 0)
                    err_sys("serv %x join with thread %x error");
            }
            pthread_attr_destroy(&attr);
            free(psvr->tids);
            return (-1);
        }
        log_msg("serv %x create thread[%d] %x success", psvr, n, psvr->tids[n]);
    }
    pthread_attr_destroy(&attr);
    psvr->run  = 1;
    psvr->tnum = nthread;
    return 0;
}
static int su_serv_thread_uninstall(su_serv_t *psvr)
{
    int i;
    void *ret;

    psvr->run = 0;
    for (i = 0; i < psvr->tnum; i++) {
        errno = pthread_join(psvr->tids[i], &ret);
        if (errno != 0)
            err_sys("serv %x can't join with thread %x error");
        log_msg("serv %x join with thread %x code %d", psvr, psvr->tids[i], ret);
    }
    free(psvr->tids);
    return 0;
}

void su_serv_reliable_request_handle_install(su_serv_t *psvr,
        cb_su_serv_receiver_t* reliable_request_handle)
{
    pthread_mutex_lock(&psvr->lock);
    psvr->reliable_request_handle = reliable_request_handle;
    pthread_mutex_unlock(&psvr->lock);
}
void su_serv_ordinary_request_handle_install(su_serv_t *psvr,
        cb_su_serv_receiver_t* ordinary_request_handle)
{
    pthread_mutex_lock(&psvr->lock);
    psvr->ordinary_request_handle = ordinary_request_handle;
    pthread_mutex_unlock(&psvr->lock);
}
void su_serv_reliable_request_handle_uninstall(su_serv_t *psvr)
{
    pthread_mutex_lock(&psvr->lock);
    psvr->reliable_request_handle = 0;
    pthread_mutex_unlock(&psvr->lock);
}
void su_serv_ordinary_request_handle_uninstall(su_serv_t *psvr)
{
    pthread_mutex_lock(&psvr->lock);
    psvr->ordinary_request_handle = 0;
    pthread_mutex_unlock(&psvr->lock);
}

static void handle_su_serv_recv(fe_t * fe)
{
    int ret;
    char ipbuff[INET6_ADDRSTRLEN];
    int  port;
    SAUN saddr;
    socklen_t socklen;
    su_serv_t *psvr = container_of(fe, su_serv_t, fe);
    struct iovec    iovrecv[2] = {{0}}; /* assumed init to 0 */
    struct msghdr   msgrecv = {0};  /* assumed init to 0 */
    frames_t *frame;
recvagain:
    socklen = sizeof(SA6);
    frame = calloc(1, sizeof(frames_t) + REALDATAMAX);
    if (frame == 0) {
        errno = ENOBUFS; // ENOMEM
        err_ret("serv %x ENOBUFS", psvr);
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
                log_msg("serv %x reject unknown protocol raw bytes %d", psvr, ret);
                goto recvagain;
        };
        ERR_RET("serv %x %d recv %s:%d bytes %d, but reject datas", psvr,
                fe->fd, ipbuff, port, ret);
#endif
        return;
    }

    frame->srclen       = psvr->servlen;

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
            log_msg("serv %x reject unknown protocol raw bytes %d", psvr, ret);
            free(frame);
            goto recvagain;
    };

    if (ret < sizeof(suhdr_t)) {
#ifdef SU_DEBUG_PEER_RECV
        errno = EBADMSG;
        err_ret("serv %x recv %s:%d raw bytes %d less-then head %d bytes",
                psvr, ipbuff, port, ret, sizeof(suhdr_t));
#endif
        free(frame);
        goto recvagain;
    }

#ifdef SU_DEBUG_PEER_RECV
    log_msg("serv %x recv %s:%d raw bytes %d", psvr,
            ipbuff, port, ret);
#endif

    suhdr_t *r = &frame->recvhdr;
    uint8_t act  = r->act;
    uint8_t type = r->type;

    frame->len = ret - sizeof(suhdr_t);

    pthread_mutex_lock(&psvr->lock);
    if (act == SU_SYN && frame->len > 0) {
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
        errno = EPROTO;
        err_ret("serv %x recv %s:%d raw bytes %d", psvr,
                ipbuff, port, ret);
#endif
        free(frame);
        return;

    }
    pthread_mutex_unlock(&psvr->lock);

    goto recvagain;
}

int su_serv_create(su_serv_t *psvr, const SA *saddr, socklen_t servlen, int nthread)
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

    memset(&psvr->servaddr, 0, sizeof(SAUN));
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
    pthread_cond_init(&psvr->ackcond, 0);
    pthread_cond_init(&psvr->syncond, 0);
    pthread_mutex_init(&psvr->cachelock, 0);

    if (su_serv_thread_install(psvr, nthread) < 0) {
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

        struct timeval now;
        gettimeofday(&now, 0);
        srand(now.tv_sec % 1000 + now.tv_usec);
    }
    psvr->sid = rand() % 65535;
    pthread_mutex_unlock(&emutex);

    memset(&psvr->fe, 0, sizeof(fe_t));
    fe_init(&psvr->fe, sugem, psvr->fd);
    fe_set(&psvr->fe, EPOLLIN, handle_su_serv_recv);
    fe_set(&psvr->fe, EPOLLET, 0);
    Fe_em_add(&psvr->fe);

    return psvr->fd;
}

void su_serv_destroy(su_serv_t *psvr)
{
    su_serv_thread_uninstall(psvr);

    pthread_mutex_destroy(&psvr->mutex);
    pthread_mutex_destroy(&psvr->lock);
    pthread_mutex_destroy(&psvr->cachelock);
    pthread_cond_destroy(&psvr->ackcond);
    pthread_cond_destroy(&psvr->syncond);

    close(psvr->fd);
    psvr->fd = -1;

    su_serv_list_empty(psvr, &psvr->ackrecvls);
    su_serv_list_empty(psvr, &psvr->synrecvls);

    cache_t *frees, *cache = container_of 
        ( list_head(&psvr->lsackcache, frames_t, node), cache_t, frame );

    while ( &psvr->lsackcache != &cache->frame.node ) {
        frees = cache;
        cache = container_of
            ( list_next(&cache->frame, frames_t, node), cache_t, frame );

        /* Disconnect associated And Cleanup All */
        list_remove(&frees->frame.node);
        rb_erase(&frees->rbn, &psvr->rbackcache);
#if defined SU_DEBUG_LIST || defined SU_DEBUG_RBTREE 
        char ipbuff[INET6_ADDRSTRLEN];
        int port;
        su_get_ip_port_f(&frees->frame.srcaddr, ipbuff, sizeof(ipbuff), &port);
        log_msg("serv %x time %u key(%s:%d:%u:%u)" ColorRed " _ACK cache %p" ColorEnd,
                psvr, frees->ts, ipbuff, port,
                frees->frame.recvhdr.sid, frees->frame.recvhdr.seq, frees);
#endif
        free(frees);
    }

    LOG_MSG("serv %x finish destroyed", psvr);
}

static int su_serv_reply_act(su_serv_t *psvr, const frames_t *frame,
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

    if (answerhdr.type == SU_RELIABLE) {
        pthread_mutex_lock(&psvr->cachelock);
        if (reliable_ack___save(psvr, frame, outbuff, outbytes) < 0) {
            pthread_mutex_unlock(&psvr->cachelock);
            err_ret("reliable_ack___save error");
            return -1;
        }
        pthread_mutex_unlock(&psvr->cachelock);
    }

    n = sendmsg(psvr->fd, &msgsend, 0);
    if (n != sizeof(suhdr_t) + outbytes) {
        err_ret("sendmsg error");
        return(-1);
    }

    return(outbytes);
}
static int su_serv_send_act(su_serv_t *psvr, SA *destaddr, socklen_t destlen, const void *outbuff, int outbytes)
{
    int			n;
    struct iovec	iovsend[2] = {{0}};
    struct msghdr	msgsend = {0};	/* assumed init to 0 */
    suhdr_t sendhdr = {0};   /* SU_RELIABLE Request protocol head */

    pthread_mutex_lock(&psvr->lock);
    sendhdr.act  = SU_SYN;
    sendhdr.type = SU_ORDINARY;
    sendhdr.seq = ++psvr->seq;
    sendhdr.ts = 0;
    msgsend.msg_name = (void*)destaddr;
    msgsend.msg_namelen = destlen;
    msgsend.msg_iov = &iovsend[0];
    msgsend.msg_iovlen = 2;

    iovsend[0].iov_base = &sendhdr;
    iovsend[0].iov_len = sizeof(suhdr_t);
    iovsend[1].iov_base = (void*)outbuff;
    iovsend[1].iov_len = outbytes;

    n = sendmsg(psvr->fd, &msgsend, 0);
    pthread_mutex_unlock(&psvr->lock);

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
static int su_serv_send_recv_act(su_serv_t *psvr, SA *destaddr, socklen_t destlen,
        const void *outbuff, int outbytes, void *inbuff, int inbytes, int retransmit)
{
    int             n;
    struct iovec    iovsend[2]={{0}};
    struct msghdr   msgsend = {0};	    /* assumed init to 0 */
    suhdr_t *r, sendhdr = {0};          /* protocol header */
    int ret, waitsec;

    struct list *node = 0;
    frames_t *packet = 0;

    pthread_mutex_lock(&psvr->mutex);
    pthread_mutex_lock(&psvr->lock);

    if (retransmit == 0) {
        psvr->seq++;
        psvr->retransmission = 1;
    } else {
        if (psvr->retransmission == 0) {
            pthread_mutex_unlock(&psvr->mutex);
            pthread_mutex_unlock(&psvr->lock);
            errno = ETIMEDOUT;
            return -1;
        }
        psvr->retransmission --;
    }

    if (psvr->rttinit == 0) {
        rtt_init(&psvr->rttinfo, psvr->retry); /* first time we're called */
        psvr->rttinit = 1;
    }

    sendhdr.act  = SU_SYN;
    sendhdr.type = SU_RELIABLE;
    sendhdr.sid  = psvr->sid;
    sendhdr.seq  = psvr->seq;
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

    rtt_newpack(&psvr->rttinfo);		/* initialize for this packet */
    psvr->ackwaitnum ++;

sendagain:
    sendhdr.ts = rtt_ts(&psvr->rttinfo);
    if (sendmsg(psvr->fd, &msgsend, 0) < 0) {
        ERR_RET("sendmsg error");
        goto error_ret;
    }

    waitsec = rtt_start(&psvr->rttinfo);	/* calc timeout value & start timer */
#ifdef	SU_DEBUG_RTT
    fprintf(stderr, ColorRed "send seq %4d: " ColorEnd, sendhdr.seq);
    rtt_debug(&psvr->rttinfo);
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
    ret = pthread_cond_timedwait(&psvr->ackcond, &psvr->lock, &abstime);
    if (ret == 0) {
#ifdef SU_DEBUG_TIMEVERBOSE
        struct timeval now;
        gettimeofday(&now, 0);
        log_msg(ColorBlue "pthread_cond_timedwait : %d.%d ack cond interrupt" ColorEnd,
                now.tv_sec, now.tv_usec*1000);
#endif
        node = psvr->ackrecvls.next;
        for (; node != &psvr->ackrecvls; node = node->next) {
            packet = container_of(node, frames_t, node);
            r = &packet->recvhdr;
            if (su_cmp_ack_SU_RELIABLE(&sendhdr, r)) { break; }
        }
        if ( node == &psvr->ackrecvls ) {
            /* Be careful of the lock, locked -> timedwait -> unlock */
#ifdef SU_DEBUG_LIST
            log_msg("serv %x no found seq %d ack, timed wait again", psvr, sendhdr.seq);
#endif
            goto timedwaitagain;
        }

        /* Find response packet node */
        list_remove(&packet->node);

        n = packet->len;
        precvhdr = &packet->recvhdr;

#if defined SU_DEBUG_PEER_RECV || defined SU_DEBUG_LIST
        log_msg("serv %x finded ack " ColorRed "%p" ColorEnd " seq %d datagram len %d",
                psvr, packet, r->seq, packet->len);
#endif

#ifdef	SU_DEBUG_RTT
        fprintf(stderr, ColorRed "recv seq %4d \n" ColorEnd, precvhdr->seq);
#endif
        // SU_RELIABLE received response, copy to user buffer
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
        if (rtt_timeout(&psvr->rttinfo) < 0) {
#ifdef	SU_DEBUG_RTT
            err_msg(ColorYel "no response from server, giving up" ColorEnd);
#endif
            psvr->rttinit = 0;	/* reinit in case we're called again */
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
    rtt_stop(&psvr->rttinfo, rtt_ts(&psvr->rttinfo) - precvhdr->ts);

    if (--psvr->ackwaitnum == 0) {
        su_serv_list_empty(psvr, &psvr->ackrecvls);
    }
    pthread_mutex_unlock(&psvr->mutex);
    pthread_mutex_unlock(&psvr->lock);

#ifdef SU_DEBUG_LIST
    log_msg("serv %x free node  " ColorRed "%p"ColorEnd" seq %d", psvr, packet, sendhdr.seq);
#endif

    free(packet);

    return(n);	/* return size of received datagram */

error_ret:
    if (--psvr->ackwaitnum == 0) {
        su_serv_list_empty(psvr, &psvr->ackrecvls);
    }
    pthread_mutex_unlock(&psvr->mutex);
    pthread_mutex_unlock(&psvr->lock);
    return(-1);
}

int su_serv_reply(su_serv_t *psvr, frames_t *frame, const void *outbuff, int outbytes)
{
    if (psvr == 0 || frame == 0) { errno = EINVAL; return -1; }
    if (outbytes > REALDATAMAX) { errno = EMSGSIZE; return -1; }
    if (    (outbytes <  0) ||
            (outbytes == 0 &&  outbuff) ||
            (outbytes >  0 && !outbuff)    )
    { errno = EINVAL; return -1; }
    return su_serv_reply_act(psvr, frame, outbuff, outbytes);
}
int su_serv_reply_ack(su_serv_t *psvr, frames_t *frame)
{
    if (psvr == 0 || frame == 0) { errno = EINVAL; return -1; }
    return su_serv_reply_act(psvr, frame, 0, 0);
}

int su_serv_send(su_serv_t *psvr, SA* destaddr, socklen_t destlen, const void *outbuff, int outbytes)
{
    if (psvr == 0) { errno = EINVAL; return -1; }
    if (outbytes > REALDATAMAX) { errno = EMSGSIZE; return -1; }
    if (outbytes <= 0 || outbuff == 0) { errno = EINVAL; return -1;}
    return su_serv_send_act(psvr, destaddr, destlen, outbuff, outbytes);
}

int su_serv_request(su_serv_t *psvr, SA *destaddr, socklen_t destlen,
        const void *outbuff, int outbytes, void *inbuff, int inbytes)
{
    if (psvr == 0) { errno = EINVAL; return -1; }
    if (outbytes > REALDATAMAX) { errno = EMSGSIZE; return -1; }
    if (outbytes <= 0 || outbuff == 0) { errno = EINVAL; return -1;}
    if (inbytes  <= 0 || inbuff== 0) { errno = EINVAL; return -1;}
    return su_serv_send_recv_act(psvr, destaddr, destlen, outbuff, outbytes, inbuff, inbytes, 0);
}

int su_serv_request_retry(su_serv_t *psvr, SA *destaddr, socklen_t destlen,
        const void *outbuff, int outbytes, void *inbuff, int inbytes)
{
    if (psvr == 0) { errno = EINVAL; return -1; }
    if (outbytes > REALDATAMAX) { errno = EMSGSIZE; return -1; }
    if (outbytes <= 0 || outbuff == 0) { errno = EINVAL; return -1;}
    if (inbytes  <= 0 || inbuff== 0) { errno = EINVAL; return -1;}
    return su_serv_send_recv_act(psvr, destaddr, destlen, outbuff, outbytes, inbuff, inbytes, 1);
}
