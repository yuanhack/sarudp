#include "sarudp.h"

#include "yherror.h"
#include "yhevent.h"
#include "yhservice.h"
#include "yhtime.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>

#define ColorRed    "\e[31m"
#define ColorGre    "\e[32m"
#define ColorYel    "\e[33m"
#define ColorBlue   "\e[34m"
#define ColorEnd    "\e[m"

pthread_mutex_t emutex = PTHREAD_MUTEX_INITIALIZER;
em_t * sugem = 0;
char rejectbuff[1024*10] = {0};

static void save_reliable_ack (supeer_t *psar, const void *outbuff, size_t outbytes)
{
    cache_t * newack = calloc(1, sizeof(cache_t) + outbytes);
    if (newack == 0)
        return;
    time(&newack->ts);
    memcpy(&newack->pack, &psar->synnowpack, sizeof(frames_t));
    memcpy(newack->pack.data, outbuff, outbytes);
    newack->pack.len = outbytes;
    list_append(&psar->lsackcache, &newack->pack.node);
#ifdef SU_DEBUG_LIST
    LOG_MSG("peer %x add cache %p time %u", psar, newack, newack->ts);
#endif
    return;
}
static void check_rm_reliable_ack (supeer_t *psar)
{
    time_t t;

    time(&t);
    cache_t *frees, *cache = container_of 
        ( list_head(&psar->lsackcache, frames_t, node), cache_t, pack );

    while ( &psar->lsackcache != &cache->pack.node ) {
        if ( abs(t-cache->ts) < CACHETIMEOUT ) break;
        frees = cache;
        cache = container_of 
            ( list_next(&cache->pack, frames_t, node), cache_t, pack );
        list_remove(&frees->pack.node);
#ifdef SU_DEBUG_LIST
        LOG_MSG("peer %x free cache_t node " ColorRed "%p" ColorEnd " timeout[%u %u]", 
                psar, frees, t, frees->ts+CACHETIMEOUT);
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
            LOG_MSG("peer %x request type unknown %d", (uint64_t)pthread_self(), phdr->type);
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
            maketimeout_seconds(&abstime, 10);
            ret = pthread_cond_timedwait(&psar->syncond, &psar->lock, &abstime);
            if ( ret == ETIMEDOUT ) {
                check_rm_reliable_ack(psar);
            }
        }
        list_remove(synnode);
        pthread_mutex_unlock(&psar->lock);

        check_rm_reliable_ack(psar);

        // TODO: Have a request
        packet = container_of(synnode, frames_t, node);
        phdr = &packet->recvhdr;

        psar->synnowpack = packet;
        request_handle(psar);
        psar->synnowpack = 0;
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

int reliable_request_handle_install(supeer_t *psar,
        cb_supeer_receiver_t* reliable_request_handle)
{
    int ret;

    pthread_mutex_lock(&psar->lock);
    psar->reliable_request_handle = reliable_request_handle;
    ret = thread_install(psar);
    pthread_mutex_unlock(&psar->lock);

    return ret;
}
int ordinary_request_handle_install(supeer_t *psar,
        cb_supeer_receiver_t* ordinary_request_handle)
{
    int ret;

    pthread_mutex_lock(&psar->lock);
    psar->ordinary_request_handle = ordinary_request_handle;
    ret = thread_install(psar);
    pthread_mutex_unlock(&psar->lock);

    return ret;
}
void reliable_request_handle_uninstall(supeer_t *psar)
{
}
void ordinary_request_handle_uninstall(supeer_t *psar)
{
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

#ifdef SU_DEBUG_PEER_RECV
    log_msg("peer %x recv %s:%d raw bytes %d", psar,
            inet_ntoa(((SA4*)&packet->srcaddr)->sin_addr),
            ntohs(((SA4*)&packet->srcaddr)->sin_port), ret);
#endif

    if (ret <= sizeof(suhdr_t)) {
#ifdef SU_DEBUG_PEER_RECV
        errno = EBADMSG;
        err_ret("peer %x recv %s:%d raw bytes %d", psar,
                inet_ntoa(((SA4*)&packet->srcaddr)->sin_addr),
                ntohs(((SA4*)&packet->srcaddr)->sin_port), ret);
#endif
        free(packet);
        goto recvagain;
    }

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
        err_ret("peer %x recv %s:%d raw bytes %d", psar,
                inet_ntoa(((SA4*)&packet->srcaddr)->sin_addr),
                ntohs(((SA4*)&packet->srcaddr)->sin_port), ret);
#endif
        free(packet);
        return;

    }
    pthread_mutex_unlock(&psar->lock);

    goto recvagain;
}

int su_peer_new(supeer_t *psar,
        const SA *ptoaddr, socklen_t servlen)
{
    psar->fd = socket(ptoaddr->sa_family, SOCK_DGRAM, 0);
    if (psar->fd < 0) {
#ifdef SU_DEBUG_PEER
        ERR_RET("peer %x create failed, socket error", psar);
#endif
        return -1;
    }

    Setfd_nonblock(psar->fd);

    memcpy(&psar->destaddr, ptoaddr, servlen);
    psar->destlen = servlen;

    psar->seq = 0;
    psar->rttinit = 0;
    psar->retry = 2; //RTT_MAXNREXMT;

    psar->ackwaitnum = 0;
    list_init(&psar->ackrecvls);
    list_init(&psar->synrecvls);
    list_init(&psar->lsackcache);

    pthread_mutex_init(&psar->lock, 0);
    pthread_cond_init(&psar->ackcond, 0);
    pthread_cond_init(&psar->syncond, 0);

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

void su_peer_rm(supeer_t *psar)
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

ssize_t su_peer_send_act(supeer_t *psar, const void *outbuff, size_t outbytes)
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

ssize_t su_peer_send_recv_act(supeer_t *psar, const void *outbuff, size_t outbytes,
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

static ssize_t
su_peer_reply_act(supeer_t *psar, const void *outbuff, size_t outbytes)
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
        save_reliable_ack(psar, outbuff, outbytes);

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

