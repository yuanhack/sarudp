#include "sarudp.h"

#include "yherror.h"
#include "yhevent.h"
#include "yhservice.h"
#include "yhtime.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>

#define SkyBlue "\e[34m"
#define ColorE     "\e[m"

pthread_mutex_t emutex = PTHREAD_MUTEX_INITIALIZER;
em_t * sugem = 0;
char rejectbuff[1024*10] = {0};

void cb_peer_data_in(fe_t * fe)
{
    int ret;
    SA4 addr;
    socklen_t socklen = sizeof(SA4);
    supeer_t *psar = struct_entry(fe, supeer_t, fe);
    struct iovec    iovrecv[2] = {{0}}; /* assumed init to 0 */ 
    struct msghdr   msgrecv = {0};  /* assumed init to 0 */
    recv_stor_t *packet;

recvagain:
    packet = calloc(1, sizeof(recv_stor_t) + REALDATAMAX);
    if (packet == 0) {
        ret = recvfrom(fe->fd, rejectbuff, sizeof(rejectbuff), 0, (SA*)&addr, &socklen); // reject data
        if (ret < 0 && errno == EAGAIN) {
            return;
        }
#ifdef SU_DEBUG_PEER
        err_ret("peer %x %d recv %s:%d bytes %d, but reject datas", psar,
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
        err_quit("recvmsg error %s %d", __FILE__, __LINE__);
    }

#ifdef SU_DEBUG_PEER_RECV
    log_msg("peer %x %d recv %s:%d bytes %d", psar,
            fe->fd, inet_ntoa(((SA4*)&packet->srcaddr)->sin_addr), 
            ntohs(((SA4*)&packet->srcaddr)->sin_port), ret);
#endif

    if (ret <= sizeof(suhdr_t)) {
        free(packet);
        goto recvagain;
    }

    suhdr_t *r = &packet->recvhdr;
    uint8_t act  = r->act;
    uint8_t type = r->type;

    packet->len = ret - sizeof(suhdr_t);

    pthread_mutex_lock(&psar->lock);

    if (act == SU_ACK && type == SU_RELIABLE) {
        list_append(&psar->ackrecvls, &packet->node);
    } else if (act == SU_SYN) {
        list_append(&psar->synrecvls, &packet->node);
    } else {
        pthread_mutex_unlock(&psar->lock);
#ifdef SU_DEBUG_PEER_RECV
        log_msg("peer %x [%05d] recv %s:%d bytes %d is abnormal", psar,
                fe->fd, inet_ntoa(((SA4*)&packet->srcaddr)->sin_addr), 
                ntohs(((SA4*)&packet->srcaddr)->sin_port), ret);
#endif
        free(packet);
        return;
    }

    pthread_mutex_unlock(&psar->lock);

#ifdef SU_DEBUG_LIST
    log_msg("peer %x appd node \e[31m%p\e[m seq %d data len=%d", psar, packet, r->seq, packet->len);
#endif

    pthread_cond_broadcast(&psar->ackcond);
    goto recvagain;
}

int su_peer_new(supeer_t *psar, 
        const SA *ptoaddr, socklen_t servlen, cb_supeer_receiver_t* in)
{
    psar->fd = socket(ptoaddr->sa_family, SOCK_DGRAM, 0);
    if (psar->fd < 0) {
#ifdef SU_DEBUG_PEER
        err_ret("peer %x create failed, socket error", psar);
#endif
        return -1;
    }

    Setfd_nonblock(psar->fd);

    memcpy(&psar->destaddr, ptoaddr, servlen);
    psar->destlen = servlen;

    psar->seq = 0;
    psar->rttinit = 0;
    psar->retry = 2; //RTT_MAXNREXMT;

    psar->in = in;

    psar->ackwaitnum = 0;
    list_init(&psar->ackrecvls);
    list_init(&psar->synrecvls);

    pthread_mutex_init(&psar->lock, 0);
    pthread_cond_init(&psar->ackcond, 0);

    pthread_mutex_lock(&emutex);
    if (sugem == 0) {
        sugem = Em_open(100, -1, 0, 0, 0);
        Em_run(sugem);
    }
    pthread_mutex_unlock(&emutex);

    memset(&psar->fe, 0, sizeof(fe_t));
    fe_init(&psar->fe, sugem, psar->fd);
    fe_set(&psar->fe, EPOLLIN, cb_peer_data_in);
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

ssize_t su_peer_send_act(supeer_t *psar, const void *outbuff, size_t outbytes)
{
    ssize_t			n;
    struct iovec	iovsend[2] = {{0}};
    struct msghdr	msgsend = {0};	/* assumed init to 0 */
    suhdr_t sendhdr = {0};   /* SU_RELIABLE Request protocol head */

    pthread_mutex_lock(&psar->lock);
    sendhdr.act  = SU_SYN;
    sendhdr.type = SU_GENERAL;
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
    recv_stor_t *packet = 0;

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
        err_ret("su_peer_send_recv_act sendmsg error");
        goto error_ret;
    }

    waitsec = rtt_start(&psar->rttinfo);	/* calc timeout value & start timer */
#ifdef	RTT_DEBUG
    fprintf(stderr, "\e[31msend seq %4d: \e[m", sendhdr.seq);
    rtt_debug(&psar->rttinfo);
#endif

    /* set timed wait time-point */
    maketimeout_seconds(&abstime, waitsec);

#ifdef SU_DEBUG_TIMEVERBOSE
    struct timeval now;
    gettimeofday(&now, 0);
    //log_msg("\e[34mpthread_cond_timedwait : %u.%u time expire\e[m", abstime.tv_sec, abstime.tv_nsec);
    log_msg( SkyBlue "pthread_cond_timedwait : %u.%u time expire" ColorE, abstime.tv_sec, abstime.tv_nsec);
    log_msg( SkyBlue "pthread_cond_timedwait : %d.%d now time" ColorE, now.tv_sec, now.tv_usec*1000);
#endif

timedwaitagain:
    ret = pthread_cond_timedwait(&psar->ackcond, &psar->lock, &abstime);
    if (ret == 0) {
#ifdef SU_DEBUG_TIMEVERBOSE
        struct timeval now;
        gettimeofday(&now, 0);
        log_msg(SkyBlue "pthread_cond_timedwait : %d.%d ack cond interrupt" ColorE, 
                now.tv_sec, now.tv_usec*1000);
#endif
        node = psar->ackrecvls.next;
        for (; node != &psar->ackrecvls; node = node->next) {
            packet = struct_entry(node, recv_stor_t, node);
            r = &packet->recvhdr;

            if (su_cmp_ack_SU_RELIABLE(&sendhdr, r)) {
                break;
            }
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
        fprintf(stderr, "\e[31mrecv seq %4d \e[m\n", precvhdr->seq);
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
        log_msg(SkyBlue "pthread_cond_timedwait : %u.%u ETIMEOUT have expired" ColorE, 
                now.tv_sec, now.tv_usec*1000);
#endif
        if (rtt_timeout(&psar->rttinfo) < 0) {
            err_msg("\e[33mno response from server, giving up\e[m");
            psar->rttinit = 0;	/* reinit in case we're called again */
            errno = ETIMEDOUT;
            goto error_ret;
        }
#ifdef	RTT_DEBUG
        err_msg("\e[31m     seq %4d timeout, retransmitting\e[m", sendhdr.seq);
#endif
        goto sendagain;
    } else {
        errno = ret;
        err_ret(" su_peer_send_recv_act unknown error[%d]");
        goto error_ret;
    }

    /* calculate & store new RTT estimator values */
    rtt_stop(&psar->rttinfo, rtt_ts(&psar->rttinfo) - precvhdr->ts);

    //void su_peer_list_empty(struct list *l);
    void su_peer_list_empty(supeer_t *su, struct list *l);

    if (--psar->ackwaitnum == 0) {
        su_peer_list_empty(psar, &psar->ackrecvls);
    }
    pthread_mutex_unlock(&psar->lock);

    free(packet);
#ifdef SU_DEBUG_LIST
    log_msg("peer %x free node \e[31m%p\e[m seq %d", psar, packet);
#endif

    return(n);	/* return size of received datagram */

error_ret:
    if (--psar->ackwaitnum == 0) {
        su_peer_list_empty(psar, &psar->ackrecvls);
    }
    pthread_mutex_unlock(&psar->lock);
    return(-1);
}

void su_peer_list_empty(supeer_t *su, struct list *l)
{
    recv_stor_t *realnode;
    struct list *node = l->next;
    while ( node != l ) {
        list_remove(node);
        realnode = struct_entry(node, recv_stor_t, node);
        node = node->next;
        free(realnode);
#ifdef SU_DEBUG_LIST
        //supeer_t *su = struct_entry(l, supeer_t, ackrecvls);
        log_msg("peer %x free recv_stor_t node \e[31m%p\e[m", su, realnode);
#endif
    } 
}

ssize_t su_peer_send_recv(supeer_t *psar, const void *outbuff, size_t outbytes,
        void *inbuff, size_t inbytes)
{
    return su_peer_send_recv_act(psar, outbuff, outbytes, inbuff, inbytes, 0);
}

ssize_t su_peer_send(supeer_t *psar, const void *outbuff, size_t outbytes)
{
    return su_peer_send_act(psar, outbuff, outbytes);
}

ssize_t su_peer_send_recv_retry(supeer_t *psar, const void *outbuff, size_t outbytes,
        void *inbuff, size_t inbytes)
{
    return su_peer_send_recv_act(psar, outbuff, outbytes, inbuff, inbytes, 1);
}

