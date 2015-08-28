#include "sarudp.h"
#include "yherror.h"
#include "yhevent.h"
#include "yhservice.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>

void peer_data_in(fd_event * fe)
{
    char buf[1024] = {0};
    struct sockaddr_in sa;
    socklen_t len = sizeof(struct sockaddr_in);
    supeer_t *psar = struct_entry(fe, supeer_t, fe);
    int ret = recvfrom( fe->fd, buf, sizeof(buf), 0, (struct sockaddr*)&sa, &len);
    log_msg("udp server [%05d] recv %s:%d bytes %d %s", fe->fd,
            inet_ntoa(sa.sin_addr), ntohs(sa.sin_port),
            ret, buf+10);
}


int su_peer_new(supeer_t *psar, const SA *ptoaddr, socklen_t servlen, sarudpin* in)
{
    psar->fd = socket(ptoaddr->sa_family, SOCK_DGRAM, 0);
    if (psar->fd < 0) 
        return -1;

    Setfd_nonblock(psar->fd);

    memcpy(&psar->destaddr, ptoaddr, servlen);
    memset(&psar->sendhdr, 0, sizeof(struct hdr));
    memset(&psar->recvhdr, 0, sizeof(struct hdr));
    memset(&psar->fe, 0, sizeof(fd_event_t));

    psar->destlen = servlen;
    psar->rttinit = 0;
    psar->sendhdr.seq = 0;
    psar->in = in;

    pthread_mutex_init(&psar->lock, 0);
    pthread_cond_init(&psar->cond, 0);

    psar->pem = Em_open(1, -1, 0, 0, 0);

    fd_event_init(&psar->fe, psar->pem, psar->fd);
    fd_event_set(&psar->fe, EPOLLIN, peer_data_in);
    Em_fd_event_add(&psar->fe);
    Em_run(psar->pem);

    return 0;
}

void serudp_peer_rm(supeer_t *psar)
{
    if (psar->fd >= 0) { 
        close(psar->fd); 
        psar->fd = -1; 
        return;
    }
    pthread_mutex_destroy(&psar->lock);
    pthread_cond_destroy(&psar->cond);
}

ssize_t su_peer_send_act(supeer_t *psar, const void *outbuff, size_t outbytes)
{
    ssize_t			n;
    struct iovec	iovsend[2] = {{0}};
    struct msghdr	msgsend = {0};	/* assumed init to 0 */

    pthread_mutex_lock(&psar->lock);
    psar->sendhdr.flag = 0;
    psar->sendhdr.type = SU_GENERAL;
    psar->sendhdr.seq++;
    msgsend.msg_name = (void*)&psar->destaddr;
    msgsend.msg_namelen = psar->destlen;
    msgsend.msg_iov = &iovsend[0];
    msgsend.msg_iovlen = 2;

    iovsend[0].iov_base = &psar->sendhdr;
    iovsend[0].iov_len = sizeof(struct hdr);
    iovsend[1].iov_base = (void*)outbuff;
    iovsend[1].iov_len = outbytes;

    n = sendmsg(psar->fd, &msgsend, 0);
    pthread_mutex_unlock(&psar->lock);

    if (n != sizeof(struct hdr) + outbytes)
        return -1;
    return(outbytes);
}

ssize_t su_peer_send_recv_act(supeer_t *psar, const void *outbuff, size_t outbytes,
        void *inbuff, size_t inbytes, int retransmit)
{
    ssize_t			n;
    struct iovec	iovsend[2], iovrecv[2];
    struct msghdr	msgsend = {0}, msgrecv = {0};	/* assumed init to 0 */
    fd_set set;
    int ret, waitsec;

    rtt_d_flag = 1;

    pthread_mutex_lock(&psar->lock);
    if (psar->rttinit == 0) {
        rtt_init(&psar->rttinfo);       /* first time we're called */
        psar->rttinit = 1;
    }

    if (retransmit == 0)
        psar->sendhdr.seq++;
    psar->sendhdr.flag = 0;
    psar->sendhdr.type = SU_RELIABLE;
    msgsend.msg_name = (void*)&psar->destaddr;
    msgsend.msg_namelen = psar->destlen;
    msgsend.msg_iov = iovsend;
    msgsend.msg_iovlen = 2;

    iovsend[0].iov_base = &psar->sendhdr;
    iovsend[0].iov_len = sizeof(struct hdr);
    iovsend[1].iov_base = (void*)outbuff;
    iovsend[1].iov_len = outbytes;

    msgrecv.msg_name = NULL;
    msgrecv.msg_namelen = 0;
    msgrecv.msg_iov = iovrecv;
    msgrecv.msg_iovlen = 2;
    iovrecv[0].iov_base = &psar->recvhdr;
    iovrecv[0].iov_len = sizeof(struct hdr);
    iovrecv[1].iov_base = inbuff;
    iovrecv[1].iov_len = inbytes;

    struct timeval tv, selectbegin, selectend;

    rtt_newpack(&psar->rttinfo);		/* initialize for this packet */

sendagain:
    psar->sendhdr.ts = rtt_ts(&psar->rttinfo);
    Sendmsg(psar->fd, &msgsend, 0);

    waitsec  = rtt_start(&psar->rttinfo);	/* calc timeout value & start timer */
#ifdef	RTT_DEBUG
    fprintf(stderr, "\e[31msend seq %4d: \e[m", psar->sendhdr.seq);
    rtt_debug(&psar->rttinfo);
#endif

    for (;;) {
        tv.tv_sec = waitsec;	/* calc timeout value & start timer */
        tv.tv_usec = 0;
        FD_ZERO(&set);
        FD_SET(psar->fd, &set);

        gettimeofday(&selectbegin, 0);  /* calc select system call EINTR time */
eintr:
        ret = select(psar->fd+1, &set, 0, 0, &tv);
        if (ret < 0) {
            if (errno == EINTR) {
                /* calc next select block time if system interrupt */
                gettimeofday(&selectend, 0);
                /* Simplified calculation, 
                 * maximum deviation within 1 second for wait recv */
                tv.tv_sec = tv.tv_sec - (selectend.tv_sec - selectbegin.tv_sec);
                tv.tv_usec = abs(tv.tv_usec - (selectend.tv_usec - selectbegin.tv_usec));  
#ifdef	RTT_DEBUG
                err_msg("select interrupt, the next Waiting-Blocking time %ld.%ld\n", tv.tv_sec, tv.tv_usec);
#endif
                goto eintr;
            }
            err_ret("select error");
        } else if (ret == 0) {
            if (rtt_timeout(&psar->rttinfo) < 0) {
                err_msg("\e[33mno response from server, giving up\e[m");
                psar->rttinit = 0;	/* reinit in case we're called again */
                errno = ETIMEDOUT;
                pthread_mutex_unlock(&psar->lock);
                return(-1);
            }
#ifdef	RTT_DEBUG
            err_msg("\e[31m     seq %4d timeout, retransmitting\e[m", psar->sendhdr.seq);
#endif
            goto sendagain;
        } 
        if (FD_ISSET(psar->fd, &set)) {
            do { 
                n = recvmsg(psar->fd, &msgrecv, 0);
                if (n < 0 && errno == EAGAIN) {
#ifdef	RTT_DEBUG
                    //fprintf(stderr, "recvmsg EAGAIN\n");
#endif
                    break;
                }
#ifdef	RTT_DEBUG
                fprintf(stderr, "\e[31mrecv seq %4d: \e[m\n", psar->recvhdr.seq);
#endif
                if(n >= sizeof(struct hdr) && psar->recvhdr.flag == 0 && 
                        (psar->recvhdr.type == SU_GENERAL || psar->recvhdr.type == SU_RELIABLE)) {
                    if (psar->recvhdr.seq == psar->sendhdr.seq) 
                        goto finish;
                    else {
                        if (psar->in) 
                            psar->in(psar, inbuff, n - sizeof(struct hdr));
                    }
                }
            } while (1);
        }
    }
finish:

    /* 4calculate & store new RTT estimator values */
    rtt_stop(&psar->rttinfo, rtt_ts(&psar->rttinfo) - psar->recvhdr.ts);

    pthread_mutex_unlock(&psar->lock);
    return(n - sizeof(struct hdr));	/* return size of received datagram */
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

