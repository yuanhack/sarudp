#include "sarudp.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>


#define RTT_DEBUG

//static struct rtt_info   rttinfo;
int setfd_nonblock(int fd)    
{
    int status;
    if ((status = fcntl(fd, F_GETFL)) < 0) { 
        err_ret("setfd_nonblock() fcntl F_GETFL error[%d]", errno); 
        return -1; 
    }  
    status |= O_NONBLOCK;     
    if (fcntl(fd, F_SETFL, status) < 0) { 
        err_ret("setfd_nonblock() fcntl F_SETFL error[%d]", errno); 
        return -1;            
    }  
    return 0;                 
}
void Setfd_nonblock(int fd)
{
    if ( setfd_nonblock(fd) < 0 ) 
        exit(1);
}

int sarudp_create(sarudpmgr_t *psar, int family, int flag)
{
    psar->fd = socket(family, SOCK_DGRAM, flag);
    if (psar->fd < 0) 
        return -1;

    psar->rttinit = 0;
    psar->sendhdr.seq = 0;
	psar->sendhdr.flag[0] = 0;
	psar->sendhdr.flag[1] = 0xfa;
    Setfd_nonblock(psar->fd);
    pthread_mutex_init(&psar->lock, 0);

    return 0;
}

void serudp_destroy(sarudpmgr_t *psar)
{
    if (psar->fd >= 0) { 
        close(psar->fd); 
        psar->fd = -1; 
        return;
    }
    pthread_mutex_destroy(&psar->lock);
}

void sarudp_seq_set(sarudpmgr_t *psar, int seq)
{
    pthread_mutex_lock(&psar->lock);
    psar->sendhdr.seq = seq;
    pthread_mutex_unlock(&psar->lock);
}

ssize_t
sarudp_send_recv(sarudpmgr_t *psar, const void *outbuff, size_t outbytes,
			 void *inbuff, size_t inbytes,
			 const SA *destaddr, socklen_t destlen)
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

	psar->sendhdr.seq++;
	msgsend.msg_name = (void*)destaddr;
	msgsend.msg_namelen = destlen;
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

//    struct timeval tv;
//    gettimeofday(&tv, 0);  /* calc select system call EINTR time */
//	fprintf(stderr, "rtt = %.3f, srtt = %.3f, rttvar = %.3f, rto = %.3f time=%0ld.%0ld\n",
//			ptr->rtt_rtt, ptr->rtt_srtt, ptr->rtt_rttvar, ptr->rtt_rto,
//            tv.tv_sec, tv.tv_usec);

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
                /* calc next select block time if system call EINTR */
                gettimeofday(&selectend, 0);
                tv.tv_sec = tv.tv_sec - (selectend.tv_sec - selectbegin.tv_sec);
                tv.tv_usec = tv.tv_usec - (selectend.tv_usec - selectbegin.tv_usec);
                err_msg("select EINTR, calc the next Waiting-Blocking time %ld.%ld\n", tv.tv_sec, tv.tv_usec);
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
                    fprintf(stderr, "recvmsg EAGAIN\n");
#endif
                    break;
                }
#ifdef	RTT_DEBUG
                fprintf(stderr, "\e[31mrecv seq %4d: \e[m\n", psar->recvhdr.seq);
                //rtt_debug(&psar->rttinfo);
#endif
                if(n >= sizeof(struct hdr) && psar->recvhdr.seq == psar->sendhdr.seq)
                    goto finish;  /* finish matching receive */
            } while (1);
        }
    }
finish:

		/* 4calculate & store new RTT estimator values */
	rtt_stop(&psar->rttinfo, rtt_ts(&psar->rttinfo) - psar->recvhdr.ts);

    pthread_mutex_unlock(&psar->lock);
	return(n - sizeof(struct hdr));	/* return size of received datagram */
}

ssize_t
Sarudp_send_recv(sarudpmgr_t *psar, const void *outbuff, size_t outbytes,
			 void *inbuff, size_t inbytes,
			 const SA *destaddr, socklen_t destlen)
{
	ssize_t	n;

	n = sarudp_send_recv(psar, outbuff, outbytes, inbuff, inbytes, destaddr, destlen);
	if (n < 0)
		err_quit("dg_send_recv error");

	return(n);
}

