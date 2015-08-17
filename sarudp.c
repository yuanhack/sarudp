#include "sarudp.h"
#include <setjmp.h>


#define RTT_DEBUG

//static struct rtt_info   rttinfo;
struct msghdr	msgsend, msgrecv;	/* assumed init to 0 */

static sigjmp_buf jmpbuf;

int sarudp_init(sarudpmgr_t *psar, int family, int flag)
{
    psar->fd = Socket(family, SOCK_DGRAM, flag);
    if (psar->fd < 0) 
        return -1;
    psar->rttinit = 0;
    sarudp_reset_seq(psar);
    return 0;
}
static void
sig_alrm(int signo)
{
   siglongjmp(jmpbuf, 1);
}

void sarudp_reset_seq(sarudpmgr_t *psar)
{
    psar->sendhdr.seq = 0;
}
ssize_t
sarudp_send_recv(sarudpmgr_t *psar, const void *outbuff, size_t outbytes,
			 void *inbuff, size_t inbytes,
			 const SA *destaddr, socklen_t destlen)
{
	ssize_t			n;
	struct iovec	iovsend[2], iovrecv[2];
    rtt_d_flag = 1;

    if (psar->rttinit == 0) {
        rtt_init(&psar->rttinfo);
        psar->rttinit = 1;
    }

	psar->sendhdr.flag[0] = 0;
	psar->sendhdr.flag[1] = 0xfa;
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

    Signal(SIGALRM, sig_alrm);
	rtt_newpack(&psar->rttinfo);		/* initialize for this packet */

sendagain:
#ifdef	RTT_DEBUG
	fprintf(stderr, "send %4d: ", psar->sendhdr.seq);
#endif
	psar->sendhdr.ts = rtt_ts(&psar->rttinfo);
	Sendmsg(psar->fd, &msgsend, 0);

	alarm(rtt_start(&psar->rttinfo));	/* calc timeout value & start timer */
#ifdef	RTT_DEBUG
	rtt_debug(&psar->rttinfo);
#endif

	if (sigsetjmp(jmpbuf, 1) != 0) {
		if (rtt_timeout(&psar->rttinfo) < 0) {
			err_msg("dg_send_recv: no response from server, giving up");
			psar->rttinit = 0;	/* reinit in case we're called again */
			errno = ETIMEDOUT;
			return(-1);
		}
#ifdef	RTT_DEBUG
		err_msg("dg_send_recv: timeout, retransmitting");
#endif
		goto sendagain;
	}

	do {
		n = Recvmsg(psar->fd, &msgrecv, 0);
#ifdef	RTT_DEBUG
		fprintf(stderr, "recv %4d\n", psar->recvhdr.seq);
#endif
	} while (n < sizeof(struct hdr) || psar->recvhdr.seq != psar->sendhdr.seq);

	alarm(0);			/* stop SIGALRM timer */
		/* 4calculate & store new RTT estimator values */
	rtt_stop(&psar->rttinfo, rtt_ts(&psar->rttinfo) - psar->recvhdr.ts);

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

