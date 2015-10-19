#ifndef __YH_SARUDP_SERV_H__
#define __YH_SARUDP_SERV_H__

#include "sarudp_comm.h"

typedef struct sar_udp_serv su_serv_t;
typedef void cb_su_serv_receiver_t(su_serv_t *ps, frames_t* frame, char* buff, int len);

/* SYN/ACK/Retransfer UDP serv manager */
struct sar_udp_serv {
    /* foreign host info */
    int fd;
    SAUN servaddr;
    socklen_t servlen;
    uint16_t sid;               /* zero */
    uint32_t seq;
    struct rtt_info rttinfo;
    int retry;
    int retransmission;
    int rttinit;

    /* event driver */
    fe_t fe;
    cb_su_serv_receiver_t * reliable_request_handle;
    cb_su_serv_receiver_t * ordinary_request_handle;

    pthread_t   *tids;
    int         run;
    int         tnum;

    pthread_mutex_t mutex;      /* Protect single line to send */
    pthread_mutex_t lock;
    pthread_cond_t ackcond;
    pthread_cond_t syncond;

    int         ackwaitnum;     /* SU_RELIABLE Requester number */

    /* frames_t list: foreign respnose */
    struct list ackrecvls;      /* SU_RELIABLE Reply of the foreign host */

    /* frames_t list: foreign request  */
    struct list synrecvls;      /* Receive foreign host the active request */

    /* container cache_t: foreign reply result datas */
    struct list lsackcache;     /* The cache results for timeout check  */
    rb_root_t rbackcache;       /* The cache results for re-syn search  */
    pthread_mutex_t cachelock;
};

int  su_serv_create(su_serv_t *psvr, const SA *saddr, socklen_t servlen, int nthread);
void su_serv_destroy(su_serv_t *psvr);

void su_serv_reliable_request_handle_install(su_serv_t *psvr, cb_su_serv_receiver_t* reliable_request_handle);
void su_serv_ordinary_request_handle_install(su_serv_t *psvr, cb_su_serv_receiver_t* ordinary_request_handle);
void su_serv_reliable_request_handle_uninstall(su_serv_t *psvr);
void su_serv_ordinary_request_handle_uninstall(su_serv_t *psvr);

int su_serv_send(su_serv_t *psar, SA*destaddr, socklen_t destlen, const void *outbuff, int outbytes);
int su_serv_request(su_serv_t *psar, SA *destaddr, socklen_t destlen, const void *outbuff, int outbytes, void *inbuff, int inbytes);
int su_serv_request_retry(su_serv_t *psar, SA *destaddr, socklen_t destlen, const void *outbuff, int outbytes, void *inbuff, int inbytes);

int su_serv_reply(su_serv_t *psvr, frames_t *frame, const void *outbuff, int outbytes);
int su_serv_reply_ack(su_serv_t *psvr, frames_t *frame);

#endif /* __YH_SARUDP_SERV_H__ */
