#ifndef __YH_SARUDP_H__
#define __YH_SARUDP_H__

#include "sarudp_comm.h"

typedef struct sar_udp_serv suserv_t;
typedef void cb_su_serv_receiver_t(suserv_t *ps, frames_t* frame, char* buff, int len);

/* SYN/ACK/Retransfer UDP peer manager */
struct sar_udp_serv {
    /* foreign host info */
    int fd;
    SAUN servaddr;
    socklen_t servlen;
    uint32_t seq;
    struct rtt_info rttinfo;
    int retry;
    int rttinit;

    /* event driver */
    fe_t fe;
    cb_su_serv_receiver_t * reliable_request_handle;
    cb_su_serv_receiver_t * ordinary_request_handle;

    pthread_t   *tid;
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

int  su_serv_create(suserv_t *psvr, int nthread, const SA *saddr, socklen_t servlen);
void su_serv_destroy(suserv_t *psvr);


void su_serv_reliable_request_handle_install(suserv_t *psvr, cb_su_serv_receiver_t* reliable_request_handle);
void su_serv_ordinary_request_handle_install(suserv_t *psvr, cb_su_serv_receiver_t* ordinary_request_handle);
void su_serv_reliable_request_handle_uninstall(suserv_t *psvr);
void su_serv_ordinary_request_handle_uninstall(suserv_t *psvr);

int su_serv_getsrcaddr_act(suserv_t *psvr, frames_t *frame, SA *addr, socklen_t *addrlen);
int su_serv_reply(suserv_t *psvr, frames_t *frame, const void *outbuff, int outbytes);
int su_serv_getsrcaddr(suserv_t *psvr, frames_t *frame, SA *addr, socklen_t *addrlen);

int su_serv_send(suserv_t *psar, SA*destaddr, socklen_t destlen, const void *outbuff, int outbytes);
int su_serv_request(suserv_t *psar, SA *destaddr, socklen_t destlen, const void *outbuff, int outbytes, void *inbuff, int inbytes);
int su_serv_request_retry(suserv_t *psar, SA *destaddr, socklen_t destlen, const void *outbuff, int outbytes, void *inbuff, int inbytes);


#endif /* __YH_SARUDP_H__ */
