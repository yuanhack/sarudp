#ifndef __YH_SARUDP_PEER_H__
#define __YH_SARUDP_PEER_H__

#include "sarudp_comm.h"

typedef struct sar_udp_peer su_peer_t;
typedef void cb_su_peer_receiver_t(su_peer_t *ps, char* buff, int len);

/* SYN/ACK/Retransfer UDP peer manager */
struct sar_udp_peer {
    /* foreign host info */
    int       fd;
    SAUN      destaddr;
    socklen_t destlen;
    uint16_t sid;
    uint32_t seq;
    struct rtt_info rttinfo;
    int retry;
    int retransmission;        /* retransmit counting  */
    int rttinit;

    /* event driver */
    fe_t fe;
    cb_su_peer_receiver_t * reliable_request_handle;
    cb_su_peer_receiver_t * ordinary_request_handle;

    pthread_t tid;
    int       run;

    pthread_mutex_t mutex;
    pthread_mutex_t lock;
    pthread_cond_t ackcond;
    pthread_cond_t syncond;

    int         ackwaitnum;     /* SU_RELIABLE Requester number */

    /* frames_t list: foreign respnose */
    struct list ackrecvls;      /* SU_RELIABLE Reply of the foreign host */

    /* frames_t list: foreign request  */
    struct list synrecvls;      /* Receive foreign host the active request */
    frames_t *nowsynframe;      /* Currently working with active request (syn) */

    /* container cache_t: foreign reply result datas */
    struct list lsackcache;     /* The cache results for timeout check  */
    rb_root_t rbackcache;       /* The cache results for re-syn search  */
    pthread_mutex_t cachelock;
};

int  su_peer_create(su_peer_t *psar, const SA *ptoaddr, socklen_t servlen);
int  su_peer_create_bind(su_peer_t *psar, int port, const SA *ptoaddr, socklen_t servlen);
void su_peer_destroy(su_peer_t *psar);

void su_peer_reliable_request_handle_install(su_peer_t *psar, cb_su_peer_receiver_t* reliable_request_handle);
void su_peer_ordinary_request_handle_install(su_peer_t *psar, cb_su_peer_receiver_t* ordinary_request_handle);
void su_peer_reliable_request_handle_uninstall(su_peer_t *psar);
void su_peer_ordinary_request_handle_uninstall(su_peer_t *psar);

int  su_peer_send(su_peer_t *psar, const void *outbuff, int outbytes);
int  su_peer_request(su_peer_t *psar, const void *outbuff, int outbytes, void *inbuff, int inbytes);
int  su_peer_request_retry(su_peer_t *psar, const void *outbuff, int outbytes, void *inbuff, int inbytes);

int  su_peer_getsrcaddr(su_peer_t *psar, SAUN *addr);

int  su_peer_reply(su_peer_t *psar, const void *outbuff, int outbytes);
int  su_peer_reply_ack(su_peer_t *psar);

#endif /* __YH_SARUDP_PEER_H__ */
