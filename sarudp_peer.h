#ifndef __YH_SARUDP_H__
#define __YH_SARUDP_H__

#include "sarudp_comm.h"

typedef struct sar_udp_peer supeer_t;
typedef void cb_supeer_recv_t(supeer_t *ps, char* buff, int len);

/* SYN/ACK/Retransfer UDP peer manager */
struct sar_udp_peer {
    /* foreign host info */
    int fd;
    SAUN destaddr;
    socklen_t destlen;
    uint32_t seq;
    struct rtt_info rttinfo;
    int retry;
    int rttinit;

    /* event driver */
    fe_t fe;
    cb_supeer_recv_t * reliable_request_handle;
    cb_supeer_recv_t * ordinary_request_handle;

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

int  su_peer_create(supeer_t *psar, const SA *ptoaddr, socklen_t servlen);
int  su_peer_create_bind(supeer_t *psar, int port, const SA *ptoaddr, socklen_t servlen);
void su_peer_destroy(supeer_t *psar);

int  su_peer_send(supeer_t *psar, const void *outbuff, int outbytes);
int  su_peer_request(supeer_t *psar, const void *outbuff, int outbytes, void *inbuff, int inbytes);
int  su_peer_request_retry(supeer_t *psar, const void *outbuff, int outbytes, void *inbuff, int inbytes);

int  su_peer_reply(supeer_t *psar, const void *outbuff, int outbytes);
int  su_peer_getsrcaddr(supeer_t *psar, SA *addr, socklen_t *addrlen);

int  su_peer_reliable_request_handle_install(supeer_t *psar, cb_supeer_recv_t* reliable_request_handle);
int  su_peer_ordinary_request_handle_install(supeer_t *psar, cb_supeer_recv_t* ordinary_request_handle);
void su_peer_reliable_request_handle_uninstall(supeer_t *psar);
void su_peer_ordinary_request_handle_uninstall(supeer_t *psar);


#endif /* __YH_SARUDP_H__ */
