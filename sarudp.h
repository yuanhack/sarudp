#ifndef __YH_SARUDP_H__
#define __YH_SARUDP_H__

#include "unprtt.h"
#include "wrapfunc.h"
#include "list.h"

#include "yherror.h"
#include "yhevent.h"
#include "yhrbtree.h"

#include <pthread.h>
#include <sys/socket.h>
#include <setjmp.h>
#include <unistd.h>
#include <fcntl.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>

#define REALDATAMAX  1024       /* datagram max size */
#define CACHETIMEOUT 90         /* reliable request-result cached seconds */

#define ColorRed    "\e[31m"
#define ColorGre    "\e[32m"
#define ColorYel    "\e[33m"
#define ColorBlue   "\e[34m"
#define ColorEnd    "\e[m"

#pragma pack(push)
#pragma pack(1)

/* protocol head */
typedef struct hdr {
    /* packet action  */
#define     SU_SYN      0xff    /* request */
#define     SU_ACK      0xfe    /* respnose */
    uint8_t   act;              /* protocol action */
    
    /* packet type */
#define     SU_ORDINARY 0       /* ordinary, foreign host Don't need to reply */
#define     SU_RELIABLE 1       /* reliable, foreign host Must reply */
    uint8_t   type;             /* protocol type */

    uint32_t	seq;	        /* sequence # */
    uint32_t	ts;		        /* timestamp when sent */
} suhdr_t;

#pragma pack(pop)

typedef struct sockaddr     SA;
typedef struct sockaddr_in  SA4;
typedef struct sockaddr_in6 SA6;
typedef struct sar_udp_peer supeer_t;
typedef union { SA4 addr4; SA6 addr6; } SAUN;

typedef void cb_su_peer_receiver_t(supeer_t *ps, char* buff, int len);


/* recv storage data, list node */
typedef struct frames {
    struct list node;
    SAUN        srcaddr;
    socklen_t   srclen;
    suhdr_t     recvhdr;
    int         len;
    uint8_t     data[];
} frames_t;

typedef struct cache {
    time_t    ts;
    struct rb_node rbn;
    frames_t  pack;
} cache_t;

typedef struct rb_key_cache {
    SAUN destaddr;
    socklen_t destlen;
    uint32_t  seq;
} rb_key_cache_t;


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
    cb_su_peer_receiver_t * reliable_request_handle;
    cb_su_peer_receiver_t * ordinary_request_handle;

    pthread_t tid;

    pthread_mutex_t lock;
    pthread_cond_t ackcond;
    pthread_cond_t syncond;

    int         ackwaitnum;     /* SU_RELIABLE Requester number */

    /* frames_t list: foreign respnose */
    struct list ackrecvls;      /* SU_RELIABLE Reply of the foreign host */

    /* frames_t list: foreign request  */
    struct list synrecvls;      /* Receive foreign host the active request */
    frames_t *synnowpack;       /* Currently working with active request (syn) */

    /* container cache_t: foreign reply result datas */
    struct list lsackcache;     /* The cache results for timeout check  */
    rb_root_t rbackcache;       /* The cache results for re-syn search  */
    pthread_mutex_t cachelock;
};

int  su_peer_create(supeer_t *psar, const SA *ptoaddr, socklen_t servlen);
int  su_peer_create_bind(supeer_t *psar, int port, const SA *ptoaddr, socklen_t servlen);
void su_peer_destroy(supeer_t *psar);

ssize_t su_peer_send(supeer_t *psar, const void *outbuff, size_t outbytes);
ssize_t su_peer_request(supeer_t *psar, const void *outbuff, size_t outbytes, void *inbuff, size_t inbytes);
ssize_t su_peer_request_retry(supeer_t *psar, const void *outbuff, size_t outbytes, void *inbuff, size_t inbytes);

ssize_t su_peer_reply(supeer_t *psar, const void *outbuff, size_t outbytes);

int  su_peer_reliable_request_handle_install(supeer_t *psar, cb_su_peer_receiver_t* reliable_request_handle);
int  su_peer_ordinary_request_handle_install(supeer_t *psar, cb_su_peer_receiver_t* ordinary_request_handle);
void su_peer_reliable_request_handle_uninstall(supeer_t *psar);
void su_peer_ordinary_request_handle_uninstall(supeer_t *psar);

int su_peer_create_bind(supeer_t *psar, int port, const SA *ptoaddr, socklen_t servlen);

#endif /* __YH_SARUDP_H__ */
