#ifndef __YH_SARUDP_H__
#define __YH_SARUDP_H__

#include "unprtt.h"
#include "wrapfunc.h"
#include "yherror.h"
#include "yhevent.h"
#include "list.h"

#include <pthread.h>
#include <sys/socket.h>
#include <setjmp.h>
#include <unistd.h>
#include <fcntl.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>


#pragma pack(push)
#pragma pack(1)
struct hdr {
  uint8_t   flag;   /* protocol flag */

#define SU_GENERAL 0 
#define SU_RELIABLE 1

  uint8_t   type;   /* protocol type */
  uint32_t	seq;	/* sequence # */
  uint32_t	ts;		/* timestamp when sent */
};
#pragma pack(pop)

typedef struct sockaddr     SA;
typedef struct sockaddr_in  SA4;
typedef struct sockaddr_in6 SA6;
typedef struct sar_udp_peer supeer_t;
typedef union { SA4 addr4; SA6 addr6; } SAUN;

typedef void cb_supeer_receiver_t(supeer_t *ps, char* buff, int len);

typedef struct data {
    struct list node;
    int         len;
    uint8_t     data[];
} data_t;

// SYN/ACK/Retransfer UDP peer manager
struct sar_udp_peer {
    int fd;
    struct hdr sendhdr;
    struct rtt_info rttinfo;
    int rttinit;

    SAUN destaddr;
    socklen_t destlen;

    fe_t fe;
    pthread_t tid;
    cb_supeer_receiver_t* in;

    pthread_mutex_t lock;
    pthread_cond_t cond;
    int relcount;
    struct list ls_rel;  // SU_RELIABLE
    struct list ls_gen;  // SU_GENERAL
};

int su_peer_new(supeer_t *psar, 
        const SA *ptoaddr, socklen_t servlen, cb_supeer_receiver_t* in);
void su_peer_rm(supeer_t *psar);

ssize_t su_peer_send(supeer_t *psar, const void *outbuff, size_t outbytes);
ssize_t su_peer_send_recv(supeer_t *psar, const void *outbuff, size_t outbytes,
        void *inbuff, size_t inbytes);

ssize_t su_peer_send_recv_retry(supeer_t *psar, const void *outbuff, size_t outbytes,
        void *inbuff, size_t inbytes);

#endif /* __YH_SARUDP_H__ */
