#ifndef __YH_SARUDP_H__
#define __YH_SARUDP_H__

#include "unprtt.h"
#include "wrapfunc.h"
#include "yherror.h"
#include "yhevent.h"

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
typedef struct sarudppeer supeer_t;
typedef union { SA4 addr4; SA6 addr6; } SUN;

typedef void sarudpin(supeer_t *ps, char* buff, int len);

// SYN/ACK Retransfer UDP peer manager
struct sarudppeer {
    int fd;
    pthread_mutex_t lock;
    pthread_cond_t cond;
    struct hdr sendhdr;
    struct hdr recvhdr;
    struct rtt_info rttinfo;
    int rttinit;
    SUN destaddr;
    socklen_t destlen;
    fd_event_t fe;
    epoll_manager_t *pem;
    sarudpin* in;
};

int su_peer_new(supeer_t *psar, const SA *ptoaddr, socklen_t servlen, sarudpin* in);
int su_peer_rm(supeer_t *psar);

ssize_t su_peer_send(supeer_t *psar, const void *outbuff, size_t outbytes);
ssize_t su_peer_send_recv(supeer_t *psar, const void *outbuff, size_t outbytes,
        void *inbuff, size_t inbytes);

ssize_t su_peer_send_recv_retry(supeer_t *psar, const void *outbuff, size_t outbytes,
        void *inbuff, size_t inbytes);

#endif /* __YH_SARUDP_H__ */
