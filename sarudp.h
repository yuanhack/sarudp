#ifndef __YH_SARUDP_H__
#define __YH_SARUDP_H__

#include "unprtt.h"

#pragma pack(push)
#pragma pack(1)
struct hdr {
  uint8_t   flag[2];/* protocol flag */
  uint32_t	seq;	/* sequence # */
  uint32_t	ts;		/* timestamp when sent */
};
#pragma pack(pop)

// SYN/ACK Retransfer manager
typedef struct sarudpmgr {
    int fd;
    struct hdr sendhdr;
    struct hdr recvhdr;
    struct rtt_info rttinfo;
    int rttinit;
} sarudpmgr_t;

typedef struct sockaddr_in SAI;

int sarudp_init(sarudpmgr_t *psar, int fam, int flag);
void sarudp_reset_seq(sarudpmgr_t *psar);

ssize_t sarudp_send_recv(sarudpmgr_t *psar, const void *outbuff, size_t outbytes,
			 void *inbuff, size_t inbytes,
			 const SA *destaddr, socklen_t destlen);

ssize_t Sarudp_send_recv(sarudpmgr_t *psar, const void *outbuff, size_t outbytes,
			 void *inbuff, size_t inbytes,
			 const SA *destaddr, socklen_t destlen);

#endif /* __YH_SARUDP_H__ */
