#include "domain_parse.h"
#include "wrapfunc.h"

#include "sarudp_peer.h"
#include "sarudp_serv.h"

#include "yhdaemon.h"
#include "yharguments.h"

#include <sys/signal.h>


// handle SIGINT
void sigint(int no);

void reliable_data_in(su_serv_t *psar, frames_t *frame, char *buff, int len);
void ordinary_data_in(su_serv_t *psar, frames_t *frame, char *buff, int len);

int main(int argc, char **argv)
{
    su_serv_t svr;

    signal(SIGINT, sigint);

    if (argc == 1) {
        usage(argc, argv);
        exit(1);
    }

    arguments(argc, argv);

    if (daemond)
        daemon_init(0, 0, 0, 0);

#if 0
	struct sockaddr_in servaddr;
	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(port);
	Inet_pton(AF_INET, "0.0.0.0", &servaddr.sin_addr);
#else
	struct sockaddr_in6 servaddr;
	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin6_family = AF_INET6;
    servaddr.sin6_port = htons(port);
	Inet_pton(AF_INET6, "::", &servaddr.sin6_addr);
#endif

    if (su_serv_create(&svr, (SA*)&servaddr, sizeof(servaddr), 10) < 0)
        err_sys("su_serv_create error");

    log_msg("serv %x sarudp listen port %d", &svr, port);

    su_serv_reliable_request_handle_install(&svr, reliable_data_in);
    su_serv_ordinary_request_handle_install(&svr, ordinary_data_in);

#if 1
    /* Service forever */
    while (1)
        pause();
#else
    /* After 30 seconds to stop the service */
    sleep(30);
    su_serv_destroy(&svr);
#endif

    exit(0);
}

void sigint(int no)
{
    log_msg(ColorRed "\nSIGINT\n" ColorEnd);
    exit(0);
}
void reliable_data_in(su_serv_t *psar, frames_t *frame, char *buff, int len)
{
    char ipbuff[INET6_ADDRSTRLEN];
    int port;

    su_get_ip_port(&frame->srcaddr, ipbuff, sizeof(ipbuff), &port);

    log_msg("reliable recv from %s:%d datagrams len %d " ColorGre"%s"ColorEnd,
            ipbuff, port, len, buff);

    int n;
#if 1
    n = su_serv_reply(psar, frame, buff, len);
#else
    n = su_serv_reply_ack(psar, frame);
#endif
    if (n < 0) {
        ERR_RET("su_peer_reply error");
    }
}
void ordinary_data_in(su_serv_t *psar, frames_t *frame, char *buff, int len)
{
    char ipbuff[INET6_ADDRSTRLEN];
    int port;

    su_get_ip_port(&frame->srcaddr, ipbuff, sizeof(ipbuff), &port);

    log_msg("ordinary recv from %s:%d datagrams len %d " ColorGre"%s"ColorEnd,
            ipbuff, port, len, buff);

    //su_serv_reply(psar, frame, buff, len); // call is invalid, ordinary packet don't handle reply
    su_serv_send(psar, (SA*)&frame->srcaddr, frame->srclen, buff, len); // call is valid
}
