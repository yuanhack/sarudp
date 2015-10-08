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
    //char ip[256], errinfo[256];

    signal(SIGINT, sigint);

	if (argc != 2)
		err_quit("usage: %s <Port>", argv[0]);

#if 0
    daemon_init(0, 0, 0, 0);
#endif

    /* The address is not used as a client, can be arbitrarily set  */
#if 0
	struct sockaddr_in servaddr;
	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(argv[1]);
	Inet_pton(AF_INET, "0.0.0.0", &servaddr.sin_addr);
#else
	struct sockaddr_in6 servaddr;
	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin6_family = AF_INET6;
    servaddr.sin6_port = htons(atoi(argv[1]));
	Inet_pton(AF_INET6, "::", &servaddr.sin6_addr);
#endif

    if (su_serv_create(&svr, (SA*)&servaddr, sizeof(servaddr), 10) < 0)
        err_sys("su_serv_create error");
    log_msg("listen port %s successful", argv[1]);

    su_serv_reliable_request_handle_install(&svr, reliable_data_in);
    su_serv_ordinary_request_handle_install(&svr, ordinary_data_in);

#if 1
    while (1)
        pause();
#else
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

    su_get_ip_port_f(&frame->srcaddr, ipbuff, sizeof(ipbuff), &port);

    log_msg("reliable recv from %s:%d datagrams len %d " ColorGre"%s"ColorEnd,
            ipbuff, port, len, buff);

    su_serv_reply(psar, frame, buff, len);
}
void ordinary_data_in(su_serv_t *psar, frames_t *frame, char *buff, int len)
{
    char ipbuff[INET6_ADDRSTRLEN];
    int port;

    //su_get_ip_port(&frame->srcaddr, ipbuff, sizeof(ipbuff), &port);
    su_get_ip_port_f(&frame->srcaddr, ipbuff, sizeof(ipbuff), &port);

    log_msg("ordinary recv from %s:%d datagrams len %d " ColorGre"%s"ColorEnd,
            ipbuff, port, len, buff);

    su_serv_reply(psar, frame, buff, len);
}
