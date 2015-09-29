#include "sarudp_serv.h"
#include "domain_parse.h"
#include "wrapfunc.h"

#include <sys/signal.h>

#include "sarudp_peer.h"

// handle SIGINT
void sigint(int no);

void reliable_data_in(su_serv_t *psar, frames_t *frame, char *buff, int len);
void ordinary_data_in(su_serv_t *psar, frames_t *frame, char *buff, int len);

int main(int argc, char **argv)
{
    su_serv_t svr;
    char ip[256], errinfo[256];

    signal(SIGINT, sigint);

	if (argc != 1 && argc != 2)
		err_quit("usage: %s [Port Default 10000]", argv[0]);

    /* The address is not used as a client, can be arbitrarily set  */
#if 0
	struct sockaddr_in servaddr;
	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(55555);
	Inet_pton(AF_INET, "0.0.0.0", &servaddr.sin_addr);
#else
	struct sockaddr_in6 servaddr;
	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin6_family = AF_INET6;
    servaddr.sin6_port = htons(55555);
	Inet_pton(AF_INET6, "::", &servaddr.sin6_addr);
#endif

    if (su_serv_create(&svr, (SA*)&servaddr, sizeof(servaddr), 10) < 0)
        err_quit("su_serv_create error");
    log_msg("listen port %d successful", 55555);

    su_serv_reliable_request_handle_install(&svr, reliable_data_in);
    su_serv_ordinary_request_handle_install(&svr, ordinary_data_in);

    sleep(2);

    su_serv_destroy(&svr);

    while (1) pause();

    exit(0);
}

void sigint(int no)
{
    log_msg(ColorRed "\nSIGINT\n" ColorEnd);
    exit(0);
}
void reliable_data_in(su_serv_t *psar, frames_t *frame, char *buff, int len)
{
    struct sockaddr_in s4;
    socklen_t slen; 
    SAUN sa;
    char ipbuff[INET6_ADDRSTRLEN];
    int port;

    //su_serv_getsrcaddr(psar, frame, (SA*)&s4, &slen);
    su_get_ip_port(&frame->srcaddr, ipbuff, sizeof(ipbuff), &port);

    printf("reliable recv from %s:%d datagrams len %d " ColorGre"%s\n"ColorEnd,
            ipbuff, port,
            //inet_ntoa(s4.sin_addr), ntohs(s4.sin_port), 
            len, buff);

    su_serv_reply(psar, frame, buff, len);
}
void ordinary_data_in(su_serv_t *psar, frames_t *frame, char *buff, int len)
{
}
