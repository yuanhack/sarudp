#include "sarudp_serv.h"
#include "domain_parse.h"
#include "wrapfunc.h"

#include <sys/signal.h>


// handle SIGINT
void sigint(int no);

void reliable_data_in(suserv_t *psar, frames_t *frame, char *buff, int len);
void ordinary_data_in(suserv_t *psar, frames_t *frame, char *buff, int len);

int main(int argc, char **argv)
{
	struct sockaddr_in	servaddr;
    suserv_t sar;
    char ip[256], errinfo[256];

    signal(SIGINT, sigint);

	if (argc != 1 && argc != 2)
		err_quit("usage: %s [Port Default 10000]", argv[0]);

    /* The address is not used as a client, can be arbitrarily set  */
	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(55555);
	Inet_pton(AF_INET, "0.0.0.0", &servaddr.sin_addr);

    if (su_serv_create(&sar, 10, (SA*)&servaddr, sizeof(SA)) < 0) 
        err_quit("su_serv_create error");

    su_serv_reliable_request_handle_install(&sar, reliable_data_in);
    su_serv_ordinary_request_handle_install(&sar, ordinary_data_in);

    while (1) 
        pause();

    exit(0);
}

void sigint(int no)
{
    log_msg(ColorRed "\nSIGINT\n" ColorEnd);
    exit(0);
}
void reliable_data_in(suserv_t *psar, frames_t *frame, char *buff, int len)
{
    struct sockaddr_in s4;
    socklen_t slen; 

    su_serv_getsrcaddr(psar,frame, (SA*)&s4, &slen);

    printf("reliable recv from %s:%d datagrams len %d " ColorGre"%s\n"ColorEnd,
            inet_ntoa(s4.sin_addr), ntohs(s4.sin_port), len, buff);

    su_serv_reply(psar, frame, buff, len);
}
void ordinary_data_in(suserv_t *psar, frames_t *frame, char *buff, int len)
{
}
