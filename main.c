#include "sarudp.h"
#include "domain_parse.h"
#include "wrapfunc.h"

#include <sys/signal.h>

void sar_cli_send(FILE *fp, supeer_t *psar);
void sar_cli_send_recv(FILE *fp, supeer_t *psar);

void udpin_reliable(supeer_t *psar, char *buff, int len)
{
    if (len > 0) 
        printf("reliable recv len %d info "ColorRed"%s\n"ColorEnd, len, buff);
    su_peer_reply(psar, buff, len);
}
void udpin_ordinary(supeer_t *psar, char *buff, int len)
{
    if (len > 0) 
        printf("ordinary recv len %d info "ColorGre"%s\n"ColorEnd, len, buff);
    su_peer_reply(psar, buff, len);
}

void sigint(int no)
{
    log_msg("\nSIGINT");
    exit(0);
}

int
main(int argc, char **argv)
{
	struct sockaddr_in	servaddr;
    supeer_t sar;
    char ip[256], errinfo[256];

    signal(SIGINT, sigint);

	if (argc != 2 && argc != 3)
		err_quit("usage: udpcli <Destination> [Port Default 7]");

    if (domain_parse(argv[1], ip, sizeof(ip), errinfo, sizeof(errinfo)) < 0)
        err_quit("Destination parse failed %s", errinfo);

    err_msg("Destination %s", ip);

	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(argc == 2 ? 7 : atoi(argv[2]));
	Inet_pton(AF_INET, ip, &servaddr.sin_addr);

#if 0
    if (su_peer_create((supeer_t*)&sar, (SA*)&servaddr, sizeof(servaddr)) < 0)
        err_quit("su_peer_create error");
#else
    if (su_peer_create_bind((supeer_t*)&sar, 10001, (SA*)&servaddr, sizeof(servaddr)) < 0)
        err_sys("su_peer_create_bind error");
#endif

    su_peer_reliable_request_handle_install(&sar, udpin_reliable);
    su_peer_ordinary_request_handle_install(&sar, udpin_ordinary);

	sar_cli_send_recv(stdin, &sar);
	sar_cli_send(stdin, &sar);

    while (1) sleep(1);

    exit(0);
}
