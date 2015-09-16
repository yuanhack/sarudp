#include "sarudp.h"
#include "domain_parse.h"
#include "wrapfunc.h"

#include <sys/signal.h>

void sar_cli_send(FILE *fp, supeer_t *psar);
void sar_cli_send_recv(FILE *fp, supeer_t *psar);

void udpin_reliable(supeer_t *psar, char *buff, int len)
{
    if (len > 0) 
        printf("1 recv svr len %d info %s\n", len, buff);
    su_peer_reply(psar, buff, len);

//    char recvbuff[32];
//    if ((len = su_peer_request(psar, "hello\n", 6, recvbuff, sizeof(recvbuff))) > 0)
//        write(1, recvbuff, len);
    
}
void udpin_ordinary(supeer_t *psar, char *buff, int len)
{
    if (len > 0) 
        printf("2 recv svr len %d info %s\n", len, buff);
    su_peer_reply(psar, "world\n", 6);
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

//    if (su_peer_create((supeer_t*)&sar, (SA*)&servaddr, sizeof(servaddr)) < 0)
//        err_quit("su_peer_create error");

    if (su_peer_create_bind((supeer_t*)&sar, 9999, (SA*)&servaddr, sizeof(servaddr)) < 0)
        err_sys("su_peer_create_bind error");

    reliable_request_handle_install(&sar, udpin_reliable);
    ordinary_request_handle_install(&sar, udpin_ordinary);

	sar_cli_send_recv(stdin, &sar);
	//sar_cli_send(stdin, &sar);

    exit(0);
}
