#include "sarudp.h"
#include "domain_parse.h"
#include "wrapfunc.h"

#include <sys/signal.h>

// test client ordinary
void sar_cli_send(FILE *fp, supeer_t *psar);
// test client reliable
void sar_cli_send_recv(FILE *fp, supeer_t *psar);

// handler reliable data come in
void udpin_reliable(supeer_t *psar, char *buff, int len);
// handle ordinary data come in
void udpin_ordinary(supeer_t *psar, char *buff, int len);

// handle SIGINT
void sigint(int no);


int main(int argc, char **argv)
{
	struct sockaddr_in	servaddr;
    supeer_t sar;
    char ip[256], errinfo[256];

    signal(SIGINT, sigint);

	if (argc != 1 && argc != 2)
		err_quit("usage: %s [Port Default 10000]", argv[0]);

    /* The address is not used as a client, can be arbitrarily set  */
	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
    servaddr.sin_port = 65534;
	Inet_pton(AF_INET, "127.0.0.1", &servaddr.sin_addr);

#if 0
    if (su_peer_create((supeer_t*)&sar, (SA*)&servaddr, sizeof(servaddr)) < 0)
        err_quit("su_peer_create error");
#else
    if (su_peer_create_bind((supeer_t*)&sar, argc == 1 ? 10000 : atoi(argv[1]), 
                (SA*)&servaddr, sizeof(servaddr)) < 0)
        err_sys("su_peer_create_bind error");
    log_msg("listen port %s successful", argc == 1 ? "10000" : argv[1]);
#endif

    su_peer_reliable_request_handle_install(&sar, udpin_reliable);
    su_peer_ordinary_request_handle_install(&sar, udpin_ordinary);

    while (1) 
        pause();

    exit(0);
}

void udpin_reliable(supeer_t *psar, char *buff, int len)
{
    static long long c=0;
    struct sockaddr_in s4;
    socklen_t slen;

    su_peer_getsrcaddr(psar, (struct sockaddr*)&s4, &slen);
    printf("reliable recv from %s:%d\n", inet_ntoa(s4.sin_addr), ntohs(s4.sin_port));

    if (len > 0)
        printf("reliable recv len %d datagrams " ColorGre "%s" ColorEnd 
                " count = %llu\n"ColorEnd, len, buff, c+=len);
    su_peer_reply(psar, buff, len);
}
void udpin_ordinary(supeer_t *psar, char *buff, int len)
{
    static long long c=0;
    struct sockaddr_in s4;
    socklen_t slen;

    su_peer_getsrcaddr(psar, (struct sockaddr*)&s4, &slen);
    printf("ordinary recv from %s:%d\n", inet_ntoa(s4.sin_addr), ntohs(s4.sin_port));

    if (len > 0)
        printf("ordinary recv len %d datagrams " ColorYel "%s" ColorEnd 
                " count = %llu\n"ColorEnd, len, buff, c+=len);

    su_peer_reply(psar, buff, len);
}

void sigint(int no)
{
    log_msg(ColorRed "\nSIGINT\n" ColorEnd);
    exit(0);
}
