#include "sarudp_peer.h"
#include "domain_parse.h"
#include "wrapfunc.h"

#include <sys/signal.h>

// handle SIGINT
void sigint(int no);

// handler reliable data come in
void udpin_reliable(supeer_t *psar, char *buff, int len);
// handle ordinary data come in
void udpin_ordinary(supeer_t *psar, char *buff, int len);

// test client ordinary
void cli_su_peer_send(FILE *fp, supeer_t *psar);

// test client reliable
void cli_su_peer_request(FILE *fp, supeer_t *psar);
void cli_su_peer_request_random(supeer_t *psar);

int main(int argc, char **argv)
{
	struct sockaddr_in	servaddr;
    supeer_t sar;
    char ip[256], errinfo[256];

    signal(SIGINT, sigint);

	if (argc != 2 && argc != 3)
		err_quit("usage: udpcli <Destination> [Port Default 7]");

    /* Targer address domain parse */
    if (domain_parse(argv[1], ip, sizeof(ip), errinfo, sizeof(errinfo)) < 0)
        err_quit("Destination parse failed %s", errinfo);

    log_msg("Destination %s", ip);

	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = PF_INET;
    servaddr.sin_port = htons(argc == 2 ? 7 : atoi(argv[2]));
	Inet_pton(AF_INET, ip, &servaddr.sin_addr);

#if 1
    /* Using random free port */
    if (su_peer_create(&sar, (SA*)&servaddr, sizeof(servaddr)) < 0)
        err_quit("su_peer_create error");
#else
    /* Using bind configure port */
    if (su_peer_create_bind(&sar, 65534, (SA*)&servaddr, sizeof(servaddr)) < 0)
        err_sys("su_peer_create_bind error");
#endif

    /* Install the reliable request handler */
    su_peer_reliable_request_handle_install(&sar, udpin_reliable);
    /* Install the ordinary request handler */
    su_peer_ordinary_request_handle_install(&sar, udpin_ordinary);

#if 1
    // send reliable data to target
	cli_su_peer_request(stdin, &sar);
    //cli_su_peer_request_random(&sar);
#else
    // send ordinary data to target
	cli_su_peer_send(stdin, &sar);
#endif

    exit(0);
}

void udpin_reliable(supeer_t *psar, char *buff, int len)
{
    struct sockaddr_in s4;
    socklen_t slen;

    su_peer_getsrcaddr(psar, (SA*)&s4, &slen);

    printf("reliable recv from %s:%d datagrams len %d " ColorGre"%s\n"ColorEnd, 
            inet_ntoa(s4.sin_addr), ntohs(s4.sin_port), len, buff);

    su_peer_reply(psar, buff, len);
}
void udpin_ordinary(supeer_t *psar, char *buff, int len)
{
    struct sockaddr_in s4;
    socklen_t slen;

    su_peer_getsrcaddr(psar, (struct sockaddr*)&s4, &slen);

    printf("ordinary recv from %s:%d datagram len %d " ColorGre"%s\n"ColorEnd, 
            inet_ntoa(s4.sin_addr), ntohs(s4.sin_port), len, buff);

}

void sigint(int no)
{
    log_msg(ColorRed "\nSIGINT\n" ColorEnd);
    exit(0);
}

#define MAXLINE     4096    /* max text line length */

void cli_su_peer_request(FILE *fp, supeer_t *psar)
{
	ssize_t	n;
	char	sendline[MAXLINE], recvline[MAXLINE + 1] = {0};

    do {
        if (Fgets(sendline, MAXLINE, fp) == NULL) {
            fprintf(stdout, "\n");
            return ;
        }

        n = su_peer_request(psar, sendline, strlen(sendline), recvline, MAXLINE);
        if (n < 0)
            err_ret("su_peer_send_recv error");

        recvline[n] = 0;	/* null terminate */
        fprintf(stdout, "\e[32m%s\e[m", recvline); 
        fflush(stdout);
    } while (1);
}

void cli_su_peer_request_random(supeer_t *psar)
{
	ssize_t	n;
	char	sendline[MAXLINE], recvline[MAXLINE + 1] = {0};

    srand(time(0));

    do {
        snprintf(sendline, sizeof(sendline), "%d\n", rand());
        n = su_peer_request(psar, sendline, strlen(sendline), recvline, MAXLINE);
        if (n < 0)
            err_ret("su_peer_request error");

        recvline[n] = 0;	/* null terminate */
        fprintf(stdout, "\e[32m%s\e[m", recvline); 
        fflush(stdout);

        usleep(1);     // microsecond
    } while (1);
}

void cli_su_peer_send(FILE *fp, supeer_t *psar)
{
	ssize_t	n;
	char	sendline[MAXLINE];

    do {
        if (Fgets(sendline, MAXLINE, fp) == NULL) {
            fprintf(stdout, "\n");
            return ;
        }

        n = su_peer_send(psar, sendline, strlen(sendline));
        if (n < 0)
            err_quit("su_peer_send error");
        else
            log_msg("su_peer_send ok");

    } while (1);
}
