#include "sarudp_peer.h"
#include "domain_parse.h"
#include "wrapfunc.h"

#include <sys/signal.h>

// handle SIGINT
void sigint(int no);

// handler reliable data come in
void udpin_reliable(su_peer_t *psar, char *buff, int len);
// handle ordinary data come in
void udpin_ordinary(su_peer_t *psar, char *buff, int len);

// test client ordinary
void cli_su_peer_send(FILE *fp, su_peer_t *psar);

// test client reliable
void cli_su_peer_request(FILE *fp, su_peer_t *psar);
void cli_su_peer_request_random(su_peer_t *psar);

int main(int argc, char **argv)
{
    su_peer_t sar;
    char ip[256], errinfo[256];

    signal(SIGINT, sigint);

    /* Targer address domain parse */
    if (domain_parse(argv[1], ip, sizeof(ip), errinfo, sizeof(errinfo)) < 0)
        err_quit("Destination parse failed %s", errinfo);
    log_msg("Destination %s", ip);

	if (argc != 2 && argc != 3)
		err_quit("usage: udpcli <Destination> [Port Default 7]");

#if 0
	struct sockaddr_in servaddr;
	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = PF_INET;
    servaddr.sin_port = htons(argc == 2 ? 7 : atoi(argv[2]));
	Inet_pton(AF_INET, ip, &servaddr.sin_addr);
#else
	struct sockaddr_in6 servaddr;
    char ip6[INET6_ADDRSTRLEN];
	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin6_family = PF_INET6;
    servaddr.sin6_port = htons(argc == 2 ? 7 : atoi(argv[2]));

    // IPv4 to IPv6
    snprintf(ip6, sizeof(ip6),"::ffff:%s", ip);
    log_msg("Target IPv6 %s", ip6);
	Inet_pton(AF_INET6, ip6, &servaddr.sin6_addr.s6_addr);
#endif

#if 1
    /* Using random free port */
    if (su_peer_create(&sar, (SA*)&servaddr, sizeof(servaddr)) < 0)
        err_quit("su_peer_create error");
#else
    /* Using bind configure port */
    if (su_peer_create_bind(&sar, 10000, (SA*)&servaddr, sizeof(servaddr)) < 0)
        err_sys("su_peer_create_bind error");
#endif

    /* Install the reliable request handler */
    su_peer_reliable_request_handle_install(&sar, udpin_reliable);
    /* Install the ordinary request handler */
    su_peer_ordinary_request_handle_install(&sar, udpin_ordinary);

#if 1
    // send reliable data to target
	//cli_su_peer_request(stdin, &sar);
    cli_su_peer_request_random(&sar);
#else
    // send ordinary data to target
	cli_su_peer_send(stdin, &sar);
#endif

    return 0;
    exit(0);
}

void udpin_reliable(su_peer_t *psar, char *buff, int len)
{
    SAUN saddr;
    char ip[INET6_ADDRSTRLEN];
    int port;

    su_peer_getsrcaddr(psar, &saddr);
    su_get_ip_port(&saddr, ip, sizeof(ip), &port);

    printf("reliable recv from %s:%d datagrams len %d "
            ColorGre "%s\n" ColorEnd,
            ip, port, len, buff);

    su_peer_reply(psar, buff, len);
}
void udpin_ordinary(su_peer_t *psar, char *buff, int len)
{
    SAUN saddr;
    char ip[INET6_ADDRSTRLEN];
    int port;

    su_peer_getsrcaddr(psar, &saddr);
    su_get_ip_port(&saddr, ip, sizeof(ip), &port);

    printf("ordinary recv from %s:%d datagram len %d "
            ColorGre "%s\n" ColorEnd,
            ip, port, len, buff);
}

void sigint(int no)
{
    log_msg(ColorRed "\nSIGINT\n" ColorEnd);
    exit(0);
}

#define MAXLINE     4096    /* max text line length */

void cli_su_peer_request(FILE *fp, su_peer_t *psar)
{
	ssize_t	n, ret;
	char sendline[MAXLINE], recvline[MAXLINE + 1];
    char outline[MAXLINE + 128];

    do {
        if (Fgets(sendline, MAXLINE, fp) == NULL) {
            fprintf(stdout, "\n");
            return ;
        }

        ret = su_peer_request(psar, sendline, strlen(sendline), recvline, MAXLINE);
        if (ret < 0)
            err_ret("su_peer_send_recv error");
        else if (ret > 0) {
            /* Foreign Host Receive successful and have a response */
            recvline[ret] = 0;	/* null terminate */
            n = snprintf(outline, sizeof(outline), "Response: \e[32m%s\e[m", recvline); 
            write(2, outline, n);
        } else {
            fprintf(stdout, "Foreign Host Receive successful\n"); 
        }
    } while (1);
}

void cli_su_peer_request_random(su_peer_t *psar)
{
	ssize_t	n, m;
	char	sendline[MAXLINE], recvline[MAXLINE + 1] = {0};

    srand(time(0));

    do {
        n = snprintf(sendline, sizeof(sendline), "%05d", rand()%10000);
        m = n;
        log_msg("send request  %d[%s]", n, sendline);
        n = su_peer_request(psar, sendline, n, recvline, MAXLINE);
        if (n < 0) {
            err_ret("su_peer_request error");
            n = su_peer_request_retry(psar, sendline, strlen(sendline), recvline, MAXLINE);
            if (n < 0) {
                err_ret("su_peer_request_retry error");
                break;
            }
        }

        recvline[n] = 0;	/* null terminate */
        log_msg("recv response %d[\e[32m%s\e[m]", n, recvline);

        if (memcmp(sendline, recvline, m) != 0) {
            err_quit("checkout data failure");
        }
        log_msg("checkout data pass");

        usleep(10 * 1000);     // microsecond
    } while (1);
}

void cli_su_peer_send(FILE *fp, su_peer_t *psar)
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
