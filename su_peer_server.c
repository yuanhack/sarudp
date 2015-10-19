#include "sarudp_peer.h"
#include "domain_parse.h"
#include "wrapfunc.h"

#include <sys/signal.h>

// test client ordinary
void sar_cli_send(FILE *fp, su_peer_t *psar);
// test client reliable
void sar_cli_send_recv(FILE *fp, su_peer_t *psar);

// handler reliable data come in
void udpin_reliable(su_peer_t *psar, char *buff, int len);
// handle ordinary data come in
void udpin_ordinary(su_peer_t *psar, char *buff, int len);

// handle SIGINT
void sigint(int no);

/* *
 * This program working promiscuous mode
 * Using macro
 * #define promiscuous_mode
 * compiling SARUDP Library
 * */
int main(int argc, char **argv)
{
    su_peer_t sar;

    signal(SIGINT, sigint);

	if (argc != 1 && argc != 2)
		err_quit("usage: %s [Port Default 10000]", argv[0]);

#if 0
    /* The address is not used as a client, can be arbitrarily set  */
	struct sockaddr_in servaddr;
	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(65535);
	Inet_pton(AF_INET, "127.0.0.1", &servaddr.sin_addr);
#else
	struct sockaddr_in6 servaddr;
	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin6_family = AF_INET6;
    servaddr.sin6_port = htons(65535);
	//Inet_pton(AF_INET6, "::ffff:127.0.0.1", &servaddr.sin6_addr); // for test localhost IPv6
	Inet_pton(AF_INET6, "::1", &servaddr.sin6_addr); // for test localhost IPv6
#endif

#if 0
    if (su_peer_create(&sar, (SA*)&servaddr, sizeof(servaddr)) < 0)
        err_quit("su_peer_create error");
#else
    if (su_peer_create_bind(&sar, argc == 1 ? 10000 : atoi(argv[1]),
                (SA*)&servaddr, sizeof(servaddr)) < 0)
        err_sys("su_peer_create_bind error");
    log_msg("listen port %s successful", argc == 1 ? "10000" : argv[1]);
#endif

    su_peer_reliable_request_handle_install(&sar, udpin_reliable);
    su_peer_ordinary_request_handle_install(&sar, udpin_ordinary);

#if 1
    while (1) 
        pause();
#else
    sleep(30);
    su_peer_destroy(&sar);
#endif

    exit(0);
}

void udpin_reliable(su_peer_t *psar, char *buff, int len)
{
    static long long c=0;
    SAUN s;
    char ip[INET6_ADDRSTRLEN];
    int port;

    su_peer_getsrcaddr(psar, &s);

    //su_get_ip_port(&s, ip, sizeof(ip), &port); // small ip address
    su_get_ip_port_f(&s, ip, sizeof(ip), &port); // fulll ip address 

    printf("reliable recv from %s:%d datagram len %d\n", ip, port, len);
    printf("reliable recv len %d datagrams "
            ColorGre "%s" ColorEnd " count = %llu\n",
            len, buff, c+=len);

    int n;
#if 1
    n = su_peer_reply(psar, buff, len);
#else
    n = su_peer_reply_ack(psar);
#endif
    if (n < 0) {
        ERR_RET("su_peer_reply error");
    }
}
void udpin_ordinary(su_peer_t *psar, char *buff, int len)
{
    static long long c=0;
    SAUN s;
    char ip[INET6_ADDRSTRLEN];
    int port;

    su_peer_getsrcaddr(psar, &s);

    //su_get_ip_port(&s, ip, sizeof(ip), &port); // small ip address
    su_get_ip_port_f(&s, ip, sizeof(ip), &port); // fulll ip address 

    printf("ordinary recv from %s:%d datagrams len %d\n", ip, port, len);
    printf("ordinary recv len %d datagrams "
            ColorYel "%s" ColorEnd " count = %llu\n",
            len, buff, c+=len);

    //su_peer_reply(psar, buff, len); // call is invalid, ordinary packet don't handle reply
    
    // response data (echo)
    if (su_peer_send(psar, buff, len) != len) { // call is valid
        err_ret("su_peer_send error");
    }
}

void sigint(int no)
{
    log_msg(ColorRed "\nSIGINT\n" ColorEnd);
    exit(0);
}
