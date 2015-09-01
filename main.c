#include "sarudp.h"
#include "domain_parse.h"
#include "wrapfunc.h"

void sar_cli_send(FILE *fp, supeer_t *psar);
void sar_cli_send_recv(FILE *fp, supeer_t *psar);

void udpin(supeer_t *pin, char *buff, int len)
{
    if (len > 0)
        printf("recv svr len %d info %s\n", len, buff);
}
  
int
main(int argc, char **argv)
{
	struct sockaddr_in	servaddr;
    supeer_t sar;
    char ip[256], errinfo[256];

	if (argc != 2 && argc != 3)
		err_quit("usage: udpcli <Destination> [Port Default 7]");

    if (domain_parse(argv[1], ip, sizeof(ip), errinfo, sizeof(errinfo)) < 0)
        err_quit("Destination parse failed %s", errinfo);

    err_msg("Destination %s", ip);

	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(argc == 2 ? 7 : atoi(argv[2]));
	Inet_pton(AF_INET, ip, &servaddr.sin_addr);

    if (su_peer_new((supeer_t*)&sar, (SA*)&servaddr, 
                sizeof(servaddr), udpin) < 0)
        err_quit("sarudp_init error");

	//sar_cli_send_recv(stdin, &sar);
	sar_cli_send(stdin, &sar);

	exit(0);
}
