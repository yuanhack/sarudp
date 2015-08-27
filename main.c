//#include "unp.h"
#include "sarudp.h"
#include "domain_parse.h"
#include "wrapfunc.h"

void sar_cli(FILE *fp, sarudpmgr_t *psar, const SA *pservaddr, socklen_t servlen);

void udpin(sarudpmgr_t *pin, char *buff, int len)
{
    if (len > 0)
        printf("recv svr len %d info %s\n", len, buff);
}
  
int
main(int argc, char **argv)
{
	struct sockaddr_in	servaddr;
    sarudpmgr_t sar;
    char ip[256], errinfo[256];

	if (argc != 2 && argc != 3)
		err_quit("usage: udpcli <Domain Or IPaddress> [Port Default 7]");

    if (domain_parse(argv[1], ip, sizeof(ip), errinfo, sizeof(errinfo)) < 0)
        err_quit("domain parse failed %s", errinfo);

    err_msg("Dest address %s", ip);

	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(argc == 2 ? 7 : atoi(argv[2]));
	Inet_pton(AF_INET, ip, &servaddr.sin_addr);

    if (sarudp_create((sarudpmgr_t*)&sar, AF_INET, 0, udpin) < 0)
        err_quit("sarudp_init error");

	sar_cli(stdin, &sar, (SA *) &servaddr, sizeof(servaddr));

	exit(0);
}
