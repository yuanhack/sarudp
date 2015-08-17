#include "unp.h"
#include "sarudp.h"
#include "domain_parse.h"

void
sar_cli(FILE *fp, sarudpmgr_t *psar, const SA *pservaddr, socklen_t servlen);

int
main(int argc, char **argv)
{
	struct sockaddr_in	servaddr;
    sarudpmgr_t sar;

	if (argc != 2)
		err_quit("usage: udpcli <IPaddress>");


    //int domain_parse(const char *str, char *buff, int len, char *errinfo, int errlen);
    char ip[256], errinfo[256];

    if (domain_parse(argv[1], ip, sizeof(ip), errinfo, sizeof(errinfo)) < 0)
        err_quit("domain parse error %s", errinfo);

    err_msg("to address %s", ip);

	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(7);
	Inet_pton(AF_INET, ip, &servaddr.sin_addr);

    if (sarudp_init((sarudpmgr_t*)&sar, AF_INET, 0) < 0)
        err_quit("sarudp_init error");

	sar_cli(stdin, &sar, (SA *) &servaddr, sizeof(servaddr));

	exit(0);
}
