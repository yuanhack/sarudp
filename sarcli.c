#include "sarudp.h"
#include	"unp.h"

void
sar_cli(FILE *fp, sarudpmgr_t *psar, const SA *pservaddr, socklen_t servlen)
{
	ssize_t	n;
	char	sendline[MAXLINE], recvline[MAXLINE + 1];

	while (Fgets(sendline, MAXLINE, fp) != NULL) {

		n = Sarudp_send_recv(psar, sendline, strlen(sendline),
						 recvline, MAXLINE, pservaddr, servlen);

		recvline[n] = 0;	/* null terminate */
		Fputs(recvline, stdout);
	}
}
