#include "sarudp.h"
#include	"unp.h"

void
sar_cli(FILE *fp, sarudpmgr_t *psar, const SA *pservaddr, socklen_t servlen)
{
	ssize_t	n;
	char	sendline[MAXLINE], recvline[MAXLINE + 1];

    do {
        fprintf(stdout, "---- input: "); 
        fflush(stdout);
        if (Fgets(sendline, MAXLINE, fp) == NULL) {
            fprintf(stdout, "\n");
            return ;
        }

        n = Sarudp_send_recv(psar, sendline, strlen(sendline),
                recvline, MAXLINE, pservaddr, servlen);

        recvline[n] = 0;	/* null terminate */
        fprintf(stdout, "---- echo : %s", recvline); 
        fflush(stdout);
    } while (1);
}
