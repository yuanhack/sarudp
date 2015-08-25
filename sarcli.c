#include "sarudp.h"
#include "wrapfunc.h"

#include <stdio.h>

#ifndef MAXLINE
#define MAXLINE     4096    /* max text line length */
#endif

void
sar_cli(FILE *fp, sarudpmgr_t *psar, const SA *pservaddr, socklen_t servlen)
{
	ssize_t	n;
	char	sendline[MAXLINE], recvline[MAXLINE + 1];

    do {
        if (Fgets(sendline, MAXLINE, fp) == NULL) {
            fprintf(stdout, "\n");
            return ;
        }

        n = sarudp_send_recv(psar, sendline, strlen(sendline),
                recvline, MAXLINE, pservaddr, servlen);
        if (n < 0)
            err_quit("sarudp_send_recv error");

        recvline[n] = 0;	/* null terminate */
        fprintf(stdout, "\e[32m%s\e[m", recvline); 
        fflush(stdout);
    } while (1);
}
