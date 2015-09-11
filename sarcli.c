#include "sarudp.h"
#include "wrapfunc.h"

#include <stdio.h>

#define MAXLINE     4096    /* max text line length */

void sar_cli_send_recv(FILE *fp, supeer_t *psar)
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

void sar_cli_send(FILE *fp, supeer_t *psar)
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

