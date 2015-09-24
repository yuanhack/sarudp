#include "wrapfunc.h"
#include "error.h"
#include "sarudp_peer.h"

#include <stdio.h>
#include <arpa/inet.h>
#include <sys/time.h>

const char *
Inet_ntop(int family, const void *addrptr, char *strptr, size_t len)
{
	const char	*ptr;

	if (strptr == NULL)		/* check for old code */
		err_quit("NULL 3rd argument to inet_ntop");
	if ( (ptr = inet_ntop(family, addrptr, strptr, len)) == NULL)
		err_sys("inet_ntop error");		/* sets errno */
	return(ptr);
}

void
Inet_pton(int family, const char *strptr, void *addrptr)
{
	int		n;

	if ( (n = inet_pton(family, strptr, addrptr)) < 0)
		err_sys("inet_pton error for %s", strptr);	/* errno set */
	else if (n == 0)
		err_quit("inet_pton error for %s", strptr);	/* errno not set */

	/* nothing to return */
}

void
Gettimeofday(struct timeval *tv, void *foo)
{
    if (gettimeofday(tv, foo) == -1)
        err_sys("gettimeofday error");
    return;
}

char *   
Fgets(char *ptr, int n, FILE *stream)
{
    char    *rptr;

    if ( (rptr = fgets(ptr, n, stream)) == NULL && ferror(stream))
        err_sys("fgets error");

    return (rptr); 
}

void     
Sendmsg(int fd, const struct msghdr *msg, int flags)
{
    unsigned int    i;
    ssize_t         nbytes;

    nbytes = 0; /* must first figure out what return value should be */
    for (i = 0; i < msg->msg_iovlen; i++)
        nbytes += msg->msg_iov[i].iov_len;

    if (sendmsg(fd, msg, flags) != nbytes)
        err_sys("sendmsg error");
}
