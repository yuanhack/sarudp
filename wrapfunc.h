#ifndef __YH_WRAPFUNC_H__
#define __YH_WRAPFUNC_H__

#include <stdio.h>

#include <sys/types.h>
#include <sys/socket.h>

#ifdef __cplusplus
extern "C"
{
#endif

void     Gettimeofday(struct timeval *, void *);

void	 Fclose(FILE *);
FILE	*Fdopen(int, const char *);
char	*Fgets(char *, int, FILE *);
FILE	*Fopen(const char *, const char *);
void	 Fputs(const char *, FILE *);

const char		*Inet_ntop(int, const void *, char *, size_t);
void			 Inet_pton(int, const char *, void *);

void	 Sendmsg(int, const struct msghdr *, int);

#ifdef __cplusplus
}
#endif

#endif /* __YH_WRAPFUNC_H__ */


