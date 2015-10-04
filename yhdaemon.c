#include "yhdaemon.h"


extern int	daemon_proc;	/* defined in yh error.c */


typedef void (*sighandler_t)(int);

sighandler_t 
Signal(int signo, sighandler_t func)    /* for our signal() function */
{
    sighandler_t sigfunc;

    if ( (sigfunc = signal(signo, func)) == SIG_ERR)
        err_sys("signal error");
    return(sigfunc);
}

pid_t
Fork(void)
{
  pid_t   pid;

  if ( (pid = fork()) == -1)
    err_sys("fork error");
  return(pid);
}
int 
Open(const char *pathname, int flags)
{
    int fd;
    fd = open(pathname, flags);
    if (fd < 0)
        err_sys("open error");
    return fd;
}
void
Dup2(int fd1, int fd2)
{
    if (dup2(fd1, fd2) == -1)
        err_sys("dup2 error");
}

void
Close(int fd)
{
    if (close(fd) < 0)
        err_sys("close error");
}

void
daemon_init(const char *pname, int facility, int nochdir, int noclose)
{
    pid_t	pid;

    if ( (pid = Fork()) != 0)
        exit(0);			/* parent terminates */

    /* 41st child continues */
    setsid();				/* become session leader */

    Signal(SIGHUP, SIG_IGN);
    if ( (pid = Fork()) != 0)
        exit(0);			/* 1st child terminates */

    /* 42nd child continues */
    if (nochdir == 0)
        chdir("/");				/* change working directory */

    umask(0);				/* clear our file mode creation mask */

    if (noclose == 0) {
        int fd = Open("/dev/null", O_RDWR);
        Dup2(fd, 0);
        Dup2(fd, 1);
        Dup2(fd, 2);
        if (fd > 2) 
            Close(fd);
    }

    daemon_proc = 1;		/* for our err_XXX() functions */

    openlog(pname, LOG_PID, facility);
}
