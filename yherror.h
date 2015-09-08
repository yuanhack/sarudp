#ifndef __YH_ERROR_H__
#define __YH_ERROR_H__

#include <stdarg.h>		/* ANSI C header file */
#include <syslog.h>		/* for syslog() */

#include  <stdarg.h>		/* ANSI C header file */
#include  <syslog.h>		/* for syslog() */
#include  <errno.h>
#include  <stdlib.h>
#include  <stdio.h>
#include  <string.h>

#define YH_ERROR_MAXLINE 1024
extern int daemon_proc;		/* set nonzero by daemon_init() */

#ifdef __cplusplus
extern "C"
{
#endif

#pragma pack(push)
#pragma pack(1)
#pragma pack(pop)


/* Nonfatal error related to a system call.
 * Print a message and return. */

/* $$.ix [err_ret]~function,~source~code$$ */
void
err_ret(const char *fmt, ...);

/* Fatal error related to a system call.
 * Print a message and terminate. */

/* $$.ix [err_sys]~function,~source~code$$ */
void
err_sys(const char *fmt, ...);


/* Fatal error related to a system call.
 * Print a message, dump core, and terminate. */

/* $$.ix [err_dump]~function,~source~code$$ */
void
err_dump(const char *fmt, ...);


/* Nonfatal error unrelated to a system call.
 * Print a message and return. */

/* $$.ix [err_msg]~function,~source~code$$ */
void
err_msg(const char *fmt, ...);
#define log_msg(fmt, ...) err_msg(fmt, ##__VA_ARGS__)


/* Fatal error unrelated to a system call.
 * Print a message and terminate. */

/* $$.ix [err_quit]~function,~source~code$$ */
void
err_quit(const char *fmt, ...);

#ifdef __cplusplus
}
#endif
#endif /* __YH_ERROR_H__ */
