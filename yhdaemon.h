#ifndef __YH_YHDAEMON_H__
#define __YH_YHDAEMON_H__

#include <syslog.h>
#include <unistd.h>    
#include <fcntl.h>

#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>

#include "yherror.h"

#ifdef __cplusplus
extern "C"
{
#endif

#pragma pack(push)
#pragma pack(1)
#pragma pack(pop)

 
// If nochdir is zero, daemon_init() changes the calling process's current working directory to  the  root  directory ("/"); 
//      otherwise, the current working directory is left unchanged.
// If  noclose is zero, daemon() redirects standard input, standard output and standard error to /dev/null; 
//      otherwise, no changes are made to these file descriptors. 
void daemon_init(const char *pname, int facility, int nochdir, int noclose);


#ifdef __cplusplus
}
#endif
#endif /* __YH_YHDAEMON_H__ */
