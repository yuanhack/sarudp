#include "yhservice.h"
#include "yharguments.h"
#include "yhevent.h"
#include "yhsocket.h"
#include "yherror.h"

#include "sarudp.h"



void before(const epoll_manager * const em)
{
    log_msg("before");
}
void event(const epoll_manager * const em)
{
    log_msg("epoll_wait ret %d", em->nfds);
    if (em->nfds < 0) { 
        if (errno == EAGAIN || errno == EINTR) return;
        err_msg("epoll_wait error %d: %s", errno, strerror(errno)); 
        exit(1); 
    }
}
void after(const epoll_manager * const em)
{
    log_msg("after");
}

void service_create(void *p)
{
    //supeer_t *psar = (supeer_t *)p;
}
