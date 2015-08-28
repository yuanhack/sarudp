#ifndef __YH_YHEPOLL_H__
#define __YH_YHEPOLL_H__

#include <sys/epoll.h>
#include <string.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/socket.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <dirent.h>
#include "yherror.h"

typedef struct fd_event fd_event, fd_event_t, *fd_event_handle, *fd_event_handle_t;
typedef struct epoll_manager epoll_manager, epoll_manager_t, *epoll_manager_handle, *epoll_manager_handle_t;

typedef void  fd_event_callback(fd_event * fe);
typedef void  em_callback(const epoll_manager * const em);

///////////////////////////////////////////////////////////////////////////////
#ifndef offsetof
#define offsetof(type, member) \
    (size_t)&(((type *)0)->member)
#endif

#ifndef container_of
#define container_of(ptr, type, member)  \
    ({\
     const typeof(((type *)0)->member) * __mptr = (ptr);\
     (type *)((char *)__mptr - offsetof(type, member)); \
     })
#endif

#ifndef struct_entry 
#define struct_entry(ptr, type,  member) container_of(ptr, type, member)
#endif

///////////////////////////////////////////////////////////////////////////////
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * 
 *  关于fd 在epoll_wait 中返回后的状态
 *	EPOLLIN ：文件描述符可以读（包括对端SOCKET正常关闭）；
 * 	EPOLLOUT：文件描述符可以写；
 * 	EPOLLPRI：文件描述符有紧急的数据可读（有带外数据）；
 * 	EPOLLERR：文件描述符发生错误；
 * 	EPOLLHUP：文件描述符被挂断；
 * 	EPOLLRDHUP：对端关闭；
 * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * * fd event object * * * * * * * * * * * * * * * * * */
// event.events = EPOLLxxx | ...; event.data.ptr = fd_event address;
struct fd_event {
    int fd;                     // file descriptor
    struct epoll_event event;   
    epoll_manager       *em;    // epoll manager
    void                *ptr;   // user data ptr, user alloc/free

    unsigned int heap; // heap flag is !0 alloc, stack flag is 0 

    // event callback:
    fd_event_callback * in;
    fd_event_callback * out;
    fd_event_callback * pri;
    fd_event_callback * rdhup;
};

/* * epoll manager object */
struct epoll_manager
{
    pthread_mutex_t     lock;    // safe lock
    pthread_t           tid;     // epoll thread id
    em_callback *       before;  // epoll_wait before
    em_callback *       event;   // epoll_wait after,Before the event processing
    em_callback *       after;   // After the completion of the event processing
    int                 run;     // epoll manager thread control
    int                 epfd;    // epoll_wait par1 epfd
    int                 timeout; // epoll_wait par4 timeout
    int                 maxfds;  // epoll_wait par3 maxevents
    int                 nfds;    // epoll_wait's return value
    struct epoll_event evlist[]; // epoll_wait par2 events
};


#ifdef __cplusplus
extern "C"
{ 
#endif

#ifdef __cplusplus
    epoll_manager* em_open(int maxfds, int timeout, 
            em_callback before=0, em_callback events=0, em_callback after=0);
    epoll_manager* Em_open(int maxfds, int timeout, 
            em_callback before=0, em_callback events=0, em_callback after=0);
#else
    epoll_manager* em_open(int maxfds, int timeout, em_callback before, 
            em_callback events, em_callback after);
    epoll_manager* Em_open(int maxfds, int timeout, em_callback before, 
            em_callback events, em_callback after);
#endif
    void Em_run(epoll_manager *em);
    int  em_run(epoll_manager *em);
    int  em_set_timeout(epoll_manager *em, int timeout);

    // 调用 epoll_ctl 执行 ADD MOD DEL
    //  返回 epoll_ctl的返回值
    //  出错时打印出错消息, 返回epoll_ctl的返回码
    int  em_fd_event_add(fd_event* fe);
    int  em_fd_event_mod(fd_event* fe);
    int  em_fd_event_del(fd_event* fe);

    // 调用 epoll_ctl 执行 ADD MOD DEL
    //   出错时打印出错消息并且退出程序
    void Em_fd_event_add(fd_event* fe);
    void Em_fd_event_mod(fd_event* fe);
    void Em_fd_event_del(fd_event* fe);

    int  setfd_nonblock(int fd);
    void Setfd_nonblock(int fd);
    int  setsock_rcvtimeo(int fd, int second, int microsecond);
    void Setsock_rcvtimeo(int fd, int second, int microsecond);
    int close_all_fd(void);

    fd_event_t * fd_event_new(epoll_manager_t *em, int fd);
    fd_event_t * Fd_event_new(epoll_manager_t *em, int fd);
    void fd_event_init(fd_event *fhp, epoll_manager *em, int fd);
    void fd_event_del(fd_event *p);

#ifdef __cplusplus
    void fd_event_set(fd_event *fh, int event, fd_event_callback cb = 0);
#else
    void fd_event_set(fd_event *fh, int event, fd_event_callback cb);
#endif

    void fd_event_unset(fd_event *fe, int event);

#ifdef __cplusplus 
} 
#endif

#endif /* __YH_YHEPOLL_H__ */
