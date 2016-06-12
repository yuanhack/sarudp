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

typedef struct fd_event fd_event_t, fe_t;
typedef struct epoll_manager epoll_manager_t, em_t;

typedef void  fe_cb_t(fe_t * fe);
typedef void  em_cb_t(const em_t * const em);
typedef void  em_cbn_t(const em_t * const em, int n);

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

#ifndef _REENTRANT
#define _REENTRANT
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
    em_t                *em;    // epoll manager
    void                *ptr;   // user data ptr, user alloc/free

    unsigned int heap; // heap flag is !0 alloc, stack flag is 0

    // event callback:
    fe_cb_t * in;
    fe_cb_t * out;
    fe_cb_t * pri;
    fe_cb_t * rdhup;
};

/* * epoll manager object */
struct epoll_manager
{
    pthread_mutex_t     lock;    // safe lock
    em_cb_t *           before;  // epoll_wait before
    em_cbn_t *          event;   // epoll_wait after,Before the event processing
    em_cb_t *           after;   // After the completion of the event processing
    int                 run;     // epoll manager thread control
    int                 epfd;    // epoll_wait par1 epfd
    int                 timeout; // epoll_wait par4 timeout
    int                 maxfds;  // epoll_wait par3 maxevents
    struct epoll_event evlist[]; // epoll_wait par2 events
};


#ifdef __cplusplus
extern "C"
{
#endif

#ifdef __cplusplus
    em_t* em_open(int maxfds, int timeout,
            em_cb_t before=0, em_cbn_t events=0, em_cb_t after=0);
    em_t* Em_open(int maxfds, int timeout,
            em_cb_t before=0, em_cbn_t events=0, em_cb_t after=0);
#else
    em_t* em_open(int maxfds, int timeout, em_cb_t before,
            em_cbn_t events, em_cb_t after);
    em_t* Em_open(int maxfds, int timeout, em_cb_t before,
            em_cbn_t events, em_cb_t after);
#endif
    void Em_run(em_t *em, int n);
    int  em_run(em_t *em, int n);
    int  em_set_timeout(em_t *em, int timeout);

    // 调用 epoll_ctl 执行 ADD MOD DEL
    //  返回 epoll_ctl的返回值
    //  出错时打印出错消息, 返回epoll_ctl的返回码
    int  fe_em_add(fe_t* fe);
    int  fe_em_mod(fe_t* fe);
    int  fe_em_del(fe_t* fe);

    // 调用 epoll_ctl 执行 ADD MOD DEL
    //   出错时打印出错消息并且退出程序
    void Fe_em_add(fe_t* fe);
    void Fe_em_mod(fe_t* fe);
    void Fe_em_del(fe_t* fe);

    int  setfd_nonblock(int fd);
    void Setfd_nonblock(int fd);
    int  setsock_rcvtimeo(int fd, int second, int microsecond);
    void Setsock_rcvtimeo(int fd, int second, int microsecond);
    int close_all_fd(void);

    fe_t * fe_new(em_t *em, int fd);
    fe_t * Fe_new(em_t *em, int fd);
    void fe_init(fe_t *fe, em_t *em, int fd);
    void fe_del (fe_t *p);

#ifdef __cplusplus
    void fe_set(fe_t *fh, int event, fe_cb_t cb = 0);
#else
    void fe_set(fe_t *fh, int event, fe_cb_t cb);
#endif

    void fe_unset(fe_t *fe, int event);

#ifdef __cplusplus
}
#endif

#endif /* __YH_YHEPOLL_H__ */
