#include "yhevent.h"

static void fe_bind(fe_t *fe, em_t *em, int fd, int type)
{
    fe->event.data.ptr  = fe;
    fe->fd              = fd;
    fe->em              = em;
    fe->heap            = type;
}

// 栈上的自动变量 fe_t 初始化时候
//  绑定 em 和 fd, 设置堆标志 heap 为0
//  这样防止 fe_del 时错误的调用 free
void fe_init(fe_t *fe, em_t *em, int fd)
{
    fe_bind(fe, em, fd, 0);
}

// 从堆上获取一个 fe_t, 在初始化的时候
//  绑定 em 和 fd, 设置堆标志 heap 为1
//  这样保证 fe_del 的时候 free
fe_t * fe_new(em_t *em, int fd)
{
    fe_t * fe = (fe_t*)calloc(1, sizeof(fe_t));
    if (fe == 0) {
        err_ret("fe_new() calloc error[%d]", errno);
        return 0;
    }
    fe_bind(fe, em, fd, 1);
    return fe;
}
fe_t * Fe_new(em_t *em, int fd)
{
    fe_t *fe = fe_new(em, fd);
    if (fe == 0) exit(1);
    return fe;
}


void fe_del(fe_t *fe)
{
    if (fe == 0) return;
    fe_em_del(fe);
    if (fe->heap) free(fe);
}
void fe_set(fe_t *fe, int event, fe_cb_t cb)
{
    switch (event) {
        case EPOLLIN  : fe->in  = cb; break;
        case EPOLLOUT : fe->out = cb; break;
        case EPOLLPRI : fe->pri = cb; break;
        case EPOLLRDHUP : fe->rdhup = cb; break;
        case EPOLLONESHOT :
        case EPOLLET : break;
        default:
            return;
    };
    fe->event.events |= event;
}
void fe_unset(fe_t *fe, int event)
{
    fe->event.events &= ~event;
}
int fe_em_add(fe_t* fe)
{
    int ret = epoll_ctl(fe->em->epfd, EPOLL_CTL_ADD, fe->fd, &fe->event);
    if (ret < 0)
        err_ret("fe_em_add() epoll_ctl %d fd %d error[%d]"
                , fe->em->epfd, fe->fd, errno);
    return ret;
}
int fe_em_mod(fe_t* fe)
{
    int ret =  epoll_ctl(fe->em->epfd, EPOLL_CTL_MOD, fe->fd, &fe->event);
    if (ret < 0)
        err_ret("fe_em_mod() epoll_ctl %d fd %d error[%d]"
                , fe->em->epfd, fe->fd, errno);
    return ret;
}
int fe_em_del(fe_t* fe)
{
    int ret = epoll_ctl(fe->em->epfd, EPOLL_CTL_DEL, fe->fd, &fe->event);
    if (ret < 0)
        err_ret("fe_em_del() epoll_ctl %d fd %d error[%d]"
                , fe->em->epfd, fe->fd, errno);
    return ret;
}
void Fe_em_add(fe_t* fe)
{
    if (fe_em_add(fe) < 0) exit(1);
}
void Fe_em_mod(fe_t* fe)
{
    if (fe_em_mod(fe) < 0) exit(1);
}
void Fe_em_del(fe_t* fe)
{
    if (fe_em_del(fe) < 0) exit(1);
}
int setfd_nonblock(int fd)
{
    int status;
    if ((status = fcntl(fd, F_GETFL)) < 0) {
        err_ret("setfd_nonblock() fcntl F_GETFL error[%d]", errno);
        return -1;
    }
    status |= O_NONBLOCK;
    if (fcntl(fd, F_SETFL, status) < 0) {
        err_ret("setfd_nonblock() fcntl F_SETFL error[%d]", errno);
        return -1;
    }
    return 0;
}
int setsock_rcvtimeo(int fd, int second, int microsecond)
{
    struct timeval rcv_timeo = {second, microsecond};
    if (setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&rcv_timeo,sizeof(rcv_timeo))< 0) {
        err_ret("setsock_rcvtimeo() setsockopt SO_RCVTIMEO error[%d]", errno);
        return -1;
    }
    return 0;
}
void Setfd_nonblock(int fd)
{
    if ( setfd_nonblock(fd) < 0 ) exit(1);
}
void Setsock_rcvtimeo(int fd, int second, int microsecond)
{
    if ( setsock_rcvtimeo(fd, second, microsecond) < 0 ) exit(1);
}
/* create epoll manager */
em_t* em_open(int maxfds, int timeout,
        em_cb_t before, em_cbn_t events, em_cb_t after)
{
    em_t *em = 0;
    if (maxfds <= 0) { errno = EINVAL; return 0; }
    em = (em_t*)calloc(1, sizeof(em_t) +
            (maxfds+1) * sizeof(struct epoll_event));
    if (em == 0) { /*errno =  ENOMEM;*/ return 0; }
    em->timeout = timeout;
    em->maxfds  = maxfds;
    em->before  = before;
    em->event   = events;
    em->after   = after;
    em->run     = 0;
    if ( (em->epfd = epoll_create(maxfds) )  < 0 )  goto err_out;
    if ( (errno = pthread_mutex_init(&em->lock, 0)) != 0 )  goto err_out;
    return em;
err_out:
    if (em->epfd   >= 0) { close(em->epfd);   }
    if (em         != 0) { free(em);          }
    return 0;
}
em_t* Em_open(int maxfds, int timeout, em_cb_t before,
        em_cbn_t events, em_cb_t after)
{
    em_t *em;
    if ((em = em_open(maxfds, timeout, before, events, after)) == 0)
    { err_ret("Em_open() em_open error[%d]", errno); exit(1); }
    return em;
}
static void * em_thread(void *p)
{
    em_t *em = (em_t*)p;
    int n, nfds;
    void *ptr;
    fe_t *fe = 0;

    while (em->run) {
        if (em->before) em->before(em);

        nfds = epoll_wait(em->epfd, em->evlist, em->maxfds, em->timeout);
        if (em->event) em->event(em, nfds);

        for (n = 0; n < nfds; ++n) {
            ptr = em->evlist[n].data.ptr;
            if (ptr == 0) continue;
            fe = (fe_t*)ptr;
            if  (    em->evlist[n].events & EPOLLIN    && fe->in)
                fe->in (fe);
            else if (em->evlist[n].events & EPOLLOUT   && fe->out)
                fe->out(fe);
            else if (em->evlist[n].events & EPOLLPRI   && fe->pri)
                fe->pri(fe);
            else if (em->evlist[n].events & EPOLLRDHUP && fe->rdhup)
                fe->rdhup(fe);
            else {
                if(em->evlist[n].events & EPOLLIN )
                    log_msg("Unhandled EPOLLIN %x fd %d", fe, fe->fd);
                else if(em->evlist[n].events & EPOLLOUT)
                    log_msg("Unhandled EPOLLOUT %x fd %d", fe, fe->fd);
                else if(em->evlist[n].events & EPOLLPRI)
                    log_msg("Unhandled EPOLLPRI %x fd %d", fe, fe->fd);
                else if(em->evlist[n].events & EPOLLRDHUP)
                    log_msg("Unhandled EPOLLRDHUP %x fd %d", fe, fe->fd);
                else
                    log_msg("Unhandled events[0x%x] %x fd %d",
                            em->evlist[n].events, fe, fe->fd);
            }
        }

        if (em->after) em->after(em);
    }
    return (void*)0;
}
int em_run(em_t *em, int n)
{
    pthread_t tid;
    pthread_attr_t attr;

    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 1024*1024); //set stack size 1M
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    pthread_mutex_lock(&em->lock);
    if (em->run) {
        pthread_mutex_unlock(&em->lock);
        return 0;
    }
    em->run = 1;
    pthread_mutex_unlock(&em->lock);

    int i;
    for (i = 0; i < n; i++) {
        if ((errno = pthread_create(&tid, &attr, em_thread, em)) != 0) {
            err_ret("em_run() pthread_create error[%d]", errno);
            return -1;
        }
    }
    pthread_attr_destroy(&attr);
    return 0;
}
void Em_run(em_t *em, int n)
{
    if (em_run(em, n) < 0) exit(1);
}
int em_set_timeout(em_t *em, int timeout)
{
    int old = em->timeout;
    em->timeout = timeout;
    return old;
}

int close_all_fd(void)
{
    DIR *dir;
    struct dirent *entry, _entry;
    int retval, rewind, fd;
    dir = opendir("/dev/fd");
    if (dir == NULL)
        return -1;
    rewind = 0;
    while (1) {
        retval = readdir_r(dir, &_entry, &entry);
        if (retval != 0) {
            errno = -retval;
            retval = -1;
            break;
        }
        if (entry == NULL) {
            if (!rewind)
                break;
            rewinddir(dir);
            rewind = 0;
            continue;
        }
        if (entry->d_name[0] == '.')
            continue;
        fd = atoi(entry->d_name);
        if (dirfd(dir) == fd)
            continue;
#ifdef MYPERF
        if (fd == 1)
            continue;
#endif
        retval = close(fd);
        if (retval != 0)
            break;
        rewind = 1;
    }
    closedir(dir);
    return retval;
}
