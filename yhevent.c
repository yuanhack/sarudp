#include "yhevent.h" 

static void fd_event_init_(fd_event *fe, epoll_manager *em, int fd, int type)
{
    fe->event.data.ptr  = fe; 
    fe->fd              = fd;
    fe->em              = em;
    fe->heap            = 0;
}
void fd_event_init(fd_event *fe, epoll_manager *em, int fd)
{
    fd_event_init_(fe, em, fd, 0);
}

// 从堆上获取一个 fd_event_t 并且初始化 
// 自动调用 初始化 绑定 em 和 fd, 设置堆标志
fd_event_t * fd_event_new(epoll_manager_t *em, int fd)
{
    fd_event_t * fe = (fd_event_t*)calloc(1, sizeof(fd_event_t));
    if (fe == 0) {
        err_ret("fd_event_new() calloc error[%d]", errno);
        return 0;
    }
    fd_event_init_(fe, em, fd, 1);
    return fe;
}
fd_event_t * Fd_event_new(epoll_manager_t *em, int fd)
{
    fd_event_t *fe = fd_event_new(em, fd);
    if (fe == 0) exit(1);
    return fe;
}


void fd_event_del(fd_event *fe)
{
    if (fe == 0) return;
    if (fe->heap) free(fe);
}
void fd_event_set(fd_event *fe, int event, fd_event_callback cb)
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
void fd_event_unset(fd_event *fe, int event)
{
    fe->event.events &= ~event;
}
int em_fd_event_add(fd_event* fe)
{
    int ret = epoll_ctl(fe->em->epfd, EPOLL_CTL_ADD, fe->fd, &fe->event);
    if (ret < 0) err_ret("em_fd_event_add() epoll_ctl %d fd %d error[%d]"
            , fe->em->epfd, fe->fd, errno);
    return ret;
}
int em_fd_event_mod(fd_event* fe)
{
    int ret =  epoll_ctl(fe->em->epfd, EPOLL_CTL_MOD, fe->fd, &fe->event);
    if (ret < 0) err_ret("em_fd_event_mod() epoll_ctl %d fd %d error[%d]"
            , fe->em->epfd, fe->fd, errno);
    return ret;
}
int em_fd_event_del(fd_event* fe)
{
    int ret = epoll_ctl(fe->em->epfd, EPOLL_CTL_DEL, fe->fd, &fe->event);
    if (ret < 0) err_ret("em_fd_event_del() epoll_ctl %d fd %d error[%d]"
            , fe->em->epfd, fe->fd, errno);
    return ret;
}
void Em_fd_event_add(fd_event* fe)
{
    if (em_fd_event_add(fe) < 0) exit(1);
}
void Em_fd_event_mod(fd_event* fe)
{
    if (em_fd_event_mod(fe) < 0) exit(1);
}
void Em_fd_event_del(fd_event* fe)
{
    if (em_fd_event_del(fe) < 0) exit(1);
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
/* * create epoll manager */
epoll_manager* em_open(int maxfds, int timeout, 
        em_callback before, em_callback events, em_callback after)
{
    epoll_manager *em = 0; 
    if (maxfds <= 0) { errno = EINVAL; return 0; }
    em = (epoll_manager*)calloc(1, sizeof(epoll_manager) + 
            (maxfds+1) * sizeof(struct epoll_event));
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
epoll_manager* Em_open(int maxfds, int timeout, em_callback before, 
        em_callback events, em_callback after)
{
    epoll_manager *em;
    if ((em = em_open(maxfds, timeout, before, events, after)) == 0) 
    { err_ret("Em_open() em_open error[%d]", errno); exit(1); }
    return em;
}
static void * em_thread(void *p)
{
    epoll_manager *em = (epoll_manager*)p;
    int n;
    void            *ptr;
    struct fd_event *fe = 0;
    pthread_detach(em->tid);
    while (em->run) {
        if (em->before) em->before(em);
        em->nfds = epoll_wait(em->epfd, em->evlist, em->maxfds, em->timeout);
        if (em->event) em->event(em);
        for (n = 0; n < em->nfds; ++n) {
            ptr = em->evlist[n].data.ptr;
            if (ptr == 0) continue;
            fe = (fd_event*)ptr;
            if(em->evlist[n].events & EPOLLIN ) if(fe->in ) { fe->in (fe); }
            if(em->evlist[n].events & EPOLLOUT) if(fe->out) { fe->out(fe); }
            if(em->evlist[n].events & EPOLLPRI) if(fe->pri) { fe->pri(fe); }
        }
        if (em->after) em->after(em);
    }
    return (void*)0;
}
int em_run(epoll_manager *em)
{
    int ret;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 1024*1024); //set stack size 1M

    pthread_mutex_lock(&em->lock);
    if (em->run) { pthread_mutex_unlock(&em->lock); return 0; }
    em->run = 1;
    pthread_mutex_unlock(&em->lock);

    if ((ret = pthread_create(&em->tid, &attr, em_thread, em)) != 0) {
        errno = ret;
        err_ret("em_run() pthread_create error[%d]", errno);
        return -1;
    }
    pthread_attr_destroy(&attr);
    return 0;
}
void Em_run(epoll_manager *em)
{
    if (em_run(em) < 0) exit(1);
}
int em_set_timeout(epoll_manager *em, int timeout)
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
