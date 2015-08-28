#ifndef __RCYH_YHSOCKET_H__
#define __RCYH_YHSOCKET_H__

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <errno.h>
#include <string.h>
#include <stddef.h>
#include <fcntl.h>
#include <time.h>

#ifdef __cplusplus
extern "C"
{
#endif

#ifndef _REENTRANT
	#define _REENTRANT
#endif

// create socket server of version TCP/IPv4
//-
// type: SOCK_STREAM, SOCK_DGRAM ...
// addr: struct sockaddr data
// alen: sizeof(struct sockaddr)
// qlen: The maximum length of the queue
//-
// [ret]: -1: create socket server failed
// [ret]: > 0: create successful, value is server socket for accept()
int create_socket_v4_server_for_addr
	(int type, const struct sockaddr *addr, socklen_t alen, int qlen);

#define create_tcp_v4_server_for_addr(addr, qlen) \
		create_socket_v4_server_for_addr(SOCK_STREAM, \
			(struct sockaddr*)addr, sizeof(struct sockaddr), qlen)
#define create_udp_v4_server_for_addr(addr, qlen) \
		create_socket_v4_server_for_addr(SOCK_DGRAM, \
			(struct sockaddr*)addr, sizeof(struct sockaddr), qlen)

// create socket server of version TCP/IPv4
//-
// family: AF_INET ...
// type  : SOCK_STREAM, SOCK_DGRAM ...
// p_addr: x.x.x.x ip address
// port  : number port
//-
// [ret] : -2: ip or port error, no set errno value
// [ret] : -1: socket error, is set errno value
// [ret] : > 0: successful connection socket
int create_socket_v4_server(int type, char* ip, int port, int listenlen);

#define create_tcp_v4_server(ip,port,listenlen) \
		create_socket_v4_server(SOCK_STREAM,ip, port, listenlen)
#define create_udp_v4_server(ip,port,listenlen) \
		create_socket_v4_server(SOCK_DGRAM, ip, port, listenlen)

// Create socket version 4 connection
//-
// family: AF_INET ...
// type  : SOCK_STREAM, SOCK_DGRAM ...
// p_addr: x.x.x.x ip address
// port  : number port
//-
// [ret] : -2: ip or port error, no set errno value
// [ret] : -1: socket error, is set errno value
// [ret] : > 0: successful connection socket
int create_socket_v4_connect(int family, int type, 
		const char* p_addr, int port);
		
#define create_tcp_v4_connect(p_ip_addr,port) \
		create_socket_v4_connect(AF_INET, SOCK_STREAM, p_ip_addr, port)
#define create_udp_v4_connect(p_ip_addr,port) \
		create_socket_v4_connect(AF_INET, SOCK_DGRA, p_ip_addr, port)

int unix_domain_listen(const char *name);
int unix_domain_accept(int listenfd, uid_t *uidptr);
int unix_domain_connect(const char *name);

int nsend(int fd, const void *p_data, size_t len, int flag);
int nrecv(int fd, void *buff, size_t len, int flag);

/******************************************************************************/
/* read line function define */
/* 状态值相关位表示相关状况 */ 
#define READLINE_SUCCESS          0x0000
#define READLINE_NORMAL           0x0000  /* 正常执行完操作返回
					     没有错误，没有内存申请操作 */

#define READLINE_ALLOC            0x0001
#define READLINE_NEED_FREE        0x0001  /* 内存分配行为标志位，
					     该位为1表示 有内存申请操作
					     传入的buffer的尺寸不够容纳
					     正在读取的一行长度, 
					     函数内在堆上重新申请了新的堆空间, 
					     将之前读到内容拷贝到新空间之后继
					     续 读取,返回的堆内存需要释放,
					     否则泄露 */
#define READLINE_ALLOC_ERROR      0x0002  /* 内存分配错误标志位 
					     该位为1表示 在分配堆内存时失败 */
#define READLINE_REALLOC_ERROR    0x0004  /* 内存分配错误标志位
					     该位为1表示 
					     在重新为堆内存扩容时失败 */
	/* READLINE_ALLOC_ERROR 和 
	 * READLINE_REALLOC_ERROR 只有一个会被设置 */

#define READLINE_FD_ERROR         0x0010  /* 描述符源状态
					     该位为1表示 
					     从fd读取内容的时候发生一个错误 */
#define READLINE_FD_CLOSE         0x0020  /* 描述符源状态
					     该位为1表示读取到fd已关闭/断开 */
	/* READLINE_FD_ERROR 和 
	 * READLINE_FD_CLOSE 只有一个会被设置  */
#define READLINE_SIZE_ERROR       0x0040  /* 传入参数buffer长度错误标志 
					     该位为1表示 
					     调用函数时传入的buffer尺寸
					     是小于等于0的错误数值 */

// 是否需要释放
#define IS_NEEDFREE(status)         (status & READLINE_NEED_FREE)
#define IS_ALLOCATION(status)       IS_NEEDFREE(status)

// 是否是分配内存时错误
#define IS_ALLOC_ERROR(status)      (status & READLINE_ALLOC_ERROR)
// 是否是对分配的内存扩展时错误
#define IS_REALLOC_ERROR(status)    (status & READLINE_REALLOC_ERROR)
// 是否是描述符错误
#define IS_FD_ERROR(status)         (status & READLINE_FD_ERROR)
// 是否是描述符关闭
#define IS_FD_CLOSE(status)         (status & READLINE_FD_CLOSE)
// 是否是参数传入缓存尺寸错误
#define IS_SIZE_ERROR(status)       (status & READLINE_SIZE_ERROR)

// 成功，无内存分配
#define IS_SUCCESS_NORMAL(status)   (!(status | READLINE_NORMAL))
// 成功, 有内存分配
#define IS_SUCCESS_NEWMEM(status)   ((status & READLINE_NEED_FREE) && \
					!(status & READLINE_ALLOC_ERROR) && \
					!(status & READLINE_REALLOC_ERROR))

/******************************************************************************
 * 从fd读取一行内容放入buffer中 
 * buffer空间不足时将从堆中申请空间 
 * 将所有内容放入新空间以继续读取行剩余内容
 * 参数: 
 *     fd: 所有可应用于read的描述符
 *     buffer: 初始缓存
 *     _size_: 传入: 初始缓存尺寸, 
 *             传出: 最终放置行内容的缓存尺寸
 *     _used_: 传入: 无
 *             传出: 最终放置行内容的缓存被使用的大小
 *     _ret_status_: 传入: 无
 *                   传出：函数执行后的状态结果
 * 返回值:
 *     0 : 没有分配内存
 *     !0: 分配的堆内存地址
 *****************************************************************************/
char * read_line(int fd, char *buffer, int *_size_, 
		int *_used_, int *_ret_status_);


/******************************************************************************
 * 从fd读取内容放到buff中, 
 * 		传入bufflen是buff的初始长度
 * 		传出bufflen是buff的被使用长度
 * 读取持续到遇到tag标志或者buff缓冲区耗尽
 *   参数返回值ret的值指出了是否是由于遇到tag标志而停止
 *
 * ** 注意： 函数返回时, 若是遇到标记而返回，
 *           那当前标记是已经从fd里拿出来了的
 *           在外部需要使用标记的时候需要手工存取
 *
 * fd:     描述符
 * buff:   存放缓冲区地址, 读取内容存于此
 * tag:    标志内容指针地址
 * taglen: 标志长度
 *
 * * * * * * * * * * * * * * * 
 *
 * bufflen: 传入和返回参数
 *       入参: 存放缓冲区的长度
 *       出参: 存放到buff的内容长度
 *
 * ret: 返回参数 
 *       1, 结束时遇到了标记(遇到标记而返回)
 *       0, 结束时未遇到标记
 *
 * return-int: 
 * 	大于0 buff的内容长度
 * 	等于0 fd关闭
 * 	小于0 出错
 *****************************************************************************/
int read_block(int fd, char *buff, int *bufflen, 
		void *tag, int taglen, int *ret);

#ifdef __cplusplus
}
#endif
#endif /* __RCYH_YHSOCKET_H__ */
