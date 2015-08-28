#include "yhsocket.h"


// create TCP/IP version 4 socket server
//-
// type: SOCK_STREAM, SOCK_DGRAM ...
// addr: struct sockaddr data
// alen: sizeof(struct sockaddr)
// qlen: The maximum length of the queue
//-
// [ret]: -1: create socket server failed, set errno
// [ret]: > 0: create successful, value is server socket
int create_socket_v4_server_for_addr
	(int type, const struct sockaddr *addr, socklen_t alen, int qlen)
{
	int is;
	int reuse = 1;

	if ((is = socket(addr->sa_family, type, 0)) < 0)
		goto errquit;
		
	/* 
	 * set SO_REUSEADDR for server socket 
	 */
	if (setsockopt(is, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int)) < 0)
		goto errquit;

	if (bind(is, addr, alen) < 0) 
		goto errquit;	

	if (type == SOCK_STREAM || type == SOCK_SEQPACKET) 
	{
		if (listen(is, qlen) < 0)
			goto errquit;
	}
	return is;
errquit:
	close(is);
	return -1;
}

// create TCP/IP version v4 socket server
//-
// type: SOCK_STREAM, SOCK_DGRAM ...
// ip  : x.x.x.x format ip address 
// port: service port
// listenlen: the length of listen list
//- 
// [ret]: -1: create socket server failed, set errno
// [ret]: > 0: create successful, value is server socket
int create_socket_v4_server(int type, char* ip, int port, int listenlen)
{
	struct sockaddr_in addr;

	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = inet_addr(ip);

	return create_socket_v4_server_for_addr
		(type, (struct sockaddr*)&addr, sizeof(struct sockaddr), listenlen);
}

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
int create_socket_v4_connect(int family, int type, const char* p_addr, int port)
{
	struct sockaddr_in saddr;
	int err, is;
	saddr.sin_port = htons(port);
	saddr.sin_family = family;
	err = inet_pton(family, p_addr, &saddr.sin_addr.s_addr);

	if (err == 0 || saddr.sin_port<=0)
		return -2;
	else if (err < 0)
		return -1;
		
	if ((is = socket(family, type, 0)) < 0)
		return -1;

	// connect timeout times
	struct timeval con_timeo = {30, 0};	
	setsockopt(is, SOL_SOCKET, SO_SNDTIMEO, &con_timeo, sizeof(con_timeo));

	if (connect(is, (struct sockaddr *) &saddr, sizeof(saddr)) < 0)
	{
		close(is);
		return -1;
	}
		
	return is;
}

// Send data to socket
//-
// fd  : destination socke
// buff: buffer
// len : buffer length
// flag: socket flags
// -
// [ret]: -1: error
//        errno set to indicate the error.
// [ret]: < len && > 0: error
//        Send incomplete length, Length is not len
// [ret]: > 0: Send completed successful.
int nsend(int fd, const void *buff, size_t len, int flag)
{
	size_t 	n;
	ssize_t ns;
	n = len;
	while (n > 0)
	{
		if ((ns = send(fd, buff, n, flag)) < 0)
		{
			if (errno == EINTR)
				continue;
			if (n == len)
				return(-1);	
			else
				break;
		}
		else if (ns == 0)
		{	
			break;
		}
		n -= ns; 	
		buff = (char*)buff + ns;
	}
	return len - n;
}



// Recvice data from socket
//-
// fd  : source socket
// buff: buffer
// len : buffer length
// flag: socket flags
// -
// [ret]: -1: error
//        errno set to indicate the error.
// [ret]: < len && > 0: error
//        Received incomplete length, Length is not len
// [ret]: > 0: Recv completed successful.
int nrecv(int fd, void *buff, size_t len, int flag)
{
	size_t n;
	ssize_t nr;

	n = len;
	while (n > 0) 
	{
		if ((nr = recv(fd, buff, n, flag)) < 0) 
		{
			if (errno == EINTR)
				continue;
			else if (len == n)
				return -1;
			else
				break;
		}
		else if (nr == 0)
			break;
		n -= nr;
		buff = (char*)buff +  nr;
	}
	return len - n;
}


char * read_line(int fd, char *buffer, int *_size_, int *_used_, int *_ret_status_)
{
	int index;
	int ret;
	int length = *_size_;
	char *new_buff = 0;

	*_ret_status_ = 0;
	if (*_size_ <= 0) {
		*_ret_status_ |= READLINE_SIZE_ERROR;
		goto no_alloc_out;    
	}

	for (index = 0; index < length; ++index)  {
		ret = read(fd, &buffer[index], 1);
		if (ret < 0){
			*_used_ = index;
			*_ret_status_ |= READLINE_FD_ERROR;  // status: fd read error
			goto no_alloc_out;    
		}
		if (ret == 0) {
			*_used_ = index;
			*_ret_status_ |= READLINE_FD_CLOSE;  // status: fd is closed
			goto no_alloc_out;    
		}
		else if(buffer[index] == '\n') {
			*_used_ = index + 1;
			*_ret_status_ |= READLINE_NORMAL;  // status: normal(no error, no closed, no alloc...)
			goto no_alloc_out;    
		}
	}

	new_buff = (char*)calloc(length<<1, 1);	
	if (!new_buff) {
		*_used_ = index;
		*_ret_status_ |= READLINE_ALLOC_ERROR;        // status: allocate memory error
		goto no_alloc_out;    
	}
	*_ret_status_ |= READLINE_NEED_FREE;        // status: alloc memory
	memcpy(new_buff, buffer, length);
	length <<= 1;
	*_size_ = length;

	while ((ret = read(fd, &new_buff[index], 1)) == 1) {
		if (new_buff[index] == '\n') {
			*_used_ = index + 1;
			//*_ret_status_ |= READLINE_NEED_FREE;  // status: new memory allocated 
			goto is_alloc_out;
		}
		if (index == length) {
			char * re_new;
			re_new = (char*)realloc(new_buff, length<<=1);
			if (!re_new) {
				*_used_ = *_size_;
				*_ret_status_ |= READLINE_REALLOC_ERROR; // status: reallocate memory error
				goto is_alloc_out;
			}
			new_buff = re_new;
			*_size_ = length;
		}
		++(*_used_);
		++index;
	}
	if (ret < 0) { // fd error
		*_ret_status_ |= READLINE_FD_ERROR; // status: fd read error
		goto is_alloc_out;
	}
	else if (ret == 0) {
		*_ret_status_ |= READLINE_FD_CLOSE;  // status: fd is closed
	}
	*_used_ = index;


is_alloc_out:
	return new_buff;

no_alloc_out:
	return 0;
}


int read_block(int fd, char *buff, int *bufflen, 
		void *tag, int taglen, int *ret)
{
	int rb;                                  // 每次读取的字节数
	const int buff_size = *bufflen;          // buff尺寸
	int rn = 0;
	
	/*
	 * 初始设置没找到标签
	 */
	*ret = 0;

	/* 
	 * buff空间耗尽时,预留一个位置放置0(考虑到方便处理可见字符) 
	 */
	buff[buff_size-1] = 0;
	
	if (!buff || buff_size <= 0 || !tag)
		return -2;                       // 传入参数错误
	
	/* 
	 * 预读结尾标签长度的内容,用以对比
	 */
	if (buff_size <= taglen)
	{
		rb = read(fd, buff, buff_size-1);
		rn = rb;
		*bufflen = rb;
		return rb;
	}
	if ((rb = read(fd, buff, taglen)) <= 0)
	{
		*bufflen = 0;
		return rb;
	}
	
	rn += rb;
	
//	int first = 1;
	char * const pbuff = buff;             // buff 首地址
	char * const pbend = buff + buff_size; // buff 尾地址
	char * const ptag = (char*)tag;                      // tag 首地址
	char * const pfend = (char*)tag + taglen;     // tag 尾地址
	char * prbuff = buff;                  // 游标(buff读取位置)
	char * prend;                                 // 游标(buff读取尾部位置)
	char * pcbuff;                                // 游标(buff比较位置)
	char * pctag;                                 // 游标(tag比较位置)
	
	/* 
	 * 对比和读取内容
	 */
	do {
		prend = prbuff + rb;
		pcbuff = prend - taglen;              // 指向新内容位
		pctag = ptag;                         // 比较标记复位

		while (	
				*pcbuff  == *pctag    // 对比内容
				&& pctag !=  pfend    // 是否tag尾
				&& pcbuff != pbend    // 是否buff尾
				&& pcbuff != prend    // 在读取到的范围内比较
			)
		{
			++pcbuff;
			++pctag;
		}
		
		/*
		 * 找到匹配完成标记,由于最多比较taglen个字符 
		 * 因此pcfuff达到此刻的读尾时,也可作为是判定条件之一
		 */
		if (pctag == pfend || pcbuff == prend)
		{
			*ret = 1;
			rn -= taglen;
			buff[rn] = 0;
			*bufflen = rn;
			return rn;
		}
		
		/*
		 * 在buff中下一次对比位置是buff的最后一个字节
		 * 说明buff空间已耗尽
		 */
		if (pcbuff == pbend)
			goto void_lack;
		
		/*
		 * 预判下一个读取位置是否buff的最后一个字节
		 * 如果不是，继续读取
		 * 如果是,buff空间耗尽,退出循环
		 */
		if (prbuff+1 < pbend)
		{
			prbuff += rb;
			if ((rb = read(fd, prbuff, 1)) <= 0)
			{
				*bufflen = prbuff - pbuff;
				return rb;
			}
			rn+=rb;
		}
		else
			goto void_lack;
		
	} while (1);
		
void_lack:
	/*
	 * 读取过程中
	 * 没有找到tag
	 * 已经达到了buff存放空间的最大
	 * (其实最后还是预留了一个字符的填充了'\0')
	 */
	*bufflen = buff_size-1;
	return *bufflen;
}

//******************************************************************************
#define QLEN	10
/*
 * Create a server endpoint of a connection.
 * Returns fd if all OK, <0 on error.
 */
int unix_domain_listen(const char *name)
{
	int					fd, len, err, rval;
	struct sockaddr_un	un;

	/* create a UNIX domain stream socket */
	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
		return(-1);

	unlink(name);	/* in case it already exists */

	/* fill in socket address structure */
	memset(&un, 0, sizeof(un));
	un.sun_family = AF_UNIX;
	strcpy(un.sun_path, name);
	len = offsetof(struct sockaddr_un, sun_path) + strlen(name);

	/* bind the name to the descriptor */
	if (bind(fd, (struct sockaddr *)&un, len) < 0) {
		rval = -2;
		goto errout;
	}

	if (listen(fd, QLEN) < 0) {	/* tell kernel we're a server */
		rval = -3;
		goto errout;
	}
	return(fd);

errout:
	err = errno;
	close(fd);
	errno = err;
	return(rval);
}
//******************************************************************************
#define STALE	30	/* client's name can't be older than this (sec) */

/*
 * Wait for a client connection to arrive, and accept it.
 * We also obtain the client's user ID from the pathname
 * that it must bind before calling us.
 * Returns new fd if all OK, <0 on error
 */
int unix_domain_accept(int listenfd, uid_t *uidptr)
{
	int					clifd, err, rval;
	time_t				staletime;
	struct sockaddr_un	un;
	struct stat			statbuf;
    socklen_t len;

	len = sizeof(un);
	if ((clifd = accept(listenfd, (struct sockaddr *)&un, &len)) < 0)
		return(-1);		/* often errno=EINTR, if signal caught */

	/* obtain the client's uid from its calling address */
	len -= offsetof(struct sockaddr_un, sun_path); /* len of pathname */
	un.sun_path[len] = 0;			/* null terminate */

	if (stat(un.sun_path, &statbuf) < 0) {
		rval = -2;
		goto errout;
	}
#ifdef	S_ISSOCK	/* not defined for SVR4 */
	if (S_ISSOCK(statbuf.st_mode) == 0) {
		rval = -3;		/* not a socket */
		goto errout;
	}
#endif
	if ((statbuf.st_mode & (S_IRWXG | S_IRWXO)) ||
		(statbuf.st_mode & S_IRWXU) != S_IRWXU) {
		  rval = -4;	/* is not rwx------ */
		  goto errout;
	}

	staletime = time(NULL) - STALE;
	if (statbuf.st_atime < staletime ||
		statbuf.st_ctime < staletime ||
		statbuf.st_mtime < staletime) {
		  rval = -5;	/* i-node is too old */
		  goto errout;
	}

	if (uidptr != NULL)
		*uidptr = statbuf.st_uid;	/* return uid of caller */
	unlink(un.sun_path);		/* we're done with pathname now */
	return(clifd);

errout:
	err = errno;
	close(clifd);
	errno = err;
	return(rval);
}
//******************************************************************************
#define	CLI_PATH	"/var/tmp/"		/* +5 for pid = 14 chars */
#define	CLI_PERM	S_IRWXU			/* rwx for user only */

/*
 * Create a client endpoint and connect to a server.
 * Returns fd if all OK, <0 on error.
 */
int unix_domain_connect(const char *name)
{
	int					fd, len, err, rval;
	struct sockaddr_un	un;

	/* create a UNIX domain stream socket */
	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
		return(-1);

	/* fill socket address structure with our address */
	memset(&un, 0, sizeof(un));
	un.sun_family = AF_UNIX;
	sprintf(un.sun_path, "%s%05d", CLI_PATH, getpid());
	len = offsetof(struct sockaddr_un, sun_path) + strlen(un.sun_path);

	unlink(un.sun_path);		/* in case it already exists */
	if (bind(fd, (struct sockaddr *)&un, len) < 0) {
		rval = -2;
		goto errout;
	}
	if (chmod(un.sun_path, CLI_PERM) < 0) {
		rval = -3;
		goto errout;
	}

	/* fill socket address structure with server's address */
	memset(&un, 0, sizeof(un));
	un.sun_family = AF_UNIX;
	strcpy(un.sun_path, name);
	len = offsetof(struct sockaddr_un, sun_path) + strlen(name);
	if (connect(fd, (struct sockaddr *)&un, len) < 0) {
		rval = -4;
		goto errout;
	}
	return(fd);

errout:
	err = errno;
	close(fd);
	errno = err;
	return(rval);
}
//******************************************************************************
