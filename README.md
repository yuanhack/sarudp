# sarudp 协议

[TOC]

---
##说明

sarudp 是 `SYN-ACK-Retransfer UDP`的缩写，是增加了传输可靠性的 UDP 协议。
>在 UDP 基础上实现了请求重传和应答重传。

sarudp 同时具有 UDP 和 TCP 的优点，可应用于各种模式的开发，并且可同时支持 IPv6 和 IPv4 应用程序的开发。sarudp 在收到请求包后，在处理函数中可以提取出对方的 IP和Port ， 编程时标识和记忆 IP和Port 即可知道对方的身份，使用 sarudp 的 su_serv_t 创建的服务，可以应对任意数量的 su_peer_t 客户端。

> sarudp 没有占用大量文件描述符的问题，所以不用担心所处理的终端上限。

sarudp 的 request 类型函数采用`请求/应答`模式工作，发送一包数据后等待应答，收到应答或超时后返回。因此非并发模式下有序地调用 request 类时，对方收到的数据也是有序的。在不关心数据有序性的情况下，request 可任意调用。<br>

sarudp 的 send 类型函数直接向对方发送数据然后返回，就像普通的 UDP 数据 sendto 那样。<br>

>sarudp 在实现上把应答放在应用程序调用而不是`协议层`，由使用者决定`是否应答`，`何时应答`和`如何应答`，预留了足够的灵活性，仅将`请求重传`和`应答重传`在协议层实现`自动处理`。<br>

## 首部
###定义
| 8 bit  | 8 bit | 16 bit  | 32 bit      | 32bit       |
| :----- | :-----| :------ | :---------- | :---------- |
| action | type  | session id | sequence number| timestamp when send |
###解释
|Item     | Explain| Value  |
| :----   | :----- | :----- |
|action   | 数据包类型，用于区分 请求/应答 包  | 0xFF/0xFE   |
|type     | 可靠性标志，用于标识 可靠/不可靠 包 | 0x01/0x00   |
|session  | 会话ID，作为红黑树 key 的一部分 | 0 ~ 2^16    |
|sequence | 本包序列号，用于识别对应的请求/应答包 | 0 ~ 2^32 |
|timestamp| 发包时间戳，用于接收到应答时的 RTT 计算 | 0 ~ 2^32 |

session  id 主要用于鉴别以绑定端口方式创建的数据发送端是否重启。调用创建函数时分配不同的 sid  便于对方识别会话是否同一会话。<br>

sarudp 中定义了两种数据类型，reliable 类型和 ordinary 类型，reliable 类型的数据是增加了传输可靠性的数据，具有重传机制；ordinary 类型的数据是普通 UDP 数据，没有重传机制。

接收端收到请求包后，应答时将改变 action 字段的值为 0xfe，然后将应答包发往请求端，其它字段的值不改变。

## 实现
sarudp 使用`缓存应答 和 请求重传-应答重传` 解决可靠性问题。request 类型的函数用于发送请求数据，请求发送后等待应答，从应答和等待超时上判断数据是否到达，是否进行重传。<br>

>为了支持客户端可以将大量并发请求同时发送的情况，采用缓存应答的实现方式，而没有采用确定对方应答收到后立即清理前一个应答缓存的这种方式，这种方式虽然节省内存但是效率很低，不适合大并发量开发。并发式调用 request 类型函数发送数据不能保证数据包之间的到达时序。<br>
>为了实现应答重传，sarudp 占用了一定内存资源，在应答发送之后立即对应答数据进行缓存，如果应答在途中丢失，当再次收到该请求时直接从缓存中取出暂存的应答数据重传应答，缓存的应答数据在超出设定的时长后清理。<br>

```
sarudp 设计了su_peer_t 和 su_serv_t 结构，分别针对客户端和服务端角色，
在功能上分别实现了 “普通”和“增加了可靠性” 的传输接口。
```	
<span id="重传"><span><br><br>
###1. 重传
理论上 UDP 包最大长度可以是 2^16 字节大小，其合理值是传输链路的 MTU 1500 字节。但传输途中无法预知数据包将经过何种网络环境，数据包在途径某个 "分片窄带" 环境时可能被分片传输，最终在到达目的地址后重组还原，如果某一个分片丢失，整个包将重组失败，就造成了这个包传输失败，需要重传整个数据包。<br>

sarudp_comm.h 文件中的`REALDATAMAX`宏设置了 sarudp 处理单个数据包的最大尺寸，为了降低丢包概率，其最优值应小于等于网络中可能经过所有路由的标准 MTU 值 576 字节大小，减去20 字节 IP 首部，减去 8 字节 UDP 首部，减去 12 字节 sarudp 首部。<br>
```
REALDATAMAX 最优值应是 576-20-8-12 = 536
```
其值越大，分片可能越多，在网络传输中越容易发生丢包。

<span id="请求重传"><span><br>
####请求重传
增加了可靠性的 数据请求/应答接收 由 request 类型的函数进行操作。request 函数发送数据包后会等待对端的应答，如在一定时间内没有收到应答，那么将重新发包，包在传输途中丢失的情况有以下2种: 
```
1. 请求包在到达对端途中丢失，对端没有收到
2. 应答包在到达本端途中丢失，本地没有收到
```
无论何种情况丢包，request 将重新发包，重试 `RTT_MAXNREXMT`次后如仍没有收到应答，返回-1，同时设置 errno 为 ETIMEOUT <br>
可以通过调整参数宏决定包的重发次数和应答数据的缓存时长，在 unprtt.h 中有宏定义<br>
	
	RTT_MAXNREXMT 最大重传次数(秒)
	RTT_MAXRTO    最大重传间隔(秒)

> 对 重传次数和重传间隔 的合理设置 在 [缓存](#缓存跳转) 章节进行讨论。
* request 接口的工作流程：<br>
调用 request 发送数据，然后等待应答，同时计算等待超时和下次重发包的时间。如果一直没有收到对方应答，将重试发送 `RTT_MAXNREXMT` 次请求后返回-1，同时 errno 被设置为 ETIMEOUT。
如果收到应答，调用时提供的缓冲区将被填充应答数据，函数返回值为应答的数据长度，如果返回值为0，表示对方发送应答时没有携带数据过来。<br>
request 发送的数据将由数据接收方安装的 reliable类型数据处理函数收到并处理，应答是由对方调用 reply 接口返回的。

> 请求重传参考了 《UNIX网络编程卷1：套接字联网API》第三版 22.5 章节中的算法实现。

普通数据没有应答。send 类型函数用于普通数据发送，此类函数发送的数据包将由对方安装的 ordinary 类型数据处理函数收到，这种数据没有实现应答，在数据处理函数内调用 reply 类型函数是无效的，但是可以在数据处理函数中调用 request 或 send 类型函数向数据源端发送数据。

<span id="应答重传"><span><br>
####应答重传
作为接收数据的一端，付出少量内存资源和红黑树查找代价实现应答重传。在数据处理函数中，当调用 reply 函数发送应答包后，sarudp 将缓存 reliable 数据，如果应答包在中途丢失，再次收到对方的请求后将自动应答。<br>
关于调用 reply 处理应答，存在以下几种情形：<br>
* 如果携带数据，对方为 request 提供的缓冲区将接收到应答数据，其返回值为数据长度；
* 如果不携带数据，对方 request 函数返回0；
* 如果不调用应答函数，对方 request 将超时返回 -1；

<span id="缓存">  </span><br><br>
###2. 缓存
sarudp 在 首次收到请求包 和 首次发送应答包 时，用`红黑树节点`进行数据缓存，同时将该节点加入`循环链表`，红黑关系用于查询，链表关系用于缓存过期清理。<br>
如果包在传输途中丢失，再次收到同一请求包时将直接在`协议层重传应答`，不会再次将请求递送到`数据处理函数`，也不会再次加入缓存。<br>

sarudp 在开发过程中，对于下面列举的参数进行了大量的传输测试:
```
#define RTT_MAXNREXMT    4   // unprtt.h
#define RTT_MAXRTO      12   // unprtt.h
#define CACHETIMEOUT    90   // sarudp_comm.h
```

设置 4 次重传，12秒重传最大间隔和 90 秒缓存是个比较合理的值，这是在编译时确定的，可以自行进行合理调整。<br>
* 如果应用的网络环境状况严峻，可适当增加重试次数，适当减小重试间隔，适当调整缓存时间。 <br>

>但更多的重试次数和更小的重试间隔，以及更大的缓存时长，往往会增加网络存在的问题。更大的缓存时长可以增加包重传的有效期，但往往会让服务将占用更多的内存资源。<br>

* sarudp 在开发过程中使用北京，香港，美国硅谷的主机进行相互数据传输测试，表现良好。<br>
* sarudp 在丢包率不高的网络上表现良好，丢包率至少小于50%。
	
`需要注意的是：`
```
重传次数和间隔的时长总和不要超过缓存时间，如果缓存的包被超时清理，
重传过来的包将当成新数据被递送数据处理函数中。一般将其设计为缓存时长的一半，
这样的话当 request 发送数据失败以后可尝试调用 request_retry 进行重试。
```
<span id="清理"><span><br><br>
###3. 清理
新缓存总是追加到循环列表的队尾，按插入时间很自然的进行了排序；而过期检测总是从队列首部进行，如果超时则清理，然后检测下一个，直到下一个节点没有过期或整个缓存列表清理完毕。<br>

---

##数据定义和接口函数

###基本结构定义
su_peer_t 主要在客户端使用，结构体在 sarudp_peer.h 中定义；<br>
su_serv_t 主要在服务器中使用，结构定义在 sarudp_serv.h 中。<br>
sarudp_comm.h 中定义了 一些共用的部分：<br>
* SAUN 联合同时兼容 IPv6 和 IPv4 格式的地址；
* suhdr_t 结构体是 sardup 首部定义；
* frames_t 结构体是地址数据容器，链表的节点。
* cache_t 结构体是 frames_t 的容器，红黑树的节点。
* rb_key_cache 结构体是红黑树查表时候使用的key定义。

<span id="创建"><span><br>
###函数说明
####1. 创建
执行创建操作，资源申请，参数初始化和启动数据接收服务。

<span id="创建1"><span><br>
#####su_peer_t 的创建
```
int su_peer_create(su_peer_t *psar，const SA *ptoaddr，socklen_t servlen);
int su_peer_create_bind(su_peer_t *psar，int port，const SA *ptoaddr，
						socklen_t servlen);
```
`ptoaddr` 是接收方的地址信息，`serveln` 是地址结构的尺寸；<br>
`su_peer_create_bind` 创建时绑定指定的端口初始化 `psar`。`su_peer_create` 创建时随机占用一个的空闲端口初始化 `psar`。<br>
如果在编译 sarudp 时不使用宏`promiscuous_mode`开启混杂模式，psar 将丢弃ptoaddr 地址之外的任何数据，例如可以以此方式创建端对端的通信应用，两端均使用 su_peer_t 创建psar时绑定一个已知的端口，ptoaddr 相互指定对方的通信地址，然后就可以互相收发数据了。<br>
如果编译 sarudp 时使用宏 `promiscuous_mode`开启混杂模式，psar 安装的数据处理函数
将可处理来自任意地址的 sarudp 数据包，但因为给`su_peer_t`仅实现了一个处理线程，因此并不具备太强的处理能力，如果要创建专业的服务进程，应使用`su_serv_create`<br>

<span id="创建2"><span><br>
#####su_serv_t 的创建
```
int su_serv_create(su_serv_t *psvr, const SA *saddr, socklen_t servlen, int nthread);
```

在创建时可传入一个大于 0 的值指定需要安装的处理线程个数nthread，nthread受进程资源的限制；saddr 是将要分配给 psvr 的名字，servlen 是其地址长度。<br><br>
* 初始化创建函数都支持 IPv6 和 IPv4，只要在 ptoaddr 和 saddr 的字段设置的时候配置即可。使用 IPv6 地址创建的服务运行时可同时支持 IPv6 和 IPv4。<br>

<span id="销毁"><span><br><br>
####2. 销毁
执行销毁操作并释放占用的资源。
```
void su_peer_destroy(su_peer_t *psar);
void su_serv_destroy(su_serv_t *psvr);
```
功能：分别用来销毁其对应创建的 psar 和 psvr。

<span id="安装"><span><br><br>
####3. 安装数据处理函数
数据处理函数需要自己去实现如何处理从网络收到的数据，并且调用下列安装函数进行安装，当收到相应类型数据时，安装的数据处理函数被回调使用。

<span id="安装11"><span><br>
#####su_peer_t 的数据处理安装函数
```
void su_peer_reliable_request_handle_install(su_peer_t *psar, cb_su_peer_receiver_t* reliable_request_handle);
void su_peer_ordinary_request_handle_install(su_peer_t *psar, cb_su_peer_receiver_t* ordinary_request_handle);
```
功能：为创建成功的`psar`安装数据处理函数。

<span id="安装12"><span><br>
#####su_peer_t 的数据处理函数的类型定义

```
typedef void cb_su_peer_receiver_t(su_peer_t *ps, char* buff, int len);
```

<span id="安装13"><span><br>
#####su_peer_t 的数据处理函数的实现
作为 su_peer_t 端的一个回射处理示例，处理函数的实现可能如下：
```
void reliable_data_in(su_peer_t *psar, char *buff, int len)
{
    SAUN saddr; // 支持IPv6和IPv4 地址的联合体
    char ip[INET6_ADDRSTRLEN];
    int port;
    
	/* 获取对方的地址信息 */
    su_peer_getsrcaddr(psar, &saddr);
    su_get_ip_port(&saddr, ip, sizeof(ip), &port);

    printf("reliable recv from %s:%d datagrams len %d %s\n",
            ip, port, len, buff);
    /* 向对方应答回射数据 */
    su_peer_reply(psar, buff, len);
}
```

<span id="安装21"><span><br>
#####su_serv_t 的数据处理安装函数<br>
```
void su_serv_reliable_request_handle_install(su_serv_t *psvr, cb_su_serv_receiver_t* reliable_request_handle);
void su_serv_ordinary_request_handle_install(su_serv_t *psvr, cb_su_serv_receiver_t* ordinary_request_handle);
```
为创建成功的`psvr`安装数据处理函数，处理函数需要事先自己编写

<span id="安装22"><span><br>
#####su_serv_t 的数据处理函数的类型定义<br>
```
typedef void cb_su_serv_receiver_t(su_serv_t *ps, frames_t* frame, 
				char* buff, int len);
```
 su_serv_t 主要在应用于服务器进程中使用，数据处理函数可能被多个处理线程调用，所以数据处理函数多一个 frame 参数用于传递当前处理的数据包，这个 frame 参数记载了当前所处理请求和应答接口所需要的信息。<br>

<span id="安装23"><span><br>
#####su_serv_t 的数据处理函数的实现
作为 su_serv_t  端的一个回射处理示例，处理函数的实现可能如下：
```
void reliable_data_in(su_serv_t *psar, frames_t *frame, 
				char *buff, int len)
{
    char ipbuff[INET6_ADDRSTRLEN];
    int port;
    /* 获取对方的地址信息，地址信息是支持IPv6和IPv4的联合体 */
    su_get_ip_port(&frame->srcaddr, ipbuff, sizeof(ipbuff), &port);
    printf("reliable recv from %s:%d datagrams len %d %s",
            ipbuff, port, len, buff);
    /* 向对方应答，回射收到的数据 */
    su_serv_reply(psar, frame, buff, len); 
}
```

<span id="拆除"><span><br><br>
####4. 拆除数据处理函数

<span id="拆除1"><span><br>
#####su_peer_t 的数据处理拆除函数
```
void su_peer_reliable_request_handle_uninstall(su_peer_t *psar);
void su_peer_ordinary_request_handle_uninstall(su_peer_t *psar);
```
功能：拆除之前给对应`psar`安装的数据处理函数，一旦拆除之后，将忽略收到的数据。<br>

<span id="拆除2"><span><br>
#####su_serv_t 的数据处理拆除函数
```
void su_serv_reliable_request_handle_uninstall(su_serv_t *psvr);
void su_serv_ordinary_request_handle_uninstall(su_serv_t *psvr);
```
功能：拆除之前给对应`psvr`安装的数据处理函数，一旦拆除之后，将忽略收到的数据。<br>

<span id="发送"><span>
<span id="发送1"><span><br><br>
####5. 数据发送
#####su_peer_t 的数据发送函数
```
int su_peer_send(su_peer_t *psar, const void *outbuff, int outbytes);
int su_peer_request(su_peer_t *psar, const void *outbuff, int outbytes, 
					void *inbuff, int inbytes);
int su_peer_request_retry(su_peer_t *psar, const void *outbuff, 
					int outbytes, void *inbuff, int inbytes);
```
功能：向psar指定的对方发送数据，request 发送 reliable 数据，send 发送 ordinary 数据。<br>
su_peer_send 函数仅用于向对方发送数据，将数据送入网络接口后立即返回。如果成功，返回值是送入网络接口的数据长度，如果失败，返回-1，并且errno值被设置。<br>

su_peer_request 函数用于向对方发送数据然后等待对方应答返回。outbuff 是将要发送的数据指针，outbytes 是发送的数据长度，inbuff 是用于接收应答的缓冲区，inbytes 告知 request 函数提供的缓冲区尺寸，如果缓冲区过小，将无法容纳应答数据，剩余的应答数据将丢弃。一般来说，缓冲区尺寸使用对方的 `REALDATAMAX` 大小即可，这个值是编译时确定的。如果 request 成功收到对方应答，则返回值为对方应答的数据长度，如果返回值为0，说明对方只发送了一个应答包而没有携带任何数据。如果 request 返回 -1，errno 值会被设置，典型的情况是 request 超时返回 -1，errno 被设置为 `ETIMEOUT`；<br>
* 当发生超时，调用 su_peer_request_retry 可以再次进行重发 outbuff 数据。<br>
* 手工重发只能调用上述函数，再次调用 su_peer_request 将被当作新数据进行处理。<br>

<span id="发送2"><span><br><br>
#####su_serv_t 的数据发送函数
```
int su_serv_send(su_serv_t *psar, SA *destaddr, socklen_t destlen, 
					const void *outbuff, int outbytes);
int su_serv_request(su_serv_t *psar, SA *destaddr, socklen_t destlen, 
					const void *outbuff, int outbytes, 
					void *inbuff, int inbytes);
int su_serv_request_retry(su_serv_t *psar, SA *destaddr, socklen_t destlen, 
					const void *outbuff, int outbytes, 
					void *inbuff, int inbytes);
```
su_serv_t 的 send 和 request 因创建时未绑定一个对方的地址，发送数据时需提供对方的地址信息。其余参数作用同 su_peer_t 的类似。<br>

<span id="应答"><span>
<span id="应答1"><span><br><br>
####6. 数据应答
#####su_peer_t 的应答函数
```
int su_peer_reply(su_peer_t *psar, const void *outbuff, int outbytes);
```
功能：在 su_peer_t 的 reliable数据处理函数中调用时，向对方发送一个应答。<br>


<span id="应答2"><span><br><br>
#####su_serv_t 的应答函数
```
int su_serv_reply(su_serv_t *psvr, frames_t *frame, const void *outbuff, int outbytes);
```
功能：在 su_serv_t 的 reliable数据处理函数中调用时，向对方发送一个应答，frame 是 reliable数据处理函数中的包引用参数，原封不动传递给 su_serv_reply，如果 outbuff 和 outbytes 均设置为空，那么对方 request 将返回0而没有应答数据。<br>
>reply 函数只能在 reliable 数据处理函数中调用，在 ordinary 数据处理函数中调用是无效的。<br>

<span id="地址获取"><span><br><br>
####7. 地址获取
```
void su_get_ip_port(SAUN *s, char *ipbuff, int len, int *port);
void su_get_ip(SAUN *s, char *ipbuff, int len);
void su_get_port(SAUN *s, int *port);

void su_get_ip_port_f(SAUN *s, char *ipbuff, int len, int *port);
void su_get_ip_f(SAUN *s, char *ipbuff, int len);
```
功能：从 SAUN 联合体中提取出易读的 IP 和 Port 格式，同时支持 IPv4 和 IPv6 地址格式，通常在数据处理函数中调用。ipbuff 是提供的缓冲区，len是提供的缓冲区长度，port 是存放端口信息的整型数据。获取出来的的 port 已被转为本地主机字节序。如果出错，port 将被设置为 -1，ipbuff 也将被写入一条提示信息。<br>

---
<span id="使用步骤"><span>
<span id="1绑定"><span><br><br>
## sarudp 的使用步骤
以 su_peer_client 为例进行说明使用 su_peer_t 创建客户端步骤。
####1. 绑定 socket 地址结构
设置数据接收方的地址和端口，以下示例的是 IPv4 地址
```
struct sockaddr_in servaddr;
bzero(&servaddr，sizeof(servaddr));
servaddr.sin_family = PF_INET;
servaddr.sin_port = htons(argc == 2 ? 7 : atoi(argv[2]));
Inet_pton(AF_INET，ip，&servaddr.sin_addr);
```

<span id="2调用"><span><br><br>
####2. 调用 create 进行创建
 su_peer_create 调用配置 su_peer_t 对象，申请系统资源，开启本地网络服务。
```
su_peer_t sar;
if (su_peer_create(&sar，(SA*)&servaddr，sizeof(servaddr)) < 0)
    err_quit("su_peer_create error");
```
>su_peer_create 调用将使用随机的系统空闲端口绑定到 su_peer_t 类型数据对象，如果使用 su_peer_create_bind，第二个参数可以用指定端口绑定到 su_peer_t，如果指定的端口被占用，函数将返回-1并设置相应 errno 值。	<br>

<span id="3实现"><span>
<span id="reliable回射"><span><br><br>
####3. 实现数据处理函数
下列 reliable_data_in 函数实现的功能为收到对方的数据后进行回射应答处理。
```
void reliable_data_in(su_peer_t *psar, char *buff, int len)
{
    SAUN saddr; // 支持IPv6和IPv4 地址的联合体
    char ip[INET6_ADDRSTRLEN];
    int port;
    
	/* 获取对方的地址信息 */
    su_peer_getsrcaddr(psar, &saddr);
    su_get_ip_port(&saddr, ip, sizeof(ip), &port);

    printf("reliable recv from %s:%d datagrams len %d %s\n",
			ip, port, len, buff);
    /* 向对方应答，回射收到的数据 */
    su_peer_reply(psar, buff, len);
}
```
此函数必须被安装后使用，当sarudp接收reliable类型数据后，以回调方式调用 reliable_data_in 进行处理，见下一步。

<span id="4安装"><span><br><br>
####4. 安装数据处理函数
```
/* 安装 reliable 请求处理函数 */
su_peer_reliable_request_handle_install(&sar, reliable_data_in);
```
reliable_data_in 数据处理函数被安装后，将在收到 reliable 类型数据时自动调用预先实现好的方式处理数据。

<span id="5使用"><span>
<span id="发送数据"><span><br><br>
####5. 发送和处理数据
#####1. 发送数据
```
/* 构造一个随机数 */
n = snprintf(sendline, sizeof(sendline), "%05d", rand()%10000);
/* 将数据发给给接收端然后等待应答 */
n = su_peer_request(psar, sendline, n, recvline, MAXLINE);
```

<span id="处理数据"><span><br><br>
#####2. 接收数据并处理
数据处理函数的实现决定了如何处理收到的数据(见 [3. 实现数据处理函数](#reliable回射))。

---
<span id="示例"><span><br><br>
## 示例
>Demo实现了3个有关回射服务，终端行输入和随机数 请求应答的相关例子:
```	
1. su_peer_client 
	使用 su_peer_t 实现的 sarudp peer 程序通常作为客户端使用。
2. su_peer_server 
	使用 su_peer_t 实现的 sarudp peer 程序可以作为能力一般的服务端。
	su_peer_t 只有一个数据处理线程，一般用来端对端通讯或处理少量客户端。
3. su_serv_server
	使用 su_serv_t 实现的 sarudp serv 程序用来作为专业的服务器程序。
	su_serv_t 创建时可指定调用数据处理函数的线程并发数。
```		
详细实现和编译请看 Makefile 和 对应程序的 .c 文件。

---

20151015