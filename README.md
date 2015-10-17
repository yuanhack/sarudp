# sarudp 协议 

[sarudp 说明](#说明)<br>
　　[首部](#首部)<br>
　　[定义](#定义)<br>
　　[解释](#解释)<br>
　　[实现](#实现)<br>
　　　　[1. 重传](#重传)<br>
　　　　　　[请求重传](#请求重传)<br>
　　　　　　[应答重传](#应答重传)<br>
　　　　[2. 缓存](#缓存)<br>
　　　　[3. 清理](#清理)<br>
　　[数据定义和接口函数](#数据定义和接口函数)<br>
　　[基本结构定义](#基本结构定义)<br>
　　[函数说明](#函数说明)<br>
　　　　[1. 创建](#创建)<br>
　　　　　　[su_peer_t 的创建](#创建1)<br>
　　　　　　[su_serv_t 的创建](#创建2)<br>
　　　　[2. 销毁](#销毁)<br>
　　　　[3. 安装数据处理函数](#安装)<br>
　　　　　　[su_peer_t 的数据处理安装函数](#安装11)<br>
　　　　　　[su_peer_t 的数据处理函数的类型定义](#安装12)<br>
　　　　　　[su_peer_t 的数据处理函数的实现](#安装13)<br>
　　　　　　[su_serv_t 的数据处理安装函数](#安装21)<br>
　　　　　　[su_serv_t 的数据处理函数的类型定义](#安装22)<br>
　　　　　　[su_serv_t 的数据处理函数的实现](#安装23)<br>
　　　　[4. 拆除数据处理函数](#拆除)<br>
　　　　　　[su_peer_t 的数据处理拆除函数](#拆除1)<br>
　　　　　　[su_serv_t 的数据处理拆除函数](#拆除2)<br>
　　　　[5. 数据发送](#发送)<br>
　　　　　　[su_peer_t 的数据发送函数](#发送1)<br>
　　　　　　[su_serv_t 的数据发送函数](#发送2)<br>
　　　　[6. 数据应答](#应答)<br>
　　　　　　[su_peer_t 的应答函数](#应答1)<br>
　　　　　　[su_serv_t 的应答函数](#应答2)<br>
　　　　[7. 地址获取](#地址获取)<br>
　　　[sarudp 的使用步骤](#使用步骤)<br>
　　　　[1. 绑定 socket 地址结构](#1绑定)<br>
　　　　[2. 调用 create 进行创建](#2调用)<br>
　　　　[3. 实现数据处理函数](#3实现)<br>
　　　　[4. 安装数据处理函数](#4安装)<br>
　　　　[5. 发送和处理数据](#5使用)<br>
　　　　　　[1. 发送数据](#发送数据)<br>
　　　　　　[2. 接收数据并处理](#处理数据)<br>
　　[示例](#示例)

---

##说明
　　sarudp 是`SYN-ACK-Retransfer UDP`的缩写，是增加了传输可靠性的 UDP 协议。<br>
　　sarudp 在 UDP 基础上实现了请求重传和应答重传，它同时具有 UDP 和 TCP 的优点，可同时支持 IPv6 和 IPv4 应用程序的开发。<br>
　　sarudp 在收到数据后以对方的 ip:port 作为区分，使用 sarudp 协议将可以处理任意数量的 sarudp 终端。<br>
> 　　sarudp 仅在初始化时创建几个文件描述符，运行时不会占用新的文件描述符资源，使用 sarudp 创建的服务，不需要担心处理的客户端上限。<br>
　　sarudp 的 request 函数采用 请求-确认 机制工作，因此有序串行地调用 request 时，可以像TCP那样使对方收到的数据也是有序的。在不关心数据有序性的情况下，request 可并行使用，对方接收数据不保证有序性，但具有可靠性。<br>
　　sarudp 的 send 函数向对方发送数据然后返回，就像普通的UDP数据 sendto 那样工作。<br>

## 首部
###定义
| 8 bit  | 8 bit | 16 bit  | 32 bit      | 32bit       |
| :----- | :-----| :------ | :---------- | :---------- |
| action | type  | session id | sequence number| timestamp when send |
###解释
|Item     | Explain| Value  |
| :----   | :----- | :----- |
|action   | 数据包功能，用于区分 请求/应答 包  | 0xFF/0xFE   |
|type     | 可靠性标志，用于标识 可靠/不可靠 包 | 0x01/0x00  |
|session  | 会话的ID，作为红黑树 key 的一部分 | 0 ~ 2^16    |
|sequence | 本包序列号，用于识别对应的请求/应答包 | 0 ~ 2^32 |
|timestamp| 发包时间戳，用于接收到应答时的 RTT 计算 | 0 ~ 2^32 |

　　session  id 主要用于鉴别以绑定端口方式创建的数据发送端是否重启。调用创建函数时分配不同的 sid  便于对方识别会话是否同一会话。<br>
　　type 定义了两种数据类型，reliable 类型和 ordinary 类型，reliable 类型的数据是增加了传输可靠性的数据，具有重传机制；ordinary 类型的数据是普通 UDP 数据，没有重传机制。
　　action 请求时为 0xff，应答时将改变为 0xfe，其他字段值不变，然后`携带应答数据(若有)`发往请求端。

## 实现

* **为减小篇幅以及便于描述，本文约定：**
	* 若非特指，`request，send, create 或 reply` 是指 `su_peer_t 或 su_serv_t` 中的函数接口；
	* `请求`是指主动向对方发送数据，调用`request`发送数据就是发送请求；
	* `应答`是指在`数据处理函数`中调用`reply`函数向`请求`方发送应答；
	* `reliable 数据`是具有传输可靠性的数据，具有重传，缓存和应答机制，这类数据由`request`发出；
	* `ordinary 数据`是不具有传输可靠性的数据，没有重传，缓存和应答机制，这类数据由`send`发出；
	* `reliable 函数`是用户为处理收到的 reliable 数据请求而实现的回调函数，处理由`request`发来的请求；
	* `ordinary 函数`是用户为处理收到的 ordinary 数据而实现的回调函数，处理由`send`发来的数据；
	* `数据处理函数` 或简称`处理函数`是指上述的 reliable函数 或 ordinary函数。
	* 当提到例如 su_x_request，handle_su_x_recv 之类的函数时，若非特指，x 代指 peer或者serv。
* **以上约定可能将在文中反复引用。**

　　网络数据接收和处理部分使用了 yhevents 来驱动，这是一套以前我用 epoll 封装的框架(half-sync/half-async)，已在多个项目中稳定地使用。<br>
　　sarudp 以线程的方式处理收到数据时，如果是合法的 sarudp 包就放入链表，通知线程处理，不是就丢弃。处理线程以回调方式调用`用户安装的处理函数`处理数据。<br>
> 当网络接口有数据到来时候，handle_su_x_recv 被调用来处理收到的数据；这个函数 在 su_x_create 中被设置为 EPOLLIN事件的回调函数。线程 thread_request_handle 处理从接收队列拿到的 sarudp 数据包，在 request_handle 中，根据当前处理的数据包的类型不同，调用 reliable 或 ordinary 处理函数。<br>
>出于性能上的的考虑，为了避免内存碎片和二次拷贝，数据接收时申请固定大小的内存而没有使用栈，如果用户安装了数据处理函数，则在调用后自动释放，如果没有安装就直接释放。<br>

　　sarudp 在实现上把应答放在用户实现的`处理函数`中去调用 ，由使用者决定是否应答，何时应答以及如何应答，预留
足够的灵活性，仅将`请求重传`和`应答重传`实现为`自动处理`。<br>

* sarudp 设计了su_peer_t 和 su_serv_t 结构，分别针对客户端和服务端角色。

<span id="重传"><span><br><br>
###1. 重传
　　理论上 UDP 包最大长度可以是 2^16 字节大小，其合理值是传输链路的 MTU 1500 字节。但传输途中无法预知数据包将经过何种网络环境，数据包在途径某个 "分片窄带" 环境时可能被分片传输，最终在到达目的地址后重组还原，如果某一个分片丢失，整个包将重组失败，就造成了这个包传输失败，需要重传整个数据包。<br>
　　sarudp_comm.h 文件中的`REALDATAMAX`宏设置了 sarudp 处理单个数据包的最大尺寸，为了降低丢包概率，其最优值应小于等于网络中可能经过所有路由的最小 MTU  576 字节：减去20 字节 IP 首部，减去 8 字节 UDP 首部，减去 12 字节 sarudp 首部。<br>
```
REALDATAMAX 最优值应是 576-20-8-12 = 536
```
　　其值越大，分片可能越多，在网络传输中越容易发生丢包，包在传输途中丢失的情况有以下2种: 
```
1. 请求包在到达对端途中丢失，对端没有收到
2. 应答包在到达本端途中丢失，本地没有收到
```
　　无论以上述何种情况丢包，request 都将重发，重试`RTT_MAXNREXMT`次。可以通过调整宏在编译时决定包的重发次数和应答数据的缓存时长，在 unprtt.h 中：<br>
	
	RTT_MAXNREXMT 最大重传次数(秒)
	RTT_MAXRTO    最大重传间隔(秒)

> 对重传次数和重传间隔的合理设置在 [缓存](#缓存) 章节进行讨论。

　　sarudp 使用`应答超时重发请求`实现请求重传，使用`缓存应答和再次收到请求时自动重传应答`实现应答重传。
　　无论是请求的重传还是对方应答的重传都由本地调用 request 引起，当 request 发出请求后，最理想的情况是对方收到请求后尽快发回一个应答，本地 request 收到了这个应答；如果请求或者应答在网络中丢失，request 在超时期间没有收到应答将重发请求，对方收到重传的请求后如果发现已经缓存了应答，就立即从缓存将应答发出。
>为了支持客户端可以将大量并发请求同时发送的情况，采用缓存应答的实现方式，没有采用确定对方应答收到后立即清理前一个应答缓存的这种方式，这种方式虽然节省内存但是效率不高，不适合大并发的应用。并发式调用 request 发送数据不能保证数据包之间的到达时序。<br>
>为了实现应答重传，sarudp 占用了一定内存资源，在应答发送之后立即对应答数据进行缓存，如果应答在途中丢失，当再次收到该请求时直接从缓存中取出暂存的应答数据重传应答，缓存的应答数据在超出设定的时长后清理。<br>

<span id="请求重传"><span><br><br>
####请求重传
　　request 接口的工作流程是，request 发出请求，然后等待应答，同时计算等待超时和下次重发包的时间。如果一直没有收到对方应答，将重试发送 `RTT_MAXNREXMT` 次请求后返回-1，同时 errno 被设置为 ETIMEDOUT。
　　如果收到应答，调用时提供的缓冲区将被填充应答数据，函数返回值为应答的数据长度，如果返回值为0，表示对方发送应答时没有携带数据。<br>
　　request 发出的请求将由对方的 `reliable处理函数` 处理，应答是由在 reliable处理函数 中调用 reply 发出的。

> 请求重传参考了`《UNIX网络编程卷1：套接字联网API》第三版` 22.5 章节中的算法实现。

　　普通数据没有应答。send 函数用于 `ordinary 数据发送`，发送的数据将由`对方安装的 ordinary处理函数` 处理，这种数据没有实现应答功能，在处理函数内调用 reply 函数是无效的，但是可以通过调用 request 或  send 函数向任意地址发送数据。

<span id="应答重传"><span><br><br>
####应答重传
　　作为接收数据的一端，当`在处理函数中调用 reply 函数发送应答后，sarudp 将缓存 reliable 数据，如果应答在中途丢失，再次收到对方的请求后将自动应答` (付出少量内存资源和红黑树查找代价实现应答重传)。<br>
　　关于调用 reply 处理应答，存在以下几种情形：<br>
* 如果携带数据，对方为 request 提供的缓冲区将接收到应答数据，其返回值为数据长度；
* 如果不携带数据，对方 request 函数返回0；
* 如果不调用应答函数，对方 request 将超时返回 -1；

<span id="缓存">  </span><br><br>
###2. 缓存
　　sarudp 在 `首次收到请求包 和 首次发送应答包 时，用红黑树节点进行首部缓存，同时将该节点添加到循环链表，链表主要用于过期清理`。<br>
　　如果包在传输途中丢失，再次收到同一请求包时将直接在协议层`自动重传应答`，不会再次将请求递送到`数据处理函数`，也`不会再次加入缓存`。<br>

　　sarudp 在开发过程中，对于下面列举的参数进行了大量的传输测试:
```
#define RTT_MAXNREXMT    4   // unprtt.h
#define RTT_MAXRTO      12   // unprtt.h
#define CACHETIMEOUT    90   // sarudp_comm.h
```

设置 4 次重传，12秒重传最大间隔和 90 秒缓存是个比较合理的值，可以自行进行合理调整。
* 如果应用的网络环境状况严峻，可适当增加重试次数，适当减小重试间隔，适当调整缓存时间。但更多的重试次数和更小的重试间隔，以及更大的缓存时长，往往会增加网络存在的问题。更大的缓存时长可以增加包重传的有效期，但可能会让占用更多的内存资源。
* sarudp 在开发过程中使用北京，香港，美国硅谷的主机进行相互数据传输测试，表现良好。
* sarudp 在丢包率不高的网络上表现良好，丢包率至少小于50%。	
* `注意：`设置的重传次数和间隔的总时长不能超过缓存时间，如果应答缓存被超时清理，重传的请求将当成新数据被递送到处理函数中处理。一般将其设计为缓存时长的一半，这样的话当 request 超时失败以后有机会尝试调用 request_retry 进行重试。

<span id="清理"><span><br><br>
###3. 清理
　　新缓存总是追加到循环列表的队尾，按插入时间很自然的进行了排序；而过期检测总是从队列首部进行，如果超时则清理，然后检测下一个，直到下一个节点没有过期或整个缓存列表清理完毕。<br>

---

##数据定义和接口函数

###基本结构定义
* su_peer_t 主要在客户端使用，结构体在 sarudp_peer.h 中定义；<br>
* su_serv_t 主要在服务器中使用，结构定义在 sarudp_serv.h 中；<br>
* sarudp_comm.h 中定义了一些共用的部分：<br>
	* SAUN 联合同时兼容 IPv6 和 IPv4 格式的地址；
	* suhdr_t 结构体是 sardup 首部定义；
	* frames_t 结构体是地址数据容器，链表的节点。
	* cache_t 结构体是 frames_t 的容器，红黑树的节点。
	* rb_key_cache 结构体是红黑树查表时候使用的key定义。

<span id="创建"><span>
<span id="创建1"><span><br><br>
###函数说明
####1. 创建
　　执行创建操作时，将创建 socket，资源申请，参数初始化和启动数据接收服务。<br>
#####su_peer_t 的创建
```
int su_peer_create(su_peer_t *psar，const SA *ptoaddr，socklen_t servlen);
int su_peer_create_bind(su_peer_t *psar，int port，const SA *ptoaddr，socklen_t servlen);
```
　　`ptoaddr` 是`psar`将要绑定的数据接收方的地址信息，`serveln` 是地址结构的尺寸，`port` 是指定的本地端口值；<br>
　　`su_peer_create` 创建时随机占用一个空闲端口，`su_peer_create_bind` 创建时绑定指定的 `port` 端口，如果此端口被占用，创建失败将返回-1，errno 值被设置 `EADDRINUSE`，如果成功，将返回socket描述符的值(>=0)。<br>

　　编译 sarudp 时是否定义了宏 `promiscuous_mode` 将影响 su_peer_t 的数据接收和处理方式。<br>
　　如果使用，psar 安装的处理函数将会收到任意地址的 sarudp 数据包，但因为给`su_peer_t`仅实现了一个处理线程，因此并不具备太强的处理能力，如要创建专业的服务进程应使用 su_serv_t，这个宏不影响 su_serv_t 端的功能。<br>
　　如果不使用，psar 的处理函数将仅接收来自 `ptoaddr` 的 sarudp 协议数据。
>例如：使用 sarudp 实现端对端的应用，步骤为：两端均使用 su_peer_create_bind 创建 psar 时绑定一个指定的端口，其中 ptoaddr 互相指定为对方的IP地址和对方绑定的端口，创建成功后就可以互相通信了，除了对方之外的任何数据将被接收时丢弃。<br>

　　
<span id="创建2"><span><br><br>
#####su_serv_t 的创建
```
int su_serv_create(su_serv_t *psvr, const SA *saddr, socklen_t servlen, int nthread);
```
　　在创建时可传入一个大于 0 的值 nthread 指定需要安装的处理线程个数，其受进程资源限制；`saddr` 是 `psvr` 将要绑定到的服务地址指针，`servlen`是地址长度。<br>
* create 函数支持 IPv6 和 IPv4，只要在地址字段设置的时候设置好即可。由于IPv6兼容IPv4，使用 IPv6 地址创建的服务运行时可同时支持 IPv6 和 IPv4。<br>

<span id="销毁"><span><br><br>
####2. 销毁
　　销毁操以优雅的方式自行退出处理线程，实现时放弃了用线程取消的这种暴力方式，因其需进一步去处理锁的关系。

#####su_peer_t 的销毁
```
void su_peer_destroy(su_peer_t *psar);
```
　　销毁由 su_peer_create 或 su_peer_create_bind 创建的 psar ，释放创建时和运行过程中申请的系统资源。

##### su_serv_t 的销毁
```
void su_serv_destroy(su_serv_t *psvr);
```
　　销毁由 su_serv_create 创建的 psvr，释放创建时和运行过程中申请的系统资源。

<span id="安装"><span><br><br>
####3. 安装数据处理函数
　　数据处理函数需要自己先实现如何处理从网络收到的 reliable 或 ordinary 数据，再调用下列安装函数进行安装，当收到相应类型数据时，安装的数据处理函数被回调使用。

<span id="安装11"><span><br>
#####su_peer_t 的数据处理安装函数
```
void su_peer_reliable_request_handle_install(su_peer_t *psar, cb_su_peer_receiver_t* reliable_request_handle);
void su_peer_ordinary_request_handle_install(su_peer_t *psar, cb_su_peer_receiver_t* ordinary_request_handle);
```
　　为创建成功的`psar`安装数据处理函数。

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
　　为创建成功的`psvr`安装数据处理函数。

<span id="安装22"><span><br>
#####su_serv_t 的数据处理函数的类型定义<br>
```
typedef void cb_su_serv_receiver_t(su_serv_t *ps, frames_t* frame, 
				char* buff, int len);
```
　　由于 su_serv_t 主要设计在服务器进程中使用，数据处理函数可能被多个处理线程调用，所以数据处理函数多一个 frame 参数用于传递当前处理的数据包，这个 frame 参数记载了当前所处理请求和应答接口所需要的信息。<br>

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
　　拆除之前给对应`psar`安装的数据处理函数，一旦拆除之后，psar 将忽略收到的对应类型的数据。<br>

<span id="拆除2"><span><br>
#####su_serv_t 的数据处理拆除函数
```
void su_serv_reliable_request_handle_uninstall(su_serv_t *psvr);
void su_serv_ordinary_request_handle_uninstall(su_serv_t *psvr);
```
　　拆除之前给对应`psvr`安装的数据处理函数，一旦拆除之后，psvr 将忽略收到的对应类型的数据。<br>

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
　　向 `psar` 绑定的对方地址发送数据，`request` 发送 `reliable 请求`，`send` 发送 `ordinary 数据`。<br>
　　`send` 函数仅向对方发送数据，将数据送入网络接口后立即返回。如果成功，返回值是送入网络接口的数据长度，如果失败，返回-1，并且errno值被设置。<br>
　　`request` 函数向对方发出请求后等待对方应答返回。outbuff 是将要发送的数据指针，outbytes 是发送的数据长度，inbuff 是用于接收应答的缓冲区，inbytes 是缓冲区尺寸，如果缓冲区过小，将无法容纳应答数据，剩余的应答数据将丢弃。一般来说，缓冲区尺寸使用对方的 `REALDATAMAX` 大小即可，这个值是编译时确定的。
　　如果 request 成功收到对方应答，则返回值为对方应答的数据长度，如果返回值为0，说明对方只发送了一个应答包而没有携带任何数据。如果 request 返回 -1，errno 值会被设置，典型的情况是 request 超时返回 -1，errno 被设置为`ETIMEDOUT`；<br>
* 当发生超时，调用 `su_peer_request_retry` 可以再次重发 outbuff 数据。<br>
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
　　在 su_peer_t 的 reliable数据处理函数中调用时，向对方发送应答。<br>


<span id="应答2"><span><br><br>
#####su_serv_t 的应答函数
```
int su_serv_reply(su_serv_t *psvr, frames_t *frame, const void *outbuff, int outbytes);
```
　　在 su_serv_t 的 reliable数据处理函数中调用时，向对方发送应答，frame 是 reliable处理函数中的当前包指针，原封不动传递给 su_serv_reply，如果 outbuff 和 outbytes 均设置为空，那么对方 request 将返回0而没有应答数据。<br>
>reply 函数只能在 reliable 处理函数中调用，在 ordinary 处理函数中调用是无效的。<br>

<span id="地址获取"><span><br><br>
####7. 地址获取
```
void su_get_ip_port(SAUN *s, char *ipbuff, int len, int *port);
void su_get_ip(SAUN *s, char *ipbuff, int len);
void su_get_port(SAUN *s, int *port);

void su_get_ip_port_f(SAUN *s, char *ipbuff, int len, int *port);
void su_get_ip_f(SAUN *s, char *ipbuff, int len);
```
　　如果要从 SAUN 联合体中提取出易读的 IP 和 Port 格式，可以使用上述函数，同时支持 IPv4 和 IPv6 地址格式。<br>
　　这些函数通常在数据处理函数中调用。ipbuff 是提供的缓冲区，len是提供的缓冲区长度，port 是存放端口信息的整型数据。获取出来的的 port 已被转为本地主机字节序。如果出错，port 将被设置为 -1，ipbuff 也将被写入一条提示信息。<br>

---
<span id="使用步骤"><span>
<span id="1绑定"><span><br><br>
## sarudp 的使用步骤
　　以 su_peer_client 为例进行说明使用 su_peer_t 创建客户端步骤。
####1. 绑定 socket 地址结构
　　设置数据接收方的地址和端口，以下示例的是 IPv4 地址
```
/* ip 和 port 已事先设置好 */
struct sockaddr_in servaddr;
bzero(&servaddr，sizeof(servaddr));
servaddr.sin_family = PF_INET;
servaddr.sin_port = htons(port);
Inet_pton(AF_INET，ip，&servaddr.sin_addr);
```

<span id="2调用"><span><br><br>
####2. 调用 create 进行创建
 　　调用 su_peer_create 初始化 sar，申请系统资源，开启本地网络服务。
```
su_peer_t sar;
if (su_peer_create(&sar，(SA*)&servaddr，sizeof(servaddr)) < 0)
    err_quit("su_peer_create error");
```
>调用 su_peer_create 将使用随机的系统空闲端口创建和绑定到sar，如果使用 su_peer_create_bind，第二个参数可以使用指定端口。	<br>

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
　　处理函数必须被安装后才会自动工作，当 sar 收到 reliable 数据后，以回调方式调用 reliable_data_in ，安装见下一步。

<span id="4安装"><span><br><br>
####4. 安装数据处理函数
```
/* 安装 reliable 请求处理函数 */
su_peer_reliable_request_handle_install(&sar, reliable_data_in);
```
　reliable_data_in 处理函数被安装后，sar 将在收到 reliable 数据时自动调用 reliable_data_in 进行处理。

<span id="5使用"><span>
<span id="发送数据"><span><br><br>
####5. 发送和处理数据
#####1. 发送数据
```
/* 以发送伪随机数为例，构造一个随机数 */
n = snprintf(sendline, sizeof(sendline), "%05d", rand()%10000);
/* 将数据请求发送给接收端然后等待应答 */
n = su_peer_request(psar, sendline, n, recvline, MAXLINE);
```

<span id="处理数据"><span><br><br>
#####2. 接收数据并处理
　　数据处理函数的实现决定了如何处理收到的数据(见 [3. 实现数据处理函数](#reliable回射))。

---
<span id="示例"><span><br><br>
## 示例
Demo实现了3个有关终端行输入和随机数 请求应答的回射相关例子:<br>

| 程序 | 说明 |
| :---- | :------ |
|su_peer_client | 使用 su_peer_t 实现的客户端。<br>向其他 sarudp 终端循环发送数据。|
|su_peer_server | 使用 su_peer_t 实现的回射服务。<br>只有单个处理线程的 sarudp 回射服务器。|
| su_serv_server| 使用 su_serv_t 实现的回射服务。<br>拥有多个处理线程的 sarudp 回射服务器。|

详细实现和编译请看 Makefile 和 对应程序的 .c 文件。

---
本文可能不定期的进行补充，修订或更新。
<br>
2015/10/18
