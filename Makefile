CC = gcc
CFLAGS += -g
CFLAGS += -D_REENTRANT -Wall
CFLAGS += -O0

#CFLAGS += -Wno-unused-variable
#CFLAGS += -Wno-unused-but-set-variable

CFLAGS += -Dpromiscuous_mode

#CFLAGS += -DSU_DEBUG_RTT
#CFLAGS += -DSU_DEBUG_PEER_RECV
#CFLAGS += -DSU_DEBUG_PEER_RESEND
#CFLAGS += -DSU_DEBUG_TIMEVERBOSE
#CFLAGS += -DSU_DEBUG_LIST
#CFLAGS += -DSU_DEBUG_RBTREE
CFLAGS += -DSU_DEBUG_IP6FULL

CLIBS = -lpthread

RANLIB = ranlib

CLEANFILES = core core.* *.core *.o temp.* typescript* *.lc *.lh

PROGS =	su_peer_client su_peer_server su_serv_server

all:	${PROGS}

.PHONY: all clean clear cmake remake

su_peer_client: su_peer_client.o sarudp_peer.o sarudp_comm.o rtt.o domain_parse.o wrapfunc.o \
	yhevent.o yherror.o yharguments.o yhtime.o yhrbtree.o
	${CC} ${CFLAGS} -o $@ $^ ${CLIBS}
su_peer_server: su_peer_server.o sarudp_peer.o sarudp_comm.o rtt.o domain_parse.o wrapfunc.o \
	yhevent.o yherror.o yharguments.o yhtime.o yhrbtree.o yhdaemon.o
	${CC} ${CFLAGS} -o $@ $^ ${CLIBS}

su_serv_server: su_serv_server.o sarudp_serv.o sarudp_comm.o rtt.o domain_parse.o wrapfunc.o \
	yhevent.o yherror.o yharguments.o yhtime.o yhrbtree.o yhdaemon.o
	${CC} ${CFLAGS} -o $@ $^ ${CLIBS}

clean:
	rm -f ${PROGS} ${CLEANFILES}
clear:
	clear
cmake:
	make clear
	make
remake:
	make clear
	make clean
	make all
