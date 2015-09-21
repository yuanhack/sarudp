CC = gcc
CFLAGS += -g
CFLAGS += -D_REENTRANT -Wall
CFLAGS += -O2
CFLAGS += -Wno-unused-variable
CFLAGS += -Wno-unused-but-set-variable

#CFLAGS += -Dsingle_peer_module
CFLAGS += -Dpromiscuous_mode

#CFLAGS += -DSU_DEBUG_PEER
#CFLAGS += -DSU_DEBUG_PEER_RECV
#CFLAGS += -DSU_DEBUG_PEER_RESEND
#CFLAGS += -DSU_DEBUG_TIMEDWAIT
#CFLAGS += -DSU_DEBUG_TIMEVERBOSE
#CFLAGS += -DSU_DEBUG_LIST
#CFLAGS += -DSU_DEBUG_RBTREE
#CFLAGS += -DSU_DEBUG_RTT

CLIBS = -lpthread

RANLIB = ranlib

CLEANFILES = core core.* *.core *.o temp.* typescript* *.lc *.lh

PROGS =	su_peer_client su_peer_server

all:	${PROGS}

.PHONY: all clean clear cmake remake

su_peer_client: su_peer_client.o sarudp.o rtt.o domain_parse.o wrapfunc.o \
	yhevent.o yhservice.o yherror.o yharguments.o yhsocket.o yhtime.o yhrbtree.o
	${CC} ${CFLAGS} -o $@ $^ ${CLIBS}
su_peer_server: su_peer_server.o sarudp.o rtt.o domain_parse.o wrapfunc.o \
	yhevent.o yhservice.o yherror.o yharguments.o yhsocket.o yhtime.o yhrbtree.o
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

