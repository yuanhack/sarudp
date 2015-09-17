
CC = gcc
CFLAGS += -g
#CFLAGS += -O2
CFLAGS += -D_REENTRANT -Wall
CLIBS = -lpthread

#CFLAGS += -Dmodule_exact_match_address

CFLAGS += -Wno-unused-variable
CFLAGS += -Wno-unused-but-set-variable

#CFLAGS += -DSU_DEBUG_PEER
#CFLAGS += -DSU_DEBUG_PEER_RECV
#CFLAGS += -D SU_DEBUG_TIMEDWAIT
#CFLAGS += -DSU_DEBUG_TIMEVERBOSE
#CFLAGS += -DSU_DEBUG_LIST
#CFLAGS += -DSU_DEBUG_RBTREE

CFLAGS += -DRTT_DEBUG


RANLIB = ranlib

CLEANFILES = core core.* *.core *.o temp.* typescript* *.lc *.lh

PROGS =	udpcli

all:	${PROGS}

.PHONY: all clean clear cmake remake

udpcli:	main.o sarcli.o sarudp.o rtt.o domain_parse.o wrapfunc.o \
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

