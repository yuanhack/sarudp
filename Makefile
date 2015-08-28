
CC = gcc
CFLAGS += -g
CFLAGS += -O2
CFLAGS += -D_REENTRANT -Wall
LIBS = -lpthread
RANLIB = ranlib

CFLAGS += -DRTT_DEBUG

CLEANFILES = core core.* *.core *.o temp.* *.out typescript* \
		*.lc *.lh *.bsdi *.sparc *.uw

PROGS =	udpcli

all:	${PROGS}

udpcli:	main.o sarcli.o sarudp.o rtt.o domain_parse.o wrapfunc.o \
	yhevent.o yhservice.o yherror.o yharguments.o yhsocket.o
		${CC} ${CFLAGS} -o $@ $^ ${LIBS}

clean:
		rm -f ${PROGS} ${CLEANFILES}
