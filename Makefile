
CC = gcc
CFLAGS = -g -O2 -D_REENTRANT -Wall
LIBS = -lpthread
RANLIB = ranlib

CLEANFILES = core core.* *.core *.o temp.* *.out typescript* \
		*.lc *.lh *.bsdi *.sparc *.uw

PROGS =	udpcli

all:	${PROGS}

udpcli:	main.o sarcli.o sarudp.o rtt.o error.o domain_parse.o wrapfunc.o
		${CC} ${CFLAGS} -o $@ $^ ${LIBS}

clean:
		rm -f ${PROGS} ${CLEANFILES}
