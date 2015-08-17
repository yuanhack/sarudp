include ../Make.defines

PROGS =	udpcli

all:	${PROGS}

udpcli:	main.o sarcli.o sarudp.o rtt.o error.o domain_parse.o
		${CC} ${CFLAGS} -o $@ $^ ${LIBS}

clean:
		rm -f ${PROGS} ${CLEANFILES}
