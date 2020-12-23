SHELL = /bin/bash
CC = gcc
CFLAGS = -g -O3
SRC = $(wildcard *.c)
EXE = $(patsubst %.c, %, $(SRC))

all: ${EXE}

%:	%.c
	${CC} ${CFLAGS} $@.c -o $@ -lpcap

clean:
	rm ${EXE}

