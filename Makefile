
CC=gcc

OBJ_CFLAGS=-Wall
LDFLAGS=-lm

SRCS = sock.c radiotap/radiotap.c osdep/common.c lib/iwlib.c
OBJS = $(patsubst %c,%o,$(SRCS))

all:airtool

airtool:$(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

%.o:%.c 
	$(CC) -c $< -o $@ $(OBJ_CFLAGS) 
