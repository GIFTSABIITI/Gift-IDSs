CC = gcc
CFLAGS ?= -std=c11 -Wall -Wextra -g -D_DEFAULT_SOURCE -Iinclude
TARGET := giftids
SRCS := src/main.c src/capture.c src/parser.c src/logger.c src/detector.c src/config.c src/cli.c src/stats.c
OBJS := $(SRCS:.c=.o)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(TARGET) $(OBJS)
