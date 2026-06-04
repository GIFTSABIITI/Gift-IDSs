CC ?= cc
CFLAGS ?= -std=c11 -Wall -Wextra -Wpedantic -O2
TARGET := ids_sniffer
SRC := src/ids_sniffer.c

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)
