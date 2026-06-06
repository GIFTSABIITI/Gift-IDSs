CC = gcc
CFLAGS ?= -std=c11 -Wall -Wextra -g -D_DEFAULT_SOURCE -Iinclude
TARGET := giftids
SRCS := src/main.c src/capture.c src/parser.c src/logger.c src/detector.c src/config.c src/cli.c src/stats.c src/pcap_reader.c src/processor.c
OBJS := $(SRCS:.c=.o)
TEST_TARGET := tests/giftids_tests
TEST_SRCS := tests/run_tests.c tests/test_config.c tests/test_detector.c tests/test_parser.c tests/test_cli.c tests/test_stats.c src/parser.c src/detector.c src/config.c src/cli.c src/stats.c

.PHONY: all test clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(TEST_TARGET): $(TEST_SRCS)
	@mkdir -p tests/tmp
	@echo "Building Gift IDS tests..."
	$(CC) $(CFLAGS) -Itests -o $@ $(TEST_SRCS)

test: $(TEST_TARGET)
	@echo "Running tests..."
	@./$(TEST_TARGET)

clean:
	rm -f $(TARGET) $(OBJS) $(TEST_TARGET)
	rm -rf tests/tmp
