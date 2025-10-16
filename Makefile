CC      ?= gcc
CSTD    ?= -std=c11
CFLAGS  ?= -O2 -g -Wall -Wextra -Wno-deprecated-declarations $(CSTD)
LDFLAGS ?=

SRC_DIR := src
BIN     := proxy

SRC := $(SRC_DIR)/main.c \
       $(SRC_DIR)/proxy.c \
       $(SRC_DIR)/ssl_utils.c

# Try pkg-config first
CFLAGS  += $(shell pkg-config --cflags libevent_openssl libevent_openssl openssl zlib libbrotlidec 2>/dev/null)
LDFLAGS += $(shell pkg-config --libs   libevent_openssl libevent_openssl openssl zlib libbrotlidec 2>/dev/null)

# Fallback libs
LDFLAGS += -levent_openssl -levent -lssl -lcrypto -lz -lbrotlidec

all: $(BIN)

$(BIN): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(BIN)

.PHONY: all clean
