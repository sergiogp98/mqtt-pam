INCLUDE_DIR=./include
OBJ_DIR=./obj
SRC_DIR=./src 
BIN_DIR=./bin

CC=gcc
CFLAGS=-I$(INCLUDE_DIR) -g

_FILES = crypt ecdsa mqtt utils uuid file

_LIBS = lmosquitto lssl lcrypto luuid
LIBS = $(patsubst %, -%, $(_LIBS))

DEPS = $(patsubst %, $(INCLUDE_DIR)/%.h, $(_FILES))

OBJ = $(patsubst %, %.o, $(_FILES))

SRC = $(patsubst %, %.c, $(_FILES))

$(OBJ_DIR)/client.o: src/client.c $(DEPS)
	$(CC)  -c -o $@ $< $(CFLAGS)

$(OBJ_DIR)/server.o: src/server.c $(DEPS)
	$(CC)  -c -o $@ $< $(CFLAGS)

$(BIN_DIR)/server: $(OBJ_DIR)/server.o 
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

$(BIN_DIR)/client: $(OBJ_DIR)/client.o 
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

all: $(BIN_DIR)/client $(BIN_DIR)/server
 
.PHONY: clean

clean:
	rm -rf $(OBJ_DIR)/*.o $(BIN_DIR)/* 