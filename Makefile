INCLUDE_DIR=./include
OBJ_DIR=./obj
SRC_DIR=./src 
BIN_DIR=./bin
SEC_LIB=/lib/security

CC=gcc
CFLAGS=-I$(INCLUDE_DIR) -g
PAM_FLAGS=-fPIC -fno-stack-protector
LD_FLAGS=-x --shared

_FILES = crypt ecdsa mqtt utils uuid file

_LIBS = lmosquitto lssl lcrypto luuid
LIBS = $(patsubst %, -%, $(_LIBS))

DEPS = $(patsubst %, $(INCLUDE_DIR)/%.h, $(_FILES))

$(OBJ_DIR)/identification.o: src/identification.c $(DEPS)
	$(CC) -c $< -o $@  $(CFLAGS)  

$(OBJ_DIR)/client.o: src/client.c $(DEPS)
	$(CC) -c $< -o $@  $(CFLAGS)

$(OBJ_DIR)/server.o: src/server.c $(DEPS)
	$(CC) -c $< -o $@  $(CFLAGS)

$(OBJ_DIR)/mqtt-pam.o: src/mqtt-pam.c $(DEPS)
	$(CC) -c $< -o $@ $(PAM_FLAGS) 

$(BIN_DIR)/identification: $(OBJ_DIR)/identification.o 
	$(CC) $< -o $@ $(CFLAGS) $(LIBS)  

$(BIN_DIR)/server: $(OBJ_DIR)/server.o 
	$(CC) $< -o $@  $(CFLAGS) $(LIBS)

$(BIN_DIR)/client: $(OBJ_DIR)/client.o 
	$(CC) $< -o $@ $(CFLAGS) $(LIBS)

$(SEC_LIB)/mqtt-pam.so: $(OBJ_DIR)/mqtt-pam.o
	sudo ld $(LD_FLAGS) $(LIBS) $< -o $@ 

all: $(BIN_DIR)/client $(BIN_DIR)/server $(BIN_DIR)/identification $(SEC_LIB)/mqtt-pam.so

.PHONY: clean

clean:
	rm -rf $(OBJ_DIR)/*.o $(BIN_DIR)/* 