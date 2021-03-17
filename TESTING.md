# TESTING

## Compile sources

### Library (sha)
```
gcc -c src/sha.c -o bin/sha.o
```

### Server 
```
gcc -c -g src/server.c -o server.o
gcc bin/server.o bin/sha.o -lmosquitto -lcrypt -o bin/server
```

### Client
```
gcc -c src/client.c -o client.o
gcc bin/client.o bin/sha.o -lmosquitto -lcrypt -o bin/client
```

### Broker
```
gcc broker.c -lmosquitto -o bin/broker
```

## Link PAM module 
gcc -fPIC -fno-stack-protector -c src/mypam.c -o bin/mypam.o 
sudo ld -x --shared -o /lib/security/mypam.so bin/mypam.o 
