#!/bin/bash

gcc -fPIC -fno-stack-protector -c src/mypam.c -o bin/mypam.o 
sudo ld -x --shared -o /lib/security/mypam.so bin/mypam.o 