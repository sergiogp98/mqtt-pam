#!/bin/bash

# server-1
rsync -a root@172.16.1.101:~ ./server-1
rsync -a vagrant@172.16.1.101:~ ./server-1

# broker-mqtt
rsync -a vagrant@172.16.1.100:~ ./broker-mqtt
rsync -a root@172.16.1.100:~ ./broker-mqtt

