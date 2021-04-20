FROM ubuntu:20.04

RUN apt-get update && apt-get install -y \
    mosquitto-clients \ 
    mosquitto \
    libmosquitto-dev \
    libpam0g-dev \
    libssl-dev  \
    net-tools

COPY mosquitto.conf /etc/mosquitto/mosquitto.conf

EXPOSE 1883/tcp
ENTRYPOINT [ "/" ]
