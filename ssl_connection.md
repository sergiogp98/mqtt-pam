# Cómo establecer una comunicación segura entre cliente y servidor usando MQTT broker

## Descripción

Tanto el cliente como el servidor necesitan de un par de claves pública y privada para cifrar y descifrar mensajes.
Estas claves tienen las siguientes propiedades:
- Directorios de almacenamiento de 
    * certificados CA: /etc/mosquitto/ca_certificates
    * claves publicas y privadas: /etc/mosquitto/certs
- Usa OpenSSL
- Version TLS: 1.2

## Pasos

Nota: el broker mqtt actua como CA (solo para test). En el sistema propuesto, el servidor de configuracion (configuration server) actua como CA

1. Creamos la clave privada de la CA

```console
root@broker-mqtt:/etc/mosquitto# openssl genrsa -des3 -out ca_certificates/c
a.key 2048
Generating RSA private key, 2048 bit long modulus (2 primes)
............................................................................................................................................+++++
...........................................+++++
e is 65537 (0x010001)
Enter pass phrase for ca_certificates/ca.key:
Verifying - Enter pass phrase for ca_certificates/ca.key:
```

2. Creamos el certificado CA y usamos la clave privada del paso 1 para firmarla
```console
root@broker-mqtt:/etc/mosquitto# openssl req -new -x509 -days 365 -key ca_certificates/ca.key -out ca_certificates/ca.crt
Enter pass phrase for ca_certificates/ca.key:
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:ES
State or Province Name (full name) [Some-State]:Granada
Locality Name (eg, city) []:Granada
Organization Name (eg, company) [Internet Widgits Pty Ltd]:UGR
Organizational Unit Name (eg, section) []:ATC
Common Name (e.g. server FQDN or YOUR name) []:ca
Email Address []:test@mail.com
```

3. Creamos la clave privada del broker mqtt sin protección con contraseña
```console
openssl genrsa -out certs/broker-mqtt.key 2
048
Generating RSA private key, 2048 bit long modulus (2 primes)
.............................................................................+++++
....................................+++++
e is 65537 (0x010001)
```

4. Creamos la ‎Solicitud de firma de certificados‎ para el broker mqtt usando la clave privada del paso 3
```console
root@broker-mqtt:/etc/mosquitto# openssl req -new -out certs/broker-mqtt.csr -key certs/broker-mqtt.key
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:ES
State or Province Name (full name) [Some-State]:Granada
Locality Name (eg, city) []:Granada
Organization Name (eg, company) [Internet Widgits Pty Ltd]:UGR
Organizational Unit Name (eg, section) []:ATC
Common Name (e.g. server FQDN or YOUR name) []:broker.mqtt.com
Email Address []:test@email.com

Please enter the following 'extra' attributes
to be sent with your certificate request
A challenge password []:
An optional company name []:
```

5. Usamos el certificado CA para firmar el certificado del broker mqtt del paso 4
```console
root@broker-mqtt:/etc/mosquitto# openssl x509 -req -in certs/broker-mqtt.csr -CA ca_certificates/ca.crt -CAkey ca_certificates/ca.key -CAcreateserial -out certs/broker-mqtt.crt
Signature ok
subject=C = ES, ST = Granada, L = Granada, O = UGR, OU = ATC, CN = broker.mqtt.com, emailAddress = test@email.com
Getting CA Private Key
Enter pass phrase for ca_certificates/ca.key
```

6. Movemos los el par de claves pública y privada a la carpeta certs y el certificado CA a ca_certificates
```console
root@broker-mqtt:/etc/mosquitto# ll certs/
total 24
drwxr-xr-x 2 root      root      4096 May 29 09:05 ./
drwxr-xr-x 5 root      root      4096 May 29 09:07 ../
-rw-r--r-- 1 root      root       130 Apr  3 11:31 README
-rw-r--r-- 1 root      root      1330 May 29 09:38 broker-mqtt.crt
-rw-r--r-- 1 root      root      1062 May 29 09:01 broker-mqtt.csr
-rw------- 1 mosquitto mosquitto 1675 May 29 08:58 broker-mqtt.key
root@broker-mqtt:/etc/mosquitto# ll ca_certificates/
total 24
drwxr-xr-x 2 root    root    4096 May 29 09:04 ./
drwxr-xr-x 5 root    root    4096 May 29 09:07 ../
-rw-r--r-- 1 root    root      73 Apr  3 11:31 README
-rw-r--r-- 1 vagrant vagrant 1452 May 29 08:57 ca.crt
-rw------- 1 root    root    1751 May 29 08:55 ca.key
-rw-r--r-- 1 root    root      41 May 29 09:38 ca.srl
```

7. Copiamos el certificado CA en el cliente (en /etc/mosquitto/ca_certificates)
```console
vagrant@client-1:~$ ll /etc/mosquitto/ca_certificates/
total 16
drwxr-xr-x 2 root    root    4096 May 29 09:12 ./
drwxr-xr-x 5 root    root    4096 May  8 09:11 ../
-rw-r--r-- 1 root    root      73 Apr  3 11:31 README
-rw-r--r-- 1 vagrant vagrant 1452 May 29 09:11 ca.crt
```

8. Editamos el archivo de configuración del broker mqtt para que use los archivos correspondientes
```conf
root@broker-mqtt:/etc/mosquitto# cat /etc/mosquitto/mosquitto.conf
# Place your local configuration in /etc/mosquitto/conf.d/
#
# A full description of the configuration file is at
# /usr/share/doc/mosquitto/examples/mosquitto.conf.example
pid_file /run/mosquitto/mosquitto.pid

log_dest file /var/log/mosquitto/mosquitto.log
log_type all
log_timestamp true

include_dir /etc/mosquitto/conf.d

listener 1883 localhost
listener 8883

cafile /etc/mosquitto/ca_certificates/ca.crt
certfile /etc/mosquitto/certs/broker-mqtt.crt
keyfile /etc/mosquitto/certs/broker-mqtt.key

tls_version tlsv1.2

allow_anonymous true
```

9. Comprobamos que el certificado del broker mqtt está firmado por la CA:
```console
root@broker-mqtt:/etc/mosquitto# openssl verify -CAfile ca_certificates/ca.crt certs/broker-mqtt.crt
certs/broker-mqtt.crt: OK
```
