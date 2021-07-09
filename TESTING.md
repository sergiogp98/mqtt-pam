# TESTING

## Dependancies

To test this module you need to have installed the following dependancies:

- gcc
- mosquitto (https://mosquitto.org/download/)
- libmosquitto-dev
- libpam0g-dev
- libssl-dev
- uuid-dev

## Compile

To compile all the scripts: `make all`

## Manually compile and link PAM file to a libray system file

1. Compile using `fPIC` and `fno-stack-protector` arguments: 

``gcc -fPIC -fno-stack-protector -c src/pam_file.c -o bin/pam_file.o``

2. Link to PAM default library (optional):

``sudo ld -x --shared -o /lib/security/pam_file.so bin/pam_file.o``

3. If you want to test the PAM file, compile to executable using `lpam` and `lpam_misc` arguments:

``gcc -o bin/pam_test src/pam_test.c -lpam -lpam_misc``