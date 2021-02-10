vim mypam.c
cat mypam.c 
gcc
apt install gcc
mkdir --help
ld
cat mypam.c 
gcc -fPIC -fstack-protector -c mypam.c 
apt-cache search libpam
apt-cache search libpam | grep dev
apt install libpam0g-dev --fix-broken
gcc -fPIC -fstack-protector -c mypam.c 
ls
ld -x -shared -o /lib/security/mypam.o mypam.o 
gcc -fPIC -fstack-protector -c mypam.c 
ls
rm /lib/security/mypam.o 
gcc -fPIC -fstack-protector -c mypam.c 
ls
ld -x -shared -o /lib/security/mypam.so mypam.o 
file /lib/security/mypam.so 
ldd /lib/security/mypam.so 
ldd mypam.o 
gcc -shared -libpam mypam.o -o mypam.so
gcc -shared mypam.o -o mypam.so -libpam
ls
ldd mypam.o
cat /etc/ssh/sshd_config | grep UsePam
cat /etc/ssh/sshd_config | grep UsePAM
vim /etc/pam.d/sshd 
vim /etc/ssh/sshd_config
systemctl restart ssh
ip addr
apt install net-tools
ifconfig eth0
ifconfig 
ifconfig enp0s8:
ifconfig enp0s8
su
ifconfig enp0s8
vim /etc/ssh/sshd_config
systemctl restart ssh
ifconfig enp0s8
vi secret-word.txt
echo secret-word.txt 
cat secret-word.txt 
vi secret-word.txt
cat secret-word.txt 
ls
ls -l s
ls -l secret-word.txt 
chmod 400 secret-word.txt 
ls -l secret-word.txt 
chmod 600 sha256.sh 
ls -l sha256.sh 
vim sha256.sh 
chmod 700 sha256.sh 
ls -l
./sha256.sh 
vim sha256.sh 
./sha256.sh 
vim sha256.sh 
./sha256.sh 
vim sha256.sh 
./sha256.sh 
cat /tmp/abc-script.1FBTqR
vim sha256.sh 
./sha256.sh 
cat /tmp/abc-script.dKU4CT
./sha256.sh 
vim sha256.sh 
./sha256.sh 
vim challenge.c 
rm .challenge.c.swp 
vim challenge.c 
find / -name mosquitto.h
grep 'mosquitto_new' /usr/include/mosquitto.h 
find / -name mosquitto.c
mosquitto v
mkdir -p /usr/share/mosquitto
rmdir /usr/share/mosquitto
mkdir -p /usr/share/mosquitto
cd /usr/share/mosquitto/
wget https://mosquitto.org/files/source/mosquitto-2.0.7.tar.gz
wget https://mosquitto.org/files/source/mosquitto-2.0.7.tar.gz.asc
ls
gzip -d mosquitto-2.0.7.tar.gz
gzip -d mosquitto-2.0.7.tar.gz.asc 
ls
cat mosquitto-2.0.7.tar.gz.asc 
gpg mosquitto-2.0.7.tar.gz.asc 
gpg --with-fingerprint mosquitto-2.0.7.tar.gz.asc 
rm mosquitto-2.0.7.tar
wget https://mosquitto.org/files/source/mosquitto-2.0.7.tar.gz
gpg --with-fingerprint mosquitto-2.0.7.tar.gz.asc 
gpg --help
gpg --fingerprint mosquitto-2.0.7.tar.gz.asc 
gpg --fingerprint mosquitto-2.0.7.tar.gz
gpg --fingerprint mosquitto-2.0.7.tar.gz.asc 
ls
gzip -d mosquitto-2.0.7.tar.gz
tar xfv mosquitto-2.0.7.tar
cd mosquitto-2.0.7
ls
make
vim README-compiling.md 
apt install make
make
apt install g++
make
cd /usr/share/mosquitto/
ls
cd mosquitto-2.0.7
ls
make
cd ..
git clone https://github.com/DaveGamble/cJSON.git
cd cJSON/
ls
apt install cmake
mkdir build
cd build/
cmake ..
ls
mak
make
make install
cd ..
cd ../mosquitto/
cd mosquitto-2.0.7
make
find / -name mosquitto
find / -name mosquitto.c
cd /usr/share/mosquitto/mosquitto-2.0.7
ls
vim README
vim README.md 
vim README-compiling.md 
make
cd ..
mv mosquitto-2.0.7 /home/vagrant/
ls
rm *
cd .
cd ..
rmdir mosquitto/
