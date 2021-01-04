# TFG

# Uso módulo PAM

Compile and link PAM file to a libray system file:

``gcc -fPIC -fno-stack-protector -c src/pam_file.c -o bin/pam_file.o``

``sudo ld -x --shared -o /lib/security/pam_file.so bin/pam_file.o``

Test PAM test file:

``gcc -o bin/pam_test src/pam_test.c -lpam -lpam_misc``
