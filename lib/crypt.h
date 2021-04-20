/*
Doc: https://www.gnu.org/software/libc/manual/html_mono/libc.html#Unpredictable-Bytes
https://www.openssl.org/docs/manmaster/man3/SHA512.html
*/

#ifndef SHA_H_
#define SHA_H_

#include <openssl/sha.h>

#define CHALLENGE_SIZE 64
#define HASH_SIZE SHA512_DIGEST_LENGTH

char* sha512(const char *digest);
char *get_challenge();

#endif
