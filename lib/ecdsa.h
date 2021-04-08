//compiled with gcc -g -lssl -UOPENSSL_NO_EC SO2228860.c -lcrypto

#ifndef ECDSA_H_
#define ECDSA_H_

#include <openssl/ec.h>
#include "crypt.h"

#define ECCTYPE NID_secp521r1
#define ECDSA_SIG_SIZE 132

struct Hash
{
    char digest[HASH_SIZE];
	unsigned char *signature;
	unsigned char *pub_key;
};

void print_keys(EC_KEY *ec_key);
int create_keys(EC_KEY *ec_key);
ECDSA_SIG *ec_sign(const unsigned char *dgst, EC_KEY *ec_key);
EC_KEY *get_pub_key(const EC_KEY *ec_key);
void initialize_Hash(struct Hash *signed_hash);
int ec_verify(const unsigned char *digest, ECDSA_SIG *signature, EC_KEY *pub_key);
struct Hash sign_hash(const char *hash);
EC_KEY *ec_new_pubkey(const uint8_t *pub_bytes, size_t pub_len);

#endif
