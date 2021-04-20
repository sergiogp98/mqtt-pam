#ifndef ECDSA_H_
#define ECDSA_H_

#include <openssl/ec.h>      
#include <openssl/obj_mac.h>

#define ECCTYPE NID_secp521r1
#define ECDSA_SIG_SIZE 132

struct EC_PARAMS
{
	/* Pub key and signature encoded in DER and EC verification */
	unsigned char *r; // ECDSA signature r value (hex format)
	unsigned char *s; // ECDSA signature s value (HEX format)
	unsigned char *pub_key; // EC_POINT (HEX format)
};

void print_keys(EC_KEY *ec_key);
int create_keys(EC_KEY *ec_key);
ECDSA_SIG *ec_sign(const unsigned char *digest, int len, EC_KEY *ec_key);
int ec_verify(const unsigned char *digest, int len, ECDSA_SIG *signature, EC_KEY *pub_key);
char *pub_key_to_hex(const EC_KEY *ec_key);
char *r_value_to_hex(const ECDSA_SIG *signature);
char *s_value_to_hex(const ECDSA_SIG *signature);
ECDSA_SIG *get_ec_sig(const char *r_hex, const char *s_hex);
void print_error(const char *label, unsigned long err);
EC_KEY *get_ec_key(const unsigned char *ec_point_hex);
struct EC_PARAMS sign_hash(const unsigned char *hash, const int hash_len);

#endif
