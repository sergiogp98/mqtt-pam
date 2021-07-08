/**
 * Header file with functions related with ECDSA
 */

#ifndef ECDSA_H_
#define ECDSA_H_

#include <openssl/ec.h>      // for EC_GROUP_new_by_curve_name, EC_GROUP_free, EC_KEY_new, EC_KEY_set_group, EC_KEY_generate_key, EC_KEY_free
#include <openssl/ecdsa.h>   // for ECDSA_do_sign, ECDSA_do_verify
#include <openssl/obj_mac.h> // for NID_secp192k1
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <pwd.h>
#include "../include/utils.h"

#define ECCTYPE NID_secp521r1
#define ECDSA_SIG_SIZE 132

struct EC_SIGN
{
    /* Elliptic Curve Digital Signature params */
    unsigned char *r; // r value (hex format)
    unsigned char *s; // s value (HEX format)
};

/**
 * Create new EC key pair
 * @param ec_key EC key pair
 * @return success creation keys 
 */
int create_keys(EC_KEY *ec_key)
{
    int retval = 1;

    if (EC_KEY_generate_key(ec_key))
    {
        printf("Successfully create EC key pair\n");
    }
    else
    {
        fprintf(stderr, "Failed to create EC key pair\n");
        retval = 0;
    }

    return retval;
}

/**
 * Write EC key pair to PEM format
 * @param ec_key EC key pair
 * @param priv_key private key in PEM format
 * @param pub_key public key in PEM format
 */
void write_key_to_pem(EC_KEY *ec_key, char *priv_key, char *pub_key)
{
    DIR *dir;
    EVP_PKEY *pkey = NULL;
    FILE *priv_key_file;
    FILE *pub_key_file;

    // Set private key (file and bio)
    priv_key_file = fopen(priv_key, "wr");
    if (priv_key_file == NULL)
    {
        fprintf(stderr, "Error opening %s\n", priv_key);
        exit(1);
    }

    // Set public key (file nad bio)
    pub_key_file = fopen(pub_key, "wr");
    if (pub_key_file == NULL)
    {
        fprintf(stderr, "Error opening %s\n", pub_key);
        exit(1);
    }

    // Set keys to pkey
    pkey = EVP_PKEY_new();
    if (!EVP_PKEY_assign_EC_KEY(pkey, ec_key))
        fprintf(stderr, "Error assigning ECC key to EVP_PKEY structure\n");

    // Write keys in PEM format
    if (!PEM_write_ECPrivateKey(priv_key_file, ec_key, NULL, NULL, 0, 0, NULL))
        fprintf(stderr, "Error writing private key data in PEM format\n");

    if (!PEM_write_EC_PUBKEY(pub_key_file, ec_key))
        fprintf(stderr, "Error writing public key data in PEM format\n");

    fclose(priv_key_file);
    fclose(pub_key_file);
}

/**
 * Convert EC sign r value to HEX format
 * @param signature EC signature
 * @return HEX EC signature r value
 */
char *r_value_to_hex(const ECDSA_SIG *signature)
{
    char *r_hex;

    const BIGNUM *r_value = ECDSA_SIG_get0_r(signature);
    if (r_value != NULL)
    {
        r_hex = BN_bn2hex(r_value);
        if (r_hex == NULL)
        {
            fprintf(stderr, "Failed to convert r value to hex format\n");
        }
    }
    else
    {
        fprintf(stderr, "Failed to get r value of EC signature\n");
    }

    return r_hex;
}

/**
 * Convert EC sign s value to HEX format
 * @param signature EC signature
 * @return HEX EC signature s value
 */
char *s_value_to_hex(const ECDSA_SIG *signature)
{
    char *s_hex;

    const BIGNUM *s_value = ECDSA_SIG_get0_s(signature);
    if (s_value != NULL)
    {
        s_hex = BN_bn2hex(s_value);
        if (s_hex == NULL)
        {
            fprintf(stderr, "Failed to convert r value to hex format\n");
        }
    }
    else
    {
        fprintf(stderr, "Failed to get r value of EC signature\n");
    }

    return s_hex;
}

/**
 * Get EC signature from r and s HEX values 
 * @param r_hex r HEX value
 * @param s_hex s HEX value
 * @return EC signature
 */
ECDSA_SIG *get_ec_sig(const char *r_hex, const char *s_hex)
{
    ECDSA_SIG *signature = NULL;
    BIGNUM *r = BN_new();
    BIGNUM *s = BN_new();

    if (BN_hex2bn(&r, r_hex) > 0)
    {
        if (BN_hex2bn(&s, s_hex) > 0)
        {
            signature = ECDSA_SIG_new();
            if (ECDSA_SIG_set0(signature, r, s) == 0)
            {
                fprintf(stderr, "Failed to set r and s values to EC signature\n");
            }
        }
        else
        {
            fprintf(stderr, "Error converting s_hex value to BIGNUM\n");
        }
    }
    else
    {
        fprintf(stderr, "Error converting r_hex value to BIGNUM\n");
    }

    return signature;
}

/**
 * Get EC public key from PEM file
 * @param pemfile PEM file
 * @return EC public key
 */
EC_KEY *get_pub_key_from_pem(const char *pemfile)
{
    FILE *file;
    EC_KEY *pub_key;

    // Open file    
    file = fopen(pemfile, "r");
    if (file != NULL)
    {
        // Create pub_key from PEM file
        pub_key = EC_KEY_new_by_curve_name(ECCTYPE);
        PEM_read_EC_PUBKEY(file, &pub_key, NULL, NULL);
    }
    else
    {
        fprintf(stderr, "Unable to open %s file\n", pemfile);
    }

    return pub_key;
}

/**
 * Get EC private key from PEM file
 * @param pemfile PEM file
 * @return EC private key
 */
EC_KEY *get_priv_key_from_pem(const char *pemfile)
{
    FILE *file;
    EC_KEY *priv_key;

    // Open file
    file = fopen(pemfile, "r");
    if (file != NULL)
    {
        priv_key = EC_KEY_new_by_curve_name(ECCTYPE);

        // Create pub_key from PEM file
        PEM_read_ECPrivateKey(file, &priv_key, NULL, NULL);
    }
    else
    {
        fprintf(stderr, "Unable to open %s file\n", pemfile);
    }

    return priv_key;
}

/**
 * Sign hash with private key and save both values r and s
 * @param hash hash value
 * @param hash_len hash length
 * @param pem_key private key in PEM format
 * @return EC_SIGN with both r and s values converted to HEX format
 */
struct EC_SIGN sign_hash(const unsigned char *hash, const int hash_len, const char *pem_key)
{
    int retval = 0;
    EC_KEY *priv_key;
    ECDSA_SIG *signature;
    struct EC_SIGN ec_sign;

    if (hash_len > 0)
    {
        priv_key = get_priv_key_from_pem(pem_key);
        if (priv_key != NULL)
        {
            signature = ECDSA_do_sign(hash, hash_len, priv_key);
            if (signature != NULL)
            {
                ec_sign.r = r_value_to_hex(signature);
                ec_sign.s = s_value_to_hex(signature);
                ECDSA_SIG_free(signature);
                EC_KEY_free(priv_key);
            }
            else
            {
                fprintf(stderr, "Failed to sign hash value\n");
            }
        }
        else
        {
            fprintf(stderr, "Failed to generate EC Key\n");
        }
    }
    else
    {
        fprintf(stderr, "Empty hash to sign\n");
    }

    return ec_sign;
}

#endif
