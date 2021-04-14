#include <openssl/ec.h>      // for EC_GROUP_new_by_curve_name, EC_GROUP_free, EC_KEY_new, EC_KEY_set_group, EC_KEY_generate_key, EC_KEY_free
#include <openssl/ecdsa.h>   // for ECDSA_do_sign, ECDSA_do_verify
#include <openssl/obj_mac.h> // for NID_secp192k1
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include "../lib/ecdsa.h"

void print_keys(EC_KEY *ec_key)
{
    EVP_PKEY *pkey = NULL;
    BIO *outbio = NULL;

    outbio = BIO_new(BIO_s_file());
    outbio = BIO_new_fp(stdout, BIO_NOCLOSE);

    pkey = EVP_PKEY_new();
    if (!EVP_PKEY_assign_EC_KEY(pkey, ec_key))
        BIO_printf(outbio, "Error assigning ECC key to EVP_PKEY structure\n");
    
    if(!PEM_write_bio_PrivateKey(outbio, pkey, NULL, NULL, 0, 0, NULL))
        BIO_printf(outbio, "Error writing private key data in PEM format\n");

    if(!PEM_write_bio_PUBKEY(outbio, pkey))
        BIO_printf(outbio, "Error writing public key data in PEM format\n");
}

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

ECDSA_SIG *ec_sign(const unsigned char *digest, int len, EC_KEY *ec_key)
{
    int retval = 1;
    ECDSA_SIG *signature;

    signature = ECDSA_do_sign(digest, len, ec_key);
    if (signature != NULL)
    {
        printf("Signed digest\n");
    }
    else
    {
        fprintf(stderr, "Failed to generate EC Signature\n");
        retval = 0;
    }

    return signature;
}

int ec_verify(const unsigned char *digest, int len, ECDSA_SIG *signature, EC_KEY *pub_key)
{
    int retval = 1;
    
    if (ECDSA_do_verify(digest, strlen(digest), signature, pub_key))
    {
        printf("Verifed EC Signature\n");
    }
    else
    {
        fprintf(stderr, "Failed to verify EC Signature\n");
        retval = 0;
    }

    return retval;
}

char *pub_key_to_hex(const EC_KEY *ec_key)
{
    int retval = 0;
    BN_CTX *ctx;
    char *hex_pub_key;

    ctx = BN_CTX_new();
    if(ctx) /* Handle error */
    {
        hex_pub_key = EC_POINT_point2hex(
            EC_KEY_get0_group(ec_key),
            EC_KEY_get0_public_key(ec_key),
            POINT_CONVERSION_COMPRESSED,
            ctx
        );

        if (hex_pub_key != NULL)
        {
            retval = 1;
        }
        else
        {
            fprintf(stderr, "Unable to convert EC_POINT to HEX\n");
        }
    }
    else
    {
        fprintf(stderr, "Error creating BN_CTX\n");
    }   
    BN_CTX_free(ctx);

    return hex_pub_key;
}

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

ECDSA_SIG *get_ec_sig(const char *r_hex, const char *s_hex)
{
    ECDSA_SIG *signature = ECDSA_SIG_new();
    BIGNUM *r = BN_new();
    BIGNUM *s = BN_new();
    
    if (BN_hex2bn(&r, r_hex) > 0)
    {
        if (BN_hex2bn(&s, s_hex) > 0)
        {
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

void print_error(const char *label, unsigned long err)
{
    static char buffer[120 * sizeof(uint8_t)];
    ERR_error_string(err, buffer);
    fprintf(stderr, "%s: %s\n", label, buffer);
}

EC_KEY *get_ec_key(const unsigned char *ec_point_hex)
{
    EC_KEY *ec_key;
    EC_POINT *ec_point;
    BN_CTX *ctx;

    ec_key = EC_KEY_new_by_curve_name(ECCTYPE);
    ec_point = EC_POINT_new(EC_GROUP_new_by_curve_name(ECCTYPE));
    ctx = BN_CTX_new();
    if(ctx) /* Handle error */
    {
        ec_point = EC_POINT_hex2point(
            EC_GROUP_new_by_curve_name(ECCTYPE),
            ec_point_hex,
            ec_point,
            ctx
        );

        if (ec_point != NULL)
        {
            if (EC_KEY_set_public_key(ec_key, ec_point) == 0)
            {
                fprintf(stderr, "Failed to create EC_KEY with EC_POINT\n");
            }
        }
        else
        {
            fprintf(stderr, "Failed to create EC_POINT with from HEX format\n");
        }
    }

    return ec_key;
}

struct EC_PARAMS sign_hash(const unsigned char *hash, const int hash_len)
{
    int retval = 0;
    EC_KEY *ec_key;
    ECDSA_SIG *signature;
    struct EC_PARAMS ec_params;
    ec_params.r = NULL;

    if (hash_len > 0)
    {
        ec_key = EC_KEY_new_by_curve_name(ECCTYPE);
        if (ec_key != NULL)
        {
            if (create_keys(ec_key))
            {
                signature = ECDSA_do_sign(hash, hash_len, ec_key);
                if (signature != NULL)
                {
                    ec_params.pub_key = pub_key_to_hex(ec_key);
                    ec_params.r = r_value_to_hex(signature);
                    ec_params.s = s_value_to_hex(signature);
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
            fprintf(stderr, "Failed to create new EC key\n");
        }
    }
    else
    {
        fprintf(stderr, "Empty hash to sign\n");
    }

    ECDSA_SIG_free(signature);
    EC_KEY_free(ec_key);

    return ec_params;
}

/*int main( int argc , char * argv[] )
{
    char *hash = "c7fbca202a95a570285e3d700eb04ca2";
    Hash signed_hash;
    
    signed_hash = sign_hash(hash);
    ec_verify(signed_hash.digest, signed_hash.signature, signed_hash.pub_key);
    if (EC_KEY_check_key(signed_hash.pub_key))
    {
        //printf("%s\n", signed_hash.digest);
        //print_keys(signed_hash.pub_key);
        ec_verify(signed_hash.digest, signed_hash.signature, signed_hash.pub_key);
    }
    
    return 0;
}*/
