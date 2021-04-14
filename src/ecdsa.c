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

ECDSA_SIG *ec_sign(const unsigned char *dgst, EC_KEY *ec_key)
{
    int retval = 1;
    ECDSA_SIG *signature;

    signature = ECDSA_do_sign(dgst, strlen(dgst), ec_key);
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

int ec_verify(const unsigned char *digest, ECDSA_SIG *signature, EC_KEY *pub_key)
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

EC_KEY *ec_new_pubkey(const uint8_t *pub_bytes, size_t pub_len) {
    EC_KEY *key;
    const uint8_t *pub_bytes_copy;

    key = EC_KEY_new_by_curve_name(ECCTYPE);
    pub_bytes_copy = pub_bytes;
    //d2i_EC_PUBKEY(&key, &pub_bytes_copy, pub_len);
    o2i_ECPublicKey(&key, &pub_bytes_copy, pub_len);

    return key;
}

char *der_to_hex(const char *label, const uint8_t *v, size_t len) {
    size_t i;

    printf("%s: ", label);
    for (i = 0; i < len; ++i) {
        printf("%02x", v[i]);
    }
    printf("\n");
}

char *pub_key_to_hex(const EC_KEY *ec_key)
{
    int retval = 0;
    BN_CTX *ctx;
    char *hex_pub_key = NULL;

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

int encode_pub_key_der(EC_KEY *ec_key, unsigned char **der_pub_key)
{   
    int num_bytes_copy = 0;

    if ((num_bytes_copy = i2d_EC_PUBKEY(ec_key, der_pub_key)) > 0)
    {
        printf("Successfully encoded %d pub key bytes to DER format\n", num_bytes_copy);
    }
    else
    {
        fprintf(stderr, "Unable to encode pub key to DER format");
    }

    return num_bytes_copy;
}

int encode_ec_signature_der(ECDSA_SIG *signature, unsigned char **der_ec_signature)
{   
    int num_bytes_copy = 0;
    
    if ((num_bytes_copy = i2d_ECDSA_SIG(signature, der_ec_signature)) > 0)
    {
        printf("Successfully encode %d ec signature bytes to DER format\n", num_bytes_copy);
    }
    else
    {
        fprintf(stderr, "Unable to encode ec signature to DER format");
    }

    return num_bytes_copy;
}

int decode_pub_key_der(const unsigned char *der_ec_pub_key, int len, EC_KEY *ec_key)
{
    int retval = 0;   

    ec_key = d2i_EC_PUBKEY(NULL, &der_ec_pub_key, len);
    
    if (ec_key != NULL)
    {
        printf("Successfully decode DER EC pub key to EC_KEY\n");
        retval = 1;
    }
    else
    {
        fprintf(stderr, "Unable to decode DER EC pub key to EC_KEY");
    }
    
    return retval;
}

int decode_ec_signature_der(const unsigned char *der_ec_signature, int len, ECDSA_SIG *signature)
{
    int retval = 0;

    signature = d2i_ECDSA_SIG(NULL, &der_ec_signature, len);

    if (signature != NULL)
    {
        printf("Successfully decode DER EC signauture to ECDSA_SIG\n");
        retval = 1;
    }
    else
    {
        fprintf(stderr, "Unable to decode DER EC signature to ECDSA_SIG\n");
    }

    return retval;
}

int sign_hash(const unsigned char *hash, const int len)
{
    int retval = 0;
    EC_KEY *ec_key;
    ECDSA_SIG *signature;
    uint8_t *der_pub_key, *der_pub_key_copy;
    uint8_t *der_sig, *der_sig_copy;
    size_t pub_key_len, sig_len;
    

    if (len > 0)
    {
        ec_key = EC_KEY_new_by_curve_name(ECCTYPE);
        if (ec_key != NULL)
        {
            if (create_keys(ec_key))
            {
                const EC_GROUP *ec_group = EC_KEY_get0_group(ec_key);
                pub_key_len = EC_GROUP_get_degree(ec_group);
                der_pub_key = calloc(pub_key_len, sizeof(uint8_t));
                der_pub_key_copy = der_pub_key;

                signature = ECDSA_do_sign(hash, len, ec_key);
                //signature = ec_sign(hash, ec_key);
                if (signature != NULL)
                {
                    printf("Successfully signed hash\n");
                    printf("verify (pre): %d\n", ECDSA_do_verify(hash, len, signature, ec_key));
                    sig_len = ECDSA_size(ec_key);
                    der_sig = calloc(sig_len, sizeof(uint8_t));
                    der_sig_copy = der_sig;

                    i2d_ECDSA_SIG(signature, &der_sig_copy);
                    der_to_hex("DER encoded sig", der_sig, sig_len);
                    
                    i2d_EC_PUBKEY(ec_key, &der_pub_key);
                    der_to_hex("DER ecnoded pb key", der_pub_key, pub_key_len);
                    
                    const uint8_t *const_sig = der_sig;
                    const uint8_t *const_pk = der_pub_key;
                    signature = d2i_ECDSA_SIG(NULL, &const_sig, sig_len);
                    if (signature != NULL)
                    {
                        EC_KEY *pub_key;
                        pub_key = EC_KEY_new_by_curve_name(ECCTYPE);
                        if (EC_KEY_set_public_key(pub_key, EC_KEY_get0_public_key(ec_key)))
                        {
                            printf("verify (post): %d\n", ECDSA_do_verify("agsdaeg", len, signature, pub_key));
                        }
                        else
                        {
                            printf("error d2i_EC_PUBKEY\n");
                        }
                    }
                    else
                    {
                        printf("error d2i_ECDSA_SIG\n");
                    }
//
                    //retval = 1;
                    /*if (encode_pub_key_der(ec_key, &der_pub_key) > 0 &&
                        encode_ec_signature_der(signature, &der_sig_copy) > 0)
                    {
                        retval = 1;          
                    }*/
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

    return retval;
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
