//compiled with gcc -g -lssl -UOPENSSL_NO_EC SO2228860.c -lcrypto
 
#include <openssl/ec.h>      // for EC_GROUP_new_by_curve_name, EC_GROUP_free, EC_KEY_new, EC_KEY_set_group, EC_KEY_generate_key, EC_KEY_free
#include <openssl/ecdsa.h>   // for ECDSA_do_sign, ECDSA_do_verify
#include <openssl/obj_mac.h> // for NID_secp192k1
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdio.h>

#define ECCTYPE NID_secp521r1

typedef struct
{
    char *digest;
	ECDSA_SIG *signature;
	EC_KEY *pub_key;
} Hash;

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

int ec_verify(const unsigned char *dgst, const ECDSA_SIG *signature, EC_KEY *ec_key)
{
    int retval = 1;
    
    if (ECDSA_do_verify(dgst, strlen(dgst), signature, ec_key))
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

/*EC_KEY *get_pub_key(const EC_KEY *ec_key)
{
    EC_KEY *pub_key;
    BN_CTX *ctx;
    
    if (EC_KEY_check_key(ec_key))
    {
        ctx = BN_CTX_new();
        if (ctx != NULL)
        {   
            BN_CTX_start(ctx);
            const unsigned char *pub_key_hex = EC_POINT_point2hex(
                EC_KEY_get0_group(ec_key), 
                EC_KEY_get0_public_key(ec_key),
                POINT_CONVERSION_UNCOMPRESSED,
                ctx
            );
            pub_key = EC_KEY_new_by_curve_name(ECCTYPE);
            o2i_ECPublicKey(&pub_key, &pub_key_hex, strlen(pub_key_hex)); 
            print_keys(pub_key);
        }    
        else
        {
            fprintf(stderr, "Failed to create BIGNUM variable\n");
        }
    }
    else
    {
        fprintf(stderr, "Invalid EC_KEY\n");
    }

    return pub_key;
}*/

Hash sign_hash(char* hash)
{
    int retval = 0;
    EC_KEY *myecc;
    ECDSA_SIG *signature;
    Hash signed_hash;

    if (strlen(hash) > 0)   
    {
        myecc = EC_KEY_new_by_curve_name(ECCTYPE);
        if (myecc == NULL)
        {
            fprintf(stderr, "Failed to create new EC key\n");
            retval = 0;
        }
        else
        {
            if (create_keys(myecc))
            {   
                signature = ec_sign(hash, myecc);
                if (signature != NULL)
                {
                    printf("Successfully signed hash\n");
                    signed_hash.digest = hash;
                    signed_hash.signature = signature;
                    signed_hash.pub_key = myecc;
                    retval = 1;    
                }
                else
                {
                    fprintf(stderr, "Failed to sign EC signature\n");
                }
            }
            else
            {                 
                fprintf(stderr, "Failed to generate EC Key\n");
            }   
        }
    }
    else
    {
        fprintf(stderr, "Empty hash to sign\n");
    }

    return signed_hash;
}

int main( int argc , char * argv[] )
{
    char *hash = "c7fbca202a95a570285e3d700eb04ca2";
    Hash signed_hash;
    
    signed_hash = sign_hash(hash);

    if (EC_KEY_check_key(signed_hash.pub_key))
    {
        //printf("%s\n", signed_hash.digest);
        //print_keys(signed_hash.pub_key);
        ec_verify(signed_hash.digest, signed_hash.signature, signed_hash.pub_key);
    }
    
    return 0;
}
