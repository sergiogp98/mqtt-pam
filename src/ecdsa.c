//compiled with gcc -g -lssl -UOPENSSL_NO_EC SO2228860.c -lcrypto
 
#include <openssl/ec.h>      // for EC_GROUP_new_by_curve_name, EC_GROUP_free, EC_KEY_new, EC_KEY_set_group, EC_KEY_generate_key, EC_KEY_free
#include <openssl/ecdsa.h>   // for ECDSA_do_sign, ECDSA_do_verify
#include <openssl/obj_mac.h> // for NID_secp192k1
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdio.h>

#define ECCTYPE NID_secp521r1

static int create_keys(EC_KEY *ec_key)
{
    int retval = 1;
    
    ec_key = EC_KEY_new();
    if (ec_key == NULL)
    {
        fprintf(stderr, "Failed to create new EC key\n");
        retval = 0;
    }
    else
    {
        EC_GROUP *ec_group= EC_GROUP_new_by_curve_name(ECCTYPE);
        if (NULL == ec_group)
        {
            fprintf(stderr, "Failed to create new EC Group\n");
            retval = 0;
        }
        else
        {
            if(EC_KEY_set_group(ec_key, ec_group))
            {
                if (EC_KEY_generate_key(ec_key))
                {
                    printf("Successfully create EC key pair\n");
                }
                else
                {
                    fprintf(stderr, "Failed to generate EC Key\n");
                    retval = 0;
                }
            }
            else
            {
                fprintf(stderr, "Failed to set group for EC Key\n");
                retval = 0;
            }
            EC_GROUP_free(ec_group);
        }
        EC_KEY_free(ec_key);
    }

    return retval;
}

void print_keys(EC_KEY *ec_key)
{
    EVP_PKEY *pkey = NULL;
    BIO *outbio = NULL;

    outbio = BIO_new(BIO_s_file());
    outbio = BIO_new_fp(stdout, BIO_NOCLOSE);

    pkey = EVP_PKEY_new();
    if (!EVP_PKEY_assign_EC_KEY(pkey, ec_key))
        BIO_printf(outbio, "Error assigning ECC key to EVP_PKEY structure.");
    
    if(!PEM_write_bio_PrivateKey(outbio, pkey, NULL, NULL, 0, 0, NULL))
        BIO_printf(outbio, "Error writing private key data in PEM format");

    if(!PEM_write_bio_PUBKEY(outbio, pkey))
        BIO_printf(outbio, "Error writing public key data in PEM format");
}

static int ec_sign(const unsigned char *dgst, ECDSA_SIG *signature, EC_KEY *ec_key)
{
    int retval = 1;

    signature = ECDSA_do_sign(dgst, strlen(dgst), ec_key);
    if (signature == NULL)
    {
        fprintf(stderr, "Failed to generate EC Signature\n");
        retval = 0;
    }

    return retval;
}

static int ec_verify(const unsigned char *dgst, const ECDSA_SIG *signature, EC_KEY *ec_key)
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

static int create_signature(unsigned char* hash)
{
    int retval = 1;
    EC_KEY *myecc  = NULL;

    if (strlen(hash) > 0)   
    {
        if (create_keys(myecc))
        {   
            ECDSA_SIG *signature;
            if (ec_sign(hash, signature, myecc))
            {
                if (ec_verify(hash, signature, myecc))
                {
                    retval = 0;
                }
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

    return retval;
}

int main( int argc , char * argv[] )
{
    unsigned char hash[] = "c7fbca202a95a570285e3d700eb04ca2";
    int status = create_signature(hash);
    return status ;
}
