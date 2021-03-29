//compiled with gcc -g -lssl -UOPENSSL_NO_EC SO2228860.c -lcrypto
#include <openssl/ec.h>      // for EC_GROUP_new_by_curve_name, EC_GROUP_free, EC_KEY_new, EC_KEY_set_group, EC_KEY_generate_key, EC_KEY_free
#include <openssl/ecdsa.h>   // for ECDSA_do_sign, ECDSA_do_verify
#include <openssl/obj_mac.h> // for NID_secp192k1
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdio.h>

#define ECCTYPE "secp521r1"

EC_KEY *create_keys()
{
    EC_KEY *ec_key = NULL;
    
    ec_key = EC_KEY_new();
    if (ec_key == NULL)
    {
        fprintf(stderr, "Failed to create new EC key\n");
    }
    else
    {
        EC_GROUP *ecgroup= EC_GROUP_new_by_curve_name(NID_secp192k1);
    }
}


static int create_signature(unsigned char* hash)
{
    int function_status = -1;
    EC_KEY *myecc  = NULL;
    EVP_PKEY *pkey   = NULL;
    BIO *outbio = NULL;

    outbio  = BIO_new(BIO_s_file());
    outbio = BIO_new_fp(stdout, BIO_NOCLOSE);    

    myecc=EC_KEY_new();
    if (NULL == myecc)
    {
        printf("Failed to create new EC Key\n");
        function_status = -1;
    }
    else
    {
        EC_GROUP *ecgroup= EC_GROUP_new_by_curve_name(NID_secp192k1);
        if (NULL == ecgroup)
        {
            printf("Failed to create new EC Group\n");
            function_status = -1;
        }
        else
        {
            int set_group_status = EC_KEY_set_group(myecc,ecgroup);
            const int set_group_success = 1;
            if (set_group_success != set_group_status)
            {
                printf("Failed to set group for EC Key\n");
                function_status = -1;
            }
            else
            {
                const int gen_success = 1;
                int gen_status = EC_KEY_generate_key(myecc);
                if (gen_success != gen_status)
                {
                    printf("Failed to generate EC Key\n");
                    function_status = -1;
                }
                else
                {
                    pkey = EVP_PKEY_new();
                    if (!EVP_PKEY_assign_EC_KEY(pkey,myecc))
                        BIO_printf(outbio, "Error assigning ECC key to EVP_PKEY structure.");
                    
                    if(!PEM_write_bio_PrivateKey(outbio, pkey, NULL, NULL, 0, 0, NULL))
                        BIO_printf(outbio, "Error writing private key data in PEM format");

                    if(!PEM_write_bio_PUBKEY(outbio, pkey))
                        BIO_printf(outbio, "Error writing public key data in PEM format");
                    
                    const BIGNUM *private_key = EC_KEY_get0_private_key(myecc);
                    const EC_POINT *public_key_point = EC_KEY_get0_public_key(myecc);
                    EC_KEY *public_key;
                    EC_KEY_set_public_key(public_key, public_key_point);

                    ECDSA_SIG *signature = ECDSA_do_sign(hash, strlen(hash), myecc);
                    if (NULL == signature)
                    {
                        printf("Failed to generate EC Signature\n");
                        function_status = -1;
                    }
                    else
                    {

                        int verify_status = ECDSA_do_verify(hash, strlen(hash), signature, myecc);
                        const int verify_success = 1;
                        if (verify_success != verify_status)
                        {
                            printf("Failed to verify EC Signature\n");
                            function_status = -1;
                        }
                        else
                        {
                            printf("Verifed EC Signature\n");
                            function_status = 1;
                        }
                    }
                }
            }
            EC_GROUP_free(ecgroup);
        }
        EC_KEY_free(myecc);
    }

  return function_status;
}

int main( int argc , char * argv[] )
{
    unsigned char hash[] = "c7fbca202a95a570285e3d700eb04ca2";
    int status = create_signature(hash);
    return(0) ;
}
