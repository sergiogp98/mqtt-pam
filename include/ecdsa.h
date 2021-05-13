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

void print_keys(EC_KEY *ec_key)
{
    EVP_PKEY *pkey = NULL;
    BIO *outbio = NULL;

    outbio = BIO_new(BIO_s_file());
    outbio = BIO_new_fp(stdout, BIO_NOCLOSE);

    pkey = EVP_PKEY_new();
    if (!EVP_PKEY_assign_EC_KEY(pkey, ec_key))
        BIO_printf(outbio, "Error assigning ECC key to EVP_PKEY structure\n");

    if (!PEM_write_bio_PrivateKey(outbio, pkey, NULL, NULL, 0, 0, NULL))
        BIO_printf(outbio, "Error writing private key data in PEM format\n");

    if (!PEM_write_bio_PUBKEY(outbio, pkey))
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

void write_key_to_pem(EC_KEY *ec_key, char *priv_key, char *pub_key)
{
    DIR *dir;
    EVP_PKEY *pkey = NULL;
    //BIO *priv_key_bio = NULL;
    //BIO *pub_key_bio = NULL;
    FILE *priv_key_file;
    FILE *pub_key_file;

    // Set private key (file and bio)
    priv_key_file = fopen(priv_key, "wr");
    if (priv_key_file == NULL)
    {
        fprintf(stderr, "Error opening %s\n", priv_key);
        exit(1);
    }
    //priv_key_bio = BIO_new(BIO_s_file());
    //priv_key_bio = BIO_new_fp(priv_key_file, BIO_NOCLOSE);

    // Set public key (file nad bio)
    pub_key_file = fopen(pub_key, "wr");
    if (pub_key_file == NULL)
    {
        fprintf(stderr, "Error opening %s\n", pub_key);
        exit(1);
    }
    //pub_key_bio = BIO_new(BIO_s_file());
    //pub_key_bio = BIO_new_fp(pub_key_file, BIO_NOCLOSE);

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
    if (ctx) /* Handle error */
    {
        hex_pub_key = EC_POINT_point2hex(
            EC_KEY_get0_group(ec_key),
            EC_KEY_get0_public_key(ec_key),
            POINT_CONVERSION_COMPRESSED,
            ctx);

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
    if (ctx) /* Handle error */
    {
        ec_point = EC_POINT_hex2point(
            EC_GROUP_new_by_curve_name(ECCTYPE),
            ec_point_hex,
            ec_point,
            ctx);

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

/*Check whether there is only one PEM key pair inside path*/
/*char *get_pem_filename(const char *path)
{
    char *pemfile = NULL;
    DIR *dir;
    struct dirent *file;
    int more_than_one = 0;
    struct stat *file_stat;
    int found = 0;
    char *uuid = NULL;

    // Open directory
    dir = opendir(path);
    if (dir != NULL)
    {
        while ((file = readdir(dir)) != NULL && !more_than_one)
        {
            stat(file->d_name, file_stat);
            if (S_ISREG(file_stat->st_mode) &&
                check_uuid_regex(file->d_name) &&
                (check_extension(file->d_name, ".pub") ||
                 check_extension(file->d_name, ".key")))
            {
                if (file_stat->st_size > 0)
                {
                    if (file_stat->st_mode & S_IRUSR)
                    {
                        if (!found || uuid == NULL)
                        {
                            uuid = get_filename(file->d_name);
                        }
                        else if (strcmp(uuid, get_filename(file->d_name)) == 0)
                        {
                            found = 1;
                            pemfile = uuid;
                        }
                        else
                        {
                            more_than_one = 1;
                            fprintf(stderr, "There is more than one PEM key pair in %s\n", dir);
                        }
                    }
                    else
                    {
                        fprintf(stderr, "Found PEM file in %s with no user read permission\n", anubis);
                    }
                }
                else
                {
                    fprintf(stderr, "%s file in %s is empty\n", file->d_name, dir);
                }
            }
        }
    }
    else
    {
        const char *err_msg = strcat("Error opening", path);
        perror(err_msg);
    }

    return pemfile;
}*/

/*EC_KEY *get_priv_key(const char *pem_dir)
{
    char *pemfile;
    EC_KEY *priv_key = NULL;

    // Open directory
    const char *uuid = get_pem_filename(pem_dir);
    if (uuid != NULL) // Exists onñy one PEM key pair
    {
        // Format pub key filename
        sprintf(pemfile, "%s/%s.key", pem_dir, uuid);

        // Create EC_KEY from PEM file
        priv_key = EC_KEY_new_by_curve_name(ECCTYPE);
        get_priv_key_from_pem(pemfile, priv_key);
        if (priv_key == NULL)
        {
            fprintf(stderr, "Failed to read pub key from PEM file: %s\n", pemfile);
        }
    }

    return priv_key;
}*/

/*EC_KEY *get_pub_key(const char *pem_dir)
{
    char *pemfile;
    EC_KEY *pub_key = NULL;

    // Open directory
    const char *uuid = get_pem_filename(pem_dir);
    if (uuid != NULL) // Exists onñy one PEM key pair
    {
        // Format pub key filename
        sprintf(pemfile, "%s/%s.pub", pem_dir, uuid);

        // Create EC_KEY from PEM file
        pub_key = EC_KEY_new_by_curve_name(ECCTYPE);
        get_pub_key_from_pem(pemfile, pub_key);
        if (pub_key == NULL)
        {
            fprintf(stderr, "Failed to read pub key from PEM file: %s\n", pemfile);
        }
    }

    return pub_key;
}*/

char *get_username_from_uid(uid_t uid)
{
    struct passwd *pws;
    char *username;

    pws = getpwuid(uid);
    username = pws->pw_name;

    return username;
}

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
