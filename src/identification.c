/* Create EC key and write them to .anubis directory in home */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "../include/ecdsa.h"
#include "../include/uuid.h"

#define MODE S_IRWXU

void create_pem_filenames(const char *name, char *pub_key, char *priv_key)
{
    char *anubis = strcat(getenv("HOME"), "/.anubis/");
    strcpy(pub_key, anubis);
    strcpy(priv_key, anubis);
    strcat(strcat(pub_key, name), ".pub");
    strcat(strcat(priv_key, name), ".key");
}

int main(int argc, const char *argv)
{
    const char *uuid = create_uuid();
    char *pem_dir = strcat(getenv("HOME"), "/.anubis");
    struct stat *st;
    char *buf;
    int retval = 1;
    char *pub_key, *priv_key;

    if (stat(pem_dir, st) == -1)
    {
        mkdir(pem_dir, MODE);
    }

    const int len = strlen(pem_dir) + strlen(uuid) + 4;
    priv_key = calloc(len, sizeof(char));
    pub_key = calloc(len, sizeof(char));
    sprintf(priv_key, "%s/%s.%s", pem_dir, uuid, "key");
    sprintf(pub_key, "%s/%s.%s", pem_dir, uuid, "pub");

    FILE *file;
    EC_KEY *ec_key;

    ec_key = EC_KEY_new_by_curve_name(ECCTYPE);
    if (ec_key != NULL)
    {
        if (create_keys(ec_key))
        {
            write_key_to_pem(ec_key, priv_key, pub_key);
            retval = 0;
        }
    }

    if (retval == 1)
    {
        ERR_error_string(ERR_get_error(), buf);
        fprintf(stderr, "%s", buf);
    }

    return retval;
}