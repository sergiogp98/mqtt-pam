/*
Doc: https://www.gnu.org/software/libc/manual/html_mono/libc.html#Unpredictable-Bytes
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <crypt.h>
#include <string.h>
#include "../lib/sha256.h"

#define SECRET_PATH "./secret-word.txt"
#define HASH_FUNCTION 512
#define PAYLOAD_SIZE 64
#define SALT_SIZE 20
#define HASH_SIZE 128

char *read_secret(const char *file)
{
    static char secret[PAYLOAD_SIZE];
    FILE *fp;
    fp = fopen(file, "r");
    fscanf(fp, "%s", secret);
    
    return secret;
}

int get_salt_size()
{
    return SALT_SIZE;
}

int get_hash_size()
{
    return HASH_SIZE;
}

char *get_salt()
{
    unsigned char ubytes[SALT_SIZE-4];
    char *salt = malloc(SALT_SIZE);
    const char *const saltchars =
        "./0123456789ABCDEFGHIJKLMNOPQRST"
        "UVWXYZabcdefghijklmnopqrstuvwxyz";
    int i;

    /* Retrieve 16 unpredictable bytes from the operating system. */
    if (getentropy(ubytes, sizeof(ubytes)))
    {
        perror("getentropy");
    }

    /* Use them to fill in the salt string. */
    salt[0] = '$';
    switch (HASH_FUNCTION)
    {
    case 256: /* SHA-256 */
        salt[1] = '5';
        break;
    case 512: /* SHA-512 */
        salt[1] = '6';
        break;
    default:
        perror("Invalid hash function");
        break;
    }
    salt[2] = '$';
    for (i = 0; i < SALT_SIZE-4; i++)
        salt[3 + i] = saltchars[ubytes[i] & 0x3f];
    salt[3 + i] = '\0';
    
    return salt;
}

char *sha(const char *secret, const char *salt)
{
    char *hash = crypt(secret, salt);
    if (!hash || hash[0] == '*')
    {
        perror("crypt");
    }
    
    return hash;
}
