#include <stdio.h>
#include <openssl/sha.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include "../lib/crypt.h"

char* sha512(const char *digest)
{
    static char buffer[SHA512_DIGEST_LENGTH];
    if (digest == NULL)
    {
        fprintf(stderr, "Digest cannot be empty\n");
    }
    else 
    {
        SHA512_CTX sha512;
        unsigned char hash[SHA512_DIGEST_LENGTH];
        
        SHA512_Init(&sha512);
        SHA512_Update(&sha512, digest, strlen(digest));
        SHA512_Final(hash, &sha512);
        
        int i = 0;
        for (i = 0; i < SHA512_DIGEST_LENGTH; i++)
        {
            sprintf(buffer + i, "%02x", hash[i]);
        }
    }
    
    return buffer;
}  

char *get_challenge()
{
    unsigned char ubytes[CHALLENGE_SIZE];
    char *challenge = malloc(CHALLENGE_SIZE);
    const char *const alphanum =
        "./0123456789ABCDEFGHIJKLMNOPQRST"
        "UVWXYZabcdefghijklmnopqrstuvwxyz";
    int i;

    /* Retrieve 16 unpredictable bytes from the operating system. */
    if (getentropy(ubytes, CHALLENGE_SIZE))
    {
        perror("getentropy");
    }

    /* Use them to fill in the salt string. */
    for (i = 0; i < CHALLENGE_SIZE-1; i++)
        challenge[i] = alphanum[ubytes[i] & 0x3f];
    challenge[i] = '\0';
    
    return challenge;
}
