/**
 * Header file with functions related to UUID processing
 */

#ifndef UUID_H_
#define UUID_H_

/* For malloc() */
#include <stdlib.h>
/* For puts()/printf() */
#include <stdio.h>
/* For uuid_generate() and uuid_unparse() */
#include <uuid/uuid.h>

#define UUID_CSV "/etc/anubis/uuid.csv"
#define LINE_LEN 128

/**
 * Struct referencing CSV anubis file values (user,uuid)
 */
struct USER_UUID
{
    char *user;
    char *uuid;
};

/* Uncomment to always generate capital UUIDs. */
//#define capitaluuid true

/* Uncomment to always generate lower-case UUIDs. */
//#define lowercaseuuid true

/*
 * Don't uncomment either if you don't care (the case of the letters
 * in the 'unparsed' UUID will depend on your system's locale).
 */


/**
 * Create random UUID using defined parameters
 * @return UUID value
 */
char *create_uuid() {
    uuid_t binuuid;
    /*
     * Generate a UUID. We're not done yet, though,
     * for the UUID generated is in binary format 
     * (hence the variable name). We must 'unparse' 
     * binuuid to get a usable 36-character string.
     */
    uuid_generate_random(binuuid);

    /*
     * uuid_unparse() doesn't allocate memory for itself, so do that with
     * malloc(). 37 is the length of a UUID (36 characters), plus '\0'.
     */
    char *uuid = malloc(UUID_STR_LEN);

#ifdef capitaluuid
    /* Produces a UUID string at uuid consisting of capital letters. */
    uuid_unparse_upper(binuuid, uuid);
#elif lowercaseuuid
    /* Produces a UUID string at uuid consisting of lower-case letters. */
    uuid_unparse_lower(binuuid, uuid);
#else
    /*
     * Produces a UUID string at uuid consisting of letters
     * whose case depends on the system's locale.
     */
    uuid_unparse(binuuid, uuid);
#endif

    // Equivalent of printf("%s\n", uuid); - just my personal preference
    //puts(uuid);

    return uuid;
}

/**
 * Check whether UUID string has the appropiate name
 * @param uuid UUID value
 * @return success checking uuid has the apropiate value
 */
int check_uuid_regex(const char *uuid)
{
    const char *exp = "[a-z0-9]*-[a-z0-9]*-[a-z0-9]*-[a-z0-9]*-[a-z0-9]*";
    int match = 0;
    regex_t regex;
        
    if (regcomp(&regex, exp, 0) == 0)
    {
        if (regexec(&regex, uuid, 0, NULL, 0) == 0)
        {
            match = 1;
        }
    }

    return match;
}

/**
 * Get UUID value associate to username in filename
 * @param filename path to CSV file with key pairs username,uuid
 * @param username username to check UUID to
 * @param data struct which save key pair user,uuid (if username has UUID assigned)
 * @return found UUID of username
 */
int get_uuid(char *filename, const char *username, struct USER_UUID *data)
{
    FILE *file;
    int i;
    char line[LINE_LEN];
    const char delim[2] = ",";
    int found = 0;
    char *tok;

    // Open CSV file
    file = fopen(filename, "r");
    if (file == NULL)
    {
        perror("Error opening file");
        exit(1);
    }

    while (fgets(line, LINE_LEN, file) != NULL && !found)
    {
        // Get username
        tok = strtok(line, delim);

        // Compare user
        if (strcmp(tok, username) == 0)
        {
            data->user = tok; // Save username

            // Get UUID
            tok = strtok(NULL, delim);
            tok[strlen(tok)-1] = 0; //remove final "\n"
            if (check_uuid_regex(tok))
            {
                data->uuid = tok; // Save UUID
                found = 1;
            }
        }        
    }

    fclose(file);

    return found;
}

#endif 