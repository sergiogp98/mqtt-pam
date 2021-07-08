/**
 * Header file with functions related to anubis configuration file 
 */

#ifndef CONF_H_
#define CONF_H_

#include <stdio.h>
#include <stdlib.h>

#define RELAX_ACCESS 0
#define STRICT_ACCESS 1

struct CONF_PARAMS {
    int access_type;   
};

/**
 * Read anubis configuration file and saver parameters
 * @param file anubis configuration file
 * @param params anubis configuration file parameters
 * @return access_type parameter (0:STRICT, 1:RELAX, -1:ERROR)
 */
int read_conf(const char *file, struct CONF_PARAMS *params)
{
    FILE *fd;
    char *line = NULL;
    size_t len = 0;
    size_t bytes_read = 0;
    char key_value[2];
    char *tok;
    int retval = 1;

    fd = fopen(file, "r");
    if (fd == NULL)
    {
        fprintf(stderr, "Error reading %s\n", file);   
        exit(1); 
    }

    while((bytes_read = getline(&line, &len, fd)) != -1)
    {
        if (line[0] != '#')
        {
            tok = strtok(line, " ");
            if (strcmp(tok, "access_type") == 0)
            {
                tok = strtok(NULL, " ");
                tok[strlen(tok)-1] = 0; //remove final "\n"
                if (strcmp(tok, "strict") == 0)
                {
                    params->access_type = 0;
                }
                else if (strcmp(tok, "relax") == 0)
                {
                    params->access_type = 1;
                }
                else
                {
                    fprintf(stderr, "Invalid access_type value: %s\n", tok);
                    params->access_type = -1;
                }
            }
        }
    }

    return params->access_type;
}

#endif