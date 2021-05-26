#ifndef UTILS_H_
#define UTILS_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <regex.h>

#define MAX_USERNAME_LEN 32
#define MAX_HOSTNAME_LEN HOST_NAME_MAX
#define MAX_PATH_LEN 100

void set_id(char buffer[], const int size, const char *id)
{
    memset(buffer, 0, size);
    snprintf(buffer, size-1, "%s_%d", id, getpid());  
}

void set_topic(char buffer[], const int size, const char *src, const char *dst, const char *item)
{
    memset(buffer, 0, size);
    snprintf(buffer, size-1, "%s/%s/%s", src, dst, item);
}

void set_buffer(char buffer[], const int size, const char *dgst)
{
    memset(buffer, 0, size);
    snprintf(buffer, size, "%s", dgst);
}

int check_uuid_regex(const char *file)
{
    const char *exp = "[a-z0-9]*-[a-z0-9]*-[a-z0-9]*-[a-z0-9]*-[a-z0-9]*-[a-z0-9]*.*";
    int found = 0;
    int value;
    regex_t regex;

    value = regcomp(&regex, exp, 0);
    
    if (value == 0)
    {
        value = regexec(&regex, file, 0, NULL, 0);
        if (value == 0)
        {
            found = 1;
        }
    }

    return found;
}

const char *get_extension(const char *filename)
{
    char *ret;
    const char point = '.';

    ret = strrchr(filename, point);

    return ret;
}

int check_extension(const char *filename, const char *ext)
{  
    return strcmp(get_extension(filename), ext) == 0;
}

char *get_filename(char *filename)
{
    char *name;
    const char slash[2] = "/";
    char *token;

    // Get filename of path filename
    token = strtok(filename, slash);
    while (token != NULL)
    {
        token = strtok(NULL, slash);
    }

    // Get name of file without extension
    const char *ext = get_extension(token);
    name = strtok(token, ext);
    
    return name;
}

#endif
