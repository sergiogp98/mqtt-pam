#ifndef UTILS_H_
#define UTILS_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <regex.h>

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
    snprintf(buffer, size-1, "%s", dgst);
}

int check_uuid_regex(const char *file)
{
    const char *exp = "[a-z0-9]*-[a-z0-9]*-[a-z0-9]*-[a-z0-9]*-[a-z0-9]*-[a-z0-9]*.pub"
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

#endif
