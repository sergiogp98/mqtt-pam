#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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
