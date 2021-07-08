/**
 * Header file with basic functions which handle processing naming process 
 */

#ifndef UTILS_H_
#define UTILS_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <regex.h>

#define MAX_USERNAME_LEN 32
#define MAX_HOSTNAME_LEN HOST_NAME_MAX
#define MAX_PATH_LEN 128

/**
 * Initialize buffer of specific len with the following expresion: id_pid
 * @param buffer buffer to initialize
 * @param size buffer maximum lenght
 * @param id buffer value
 */
void set_id(char buffer[], const int size, const char *id)
{
    memset(buffer, 0, size);
    snprintf(buffer, size-1, "%s_%d", id, getpid());  
}

/**
 * Initialize topic with the following expression: src/dst/item
 * @param buffer topic array
 * @param size buffer maximum length
 * @param src source topic value
 * @param dst destination topic value
 * @param item item topic value
 */
void set_topic(char buffer[], const int size, const char *src, const char *dst, const char *item)
{
    memset(buffer, 0, size);
    snprintf(buffer, size-1, "%s/%s/%s", src, dst, item);
}

/**
 * Initialize buffer of size length to dgst
 * @param buffer array to initialize
 * @param size buffer maximum length
 * @param dgst message to store in buffer
 */
void set_buffer(char buffer[], const int size, const char *dgst)
{
    memset(buffer, 0, size);
    snprintf(buffer, size, "%s", dgst);
}

#endif
