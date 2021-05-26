#ifndef FILE_H_
#define FILE_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


void write_file(const char *file, const char *mode, const char *dgst)
{
    FILE *fp;

    fp = fopen(file, mode);

    if(fp == NULL)
    {
        fprintf(stderr, "Error reading %s\n", file);   
        exit(1);             
    }
    
    fprintf(fp, "%s\n", dgst);
    fclose(fp);
}

char *read_file(const char *file, const char *mode)
{
    FILE * fp;
    char * line = NULL;
    char *buff = NULL;
    size_t len = 0;
    size_t read;

    fp = fopen(file, mode);
    
    if(fp == NULL)
    {
        fprintf(stderr, "Error reading %s\n", file);   
        exit(1);             
    }

    while ((read = getline(&line, &len, fp)) != -1)
    {
        buff = line;
    }
    
    fclose(fp);

    return buff;
}

#endif