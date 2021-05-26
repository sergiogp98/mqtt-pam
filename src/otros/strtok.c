#include <string.h>
#include <stdio.h>
#include <stdlib.h>

int main () {
   char str[80] = "/home/vagrant/.anubis";
   const char s[2] = "/";
   char *token;
   
   /* get the first token */
   token = strtok(str, s);
   
   /* walk through other tokens */
   while( token != NULL ) {
      printf("%s\n", token);
    
      token = strtok(NULL, s);
   }
   printf("%s\n", getenv("HOME"));
   return(0);
}