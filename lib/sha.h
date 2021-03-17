#ifndef SHA_H_
#define SHA_H_

char *read_secret(const char *file);
int get_salt_size();
int get_hash_size();
char *get_salt();
char *sha(const char *secret, const char *salt);

#endif
