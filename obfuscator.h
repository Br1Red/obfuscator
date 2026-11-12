#ifndef __OBFUSCATOR_H__
#define __OBFUSCATOR_H__

#include <stddef.h>

int obfuscate(const unsigned char *plaintext, int plaintext_len, char *ciphertext, size_t ciphertext_capacity);
int deobfuscate(const char *ciphertext, int ciphertext_len, unsigned char *plaintext, size_t plaintext_capacity);

#endif