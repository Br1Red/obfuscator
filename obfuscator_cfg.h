#ifndef OBFUSCATOR_CFG_H
#define OBFUSCATOR_CFG_H

// If OBFUSCATOR_CACHE_MASTER_KEY is defined, the derived master key is cached in memory.
#define OBFUSCATOR_CACHE_MASTER_KEY

// If OBFUSCATOR_USE_ARGON2 is defined, Argon2id will be used for key derivation.
// Otherwise, PBKDF2-HMAC-SHA256 will be used.
#define OBFUSCATOR_USE_ARGON2

#ifdef OBFUSCATOR_USE_ARGON2
// Argon2id parameters for key derivation.
#define ARGON2_TIME_COST 3
#define ARGON2_MEMORY_COST_KIB 65536
#define ARGON2_PARALLELISM 1
#define SALT_LEN 16
#else
// PBKDF2-HMAC-SHA256 parameters for key derivation.
#define PBKDF2_ITERATIONS 1000000
#define SALT_LEN 8
#endif

#endif