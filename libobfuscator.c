#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/buffer.h>
#include <openssl/crypto.h>

#include "obfuscator.h"
#include "obfuscator_cfg.h"
#include "obfuscator_secrets.h"

#ifdef OBFUSCATOR_USE_ARGON2
#include <argon2.h>
#endif

#define KEY_LEN 32
#define GCM_NONCE_LEN 12
#define GCM_TAG_LEN 16

static int derive_key(const unsigned char *salt, unsigned char key[KEY_LEN]);

int obfuscate(const unsigned char *plaintext, int plaintext_len, char *ciphertext, size_t ciphertext_capacity) {
    if (!plaintext || plaintext_len < 0 || plaintext_len > INT_MAX - 64 || !ciphertext) return -1;
    unsigned char salt[SALT_LEN];
    unsigned char nonce[GCM_NONCE_LEN];
    if (RAND_bytes(salt, SALT_LEN) != 1 || RAND_bytes(nonce, GCM_NONCE_LEN) != 1) {
        fprintf(stderr, "OBFUSCATOR: generazione salt o nonce fallita\n");
        return -1;
    }
    unsigned char key[KEY_LEN];
    if (derive_key(salt, key) != 0) {
        return -1;
    }
    unsigned char *raw_cipher = malloc((size_t)plaintext_len + SALT_LEN + GCM_NONCE_LEN + GCM_TAG_LEN);
    if (!raw_cipher) {
        perror("OBFUSCATOR: allocazione memoria fallita");
        OPENSSL_cleanse(key, KEY_LEN);
        return -1;
    }
    memcpy(raw_cipher, salt, SALT_LEN);
    memcpy(raw_cipher + SALT_LEN, nonce, GCM_NONCE_LEN);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "OBFUSCATOR: creazione contesto cifratura fallita\n");
        OPENSSL_cleanse(key, KEY_LEN);
        free(raw_cipher);
        return -1;
    }
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_NONCE_LEN, NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) {
        fprintf(stderr, "OBFUSCATOR: inizializzazione cifratura fallita\n");
        OPENSSL_cleanse(key, KEY_LEN);
        goto err;
    }
    OPENSSL_cleanse(key, KEY_LEN);
    int len;
    if (EVP_EncryptUpdate(ctx, raw_cipher + SALT_LEN + GCM_NONCE_LEN, &len, plaintext, plaintext_len) != 1) {
        fprintf(stderr, "OBFUSCATOR: cifratura fallita\n");
        goto err;
    }
    int ciphertext_len = len;
    if (EVP_EncryptFinal_ex(ctx, raw_cipher + SALT_LEN + GCM_NONCE_LEN + len, &len) != 1) {
        fprintf(stderr, "OBFUSCATOR: finalizzazione cifratura fallita\n");
        goto err;
    }
    ciphertext_len += len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, raw_cipher + SALT_LEN + GCM_NONCE_LEN + ciphertext_len) != 1) {
        fprintf(stderr, "OBFUSCATOR: ottenimento tag GCM fallito\n");
        goto err;
    }
    EVP_CIPHER_CTX_free(ctx);
    int authenticated_len = SALT_LEN + GCM_NONCE_LEN + ciphertext_len + GCM_TAG_LEN;
    BIO *bio_mem = BIO_new(BIO_s_mem());
    BIO *bio_b64 = BIO_new(BIO_f_base64());
    if (!bio_mem || !bio_b64) {
        fprintf(stderr, "OBFUSCATOR: creazione BIO fallita\n");
        BIO_free(bio_mem);
        BIO_free(bio_b64);
        free(raw_cipher);
        return -1;
    }
    BIO_set_flags(bio_b64, BIO_FLAGS_BASE64_NO_NL);
    BIO *bio_chain = BIO_push(bio_b64, bio_mem);
    if (!bio_chain || BIO_write(bio_chain, raw_cipher, authenticated_len) != authenticated_len || BIO_flush(bio_chain) != 1) {
        fprintf(stderr, "OBFUSCATOR: scrittura su BIO fallita\n");
        BIO_free_all(bio_chain ? bio_chain : bio_b64);
        free(raw_cipher);
        return -1;
    }
    BUF_MEM *buffer_ptr;
    if (BIO_get_mem_ptr(bio_mem, &buffer_ptr) != 1 || buffer_ptr->length > INT_MAX) {
        fprintf(stderr, "OBFUSCATOR: ottenimento puntatore memoria BIO fallito\n");
        BIO_free_all(bio_chain);
        free(raw_cipher);
        return -1;
    }
    int final_len = (int)buffer_ptr->length;
    if ((size_t)final_len >= ciphertext_capacity) {
        fprintf(stderr, "OBFUSCATOR: buffer di output insufficiente\n");
        BIO_free_all(bio_chain);
        free(raw_cipher);
        return -1;
    }
    memcpy(ciphertext, buffer_ptr->data, final_len);
    ciphertext[final_len] = '\0';
    BIO_free_all(bio_chain);
    free(raw_cipher);
    return final_len;
err:
    EVP_CIPHER_CTX_free(ctx);
    free(raw_cipher);
    return -1;
}

int deobfuscate(const char *ciphertext, int ciphertext_len, unsigned char *plaintext, size_t plaintext_capacity) {
    if (!ciphertext || ciphertext_len <= 0 || !plaintext) return -1;
    unsigned char *raw_cipher = malloc(ciphertext_len);
    if (!raw_cipher) {
        perror("OBFUSCATOR: allocazione memoria fallita");
        return -1;
    }
    BIO *bio_b64 = BIO_new(BIO_f_base64());
    BIO *bio_mem = BIO_new_mem_buf(ciphertext, ciphertext_len);
    if (!bio_b64 || !bio_mem) {
        fprintf(stderr, "OBFUSCATOR: creazione BIO fallita\n");
        BIO_free(bio_b64);
        BIO_free(bio_mem);
        free(raw_cipher);
        return -1;
    }
    BIO_set_flags(bio_b64, BIO_FLAGS_BASE64_NO_NL);
    BIO *bio_chain = BIO_push(bio_b64, bio_mem);
    int total_raw_len = BIO_read(bio_chain, raw_cipher, ciphertext_len);
    BIO_free_all(bio_chain);
    if (total_raw_len < SALT_LEN + GCM_NONCE_LEN + GCM_TAG_LEN) {
        fprintf(stderr, "OBFUSCATOR: formato cifrato non valido\n");
        free(raw_cipher);
        return -1;
    }
    int raw_ciphertext_len = total_raw_len - SALT_LEN - GCM_NONCE_LEN - GCM_TAG_LEN;
    unsigned char salt[SALT_LEN];
    memcpy(salt, raw_cipher, SALT_LEN);
    unsigned char key[KEY_LEN];
    if (derive_key(salt, key) != 0) {
        free(raw_cipher);
        return -1;
    }
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "OBFUSCATOR: creazione contesto decrittazione fallita\n");
        OPENSSL_cleanse(key, KEY_LEN);
        free(raw_cipher);
        return -1;
    }
    unsigned char *decrypted = NULL;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_NONCE_LEN, NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, key, raw_cipher + SALT_LEN) != 1) {
        fprintf(stderr, "OBFUSCATOR: inizializzazione decrittazione fallita\n");
        OPENSSL_cleanse(key, KEY_LEN);
        goto err;
    }
    OPENSSL_cleanse(key, KEY_LEN);
    decrypted = malloc((size_t)raw_ciphertext_len + 1);
    if (!decrypted) {
        fprintf(stderr, "OBFUSCATOR: allocazione memoria per decrittazione fallita\n");
        EVP_CIPHER_CTX_free(ctx);
        free(raw_cipher);
        return -1;
    }
    int len;
    if (EVP_DecryptUpdate(ctx, decrypted, &len, raw_cipher + SALT_LEN + GCM_NONCE_LEN, raw_ciphertext_len) != 1) {
        fprintf(stderr, "OBFUSCATOR: decrittazione fallita\n");
        goto err;
    }
    int plaintext_len = len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN, raw_cipher + total_raw_len - GCM_TAG_LEN) != 1 ||
        EVP_DecryptFinal_ex(ctx, decrypted + len, &len) != 1) {
        fprintf(stderr, "OBFUSCATOR: autenticazione del ciphertext non riuscita\n");
        goto err;
    }
    plaintext_len += len;
    if ((size_t)plaintext_len >= plaintext_capacity) {
        fprintf(stderr, "OBFUSCATOR: buffer di output insufficiente\n");
        EVP_CIPHER_CTX_free(ctx);
        OPENSSL_cleanse(decrypted, (size_t)raw_ciphertext_len + 1);
        free(decrypted);
        free(raw_cipher);
        return -1;
    }
    memcpy(plaintext, decrypted, plaintext_len);
    plaintext[plaintext_len] = '\0';
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(decrypted, (size_t)raw_ciphertext_len + 1);
    free(decrypted);
    free(raw_cipher);
    return plaintext_len;
err:
    EVP_CIPHER_CTX_free(ctx);
    if (decrypted) OPENSSL_cleanse(decrypted, (size_t)raw_ciphertext_len + 1);
    free(decrypted);
    free(raw_cipher);
    return -1;
}

int libobfuscator_main(int argc, char *argv[]) {
    int decrypt = 0;
    if (argc > 2 || (argc == 2 && (strcmp(argv[1], "-d") != 0 && strcmp(argv[1], "-k") != 0))) {
        fprintf(stderr, "Usage: %s [-d] < stdin > stdout\n", argv[0]);
        fprintf(stderr, "Usage: %s -k\n", argv[0]);
        return 2;
    }
    if (argc ==2 && strcmp(argv[1], "-k") == 0) {
        unsigned char key[KEY_LEN];
        if (RAND_bytes(key, KEY_LEN) != 1) {
            fprintf(stderr, "failed to generate key\n");
            OPENSSL_cleanse(key, sizeof(key));
            return 1;
        }
        for (size_t i = 0; i < sizeof(key); i++) {
            if (printf("%02x", (unsigned int)key[i]) < 0) {
                perror("printf()");
                OPENSSL_cleanse(key, sizeof(key));
                return 1;
            }
        }
        OPENSSL_cleanse(key, sizeof(key));
        if (fputc('\n', stdout) == EOF || fflush(stdout) == EOF) {
            perror("stdout");
            return 1;
        }
        return 0;
    } else if (argc == 2 && strcmp(argv[1], "-d") == 0) {
        decrypt = 1;
    }
    char *line = NULL;
    size_t line_capacity = 0;
    ssize_t input_length;
    int result = 0;
    while ((input_length = getline(&line, &line_capacity, stdin)) != -1) {
        size_t line_length = (size_t)input_length;
        if (line_length > 0 && line[line_length - 1] == '\n') {
            line[--line_length] = '\0';
        }
        if (line_length > 0 && line[line_length - 1] == '\r') {
            line[--line_length] = '\0';
        }
        if (decrypt) {
            unsigned char *plaintext = malloc(line_length + 1);
            if (!plaintext) {
                perror("malloc()");
                result = 1;
                break;
            }
            int plaintext_length = deobfuscate(line, (int)line_length, plaintext, line_length + 1);
            if (plaintext_length < 0) {
                free(plaintext);
                result = 1;
                break;
            }
            if (fwrite(plaintext, 1, (size_t)plaintext_length, stdout) != (size_t)plaintext_length || fputc('\n', stdout) == EOF) {
                perror("fwrite()/fputc()");
                OPENSSL_cleanse(plaintext, line_length + 1);
                free(plaintext);
                result = 1;
                break;
            }
            OPENSSL_cleanse(plaintext, line_length + 1);
            free(plaintext);
        } else {
            size_t raw_capacity = line_length + 64; // SALT_LEN + GCM_NONCE_LEN + GCM_TAG_LEN (16 + 12 + 16 = 48, rounded up for safety)
            size_t encoded_capacity = ((raw_capacity + 2) / 3) * 4 + 1;
            char *encoded = malloc(encoded_capacity);
            if (!encoded) {
                perror("malloc()");
                result = 1;
                break;
            }
            int encoded_length = obfuscate((const unsigned char *)line, (int)line_length, encoded, encoded_capacity);
            if (encoded_length < 0) {
                free(encoded);
                result = 1;
                break;
            }
            if (fwrite(encoded, 1, (size_t)encoded_length, stdout) != (size_t)encoded_length || fputc('\n', stdout) == EOF) {
                perror("fwrite()/fputc()");
                free(encoded);
                result = 1;
                break;
            }
            free(encoded);
        }
    }
    if (ferror(stdin)) {
        perror("ferror()");
        result = 1;
    }
    if (fflush(stdout) == EOF) {
        perror("fflush()");
        result = 1;
    }
    if (line) {
        OPENSSL_cleanse(line, line_capacity);
        free(line);
    }
    return result;
}

static int append_bytes(unsigned char **passphrase, size_t *passphrase_length, size_t *passphrase_capacity, const void *data, size_t length) {
    if (length > SIZE_MAX - *passphrase_length) {
        fprintf(stderr, "OBFUSCATOR: contenuto della passphrase troppo lungo\n");
        return 0;
    }
    if (length == 0) return 1;
    size_t required = *passphrase_length + length;
    if (required > *passphrase_capacity) {
        size_t new_capacity = *passphrase_capacity ? *passphrase_capacity : 128;
        while (new_capacity < required) {
            if (new_capacity > SIZE_MAX / 2) {
                new_capacity = required;
                break;
            }
            new_capacity *= 2;
        }
        unsigned char *new_passphrase = malloc(new_capacity);
        if (!new_passphrase) {
            perror("OBFUSCATOR: allocazione della passphrase fallita");
            return 0;
        }
        if (*passphrase_length) {
            memcpy(new_passphrase, *passphrase, *passphrase_length);
        }
        if (*passphrase) {
            OPENSSL_cleanse(*passphrase, *passphrase_capacity);
            free(*passphrase);
        }
        *passphrase = new_passphrase;
        *passphrase_capacity = new_capacity;
    }
    memcpy(*passphrase + *passphrase_length, data, length);
    *passphrase_length = required;
    return 1;
}

static int append_str(unsigned char **passphrase, size_t *passphrase_length, size_t *passphrase_capacity, const char *str) {
    size_t length = strlen(str);
    return append_bytes(passphrase, passphrase_length, passphrase_capacity, str, length);
}

static int append_path_text(char **output, size_t *length, size_t *capacity, const char *text, size_t text_length) {
    if (text_length > SIZE_MAX - *length - 1) {
        fprintf(stderr, "OBFUSCATOR: percorso file troppo lungo\n");
        return 0;
    }
    size_t required = *length + text_length + 1;
    if (required > *capacity) {
        size_t new_capacity = *capacity ? *capacity : 32;
        while (new_capacity < required) {
            if (new_capacity > SIZE_MAX / 2) {
                new_capacity = required;
                break;
            }
            new_capacity *= 2;
        }
        char *new_output = realloc(*output, new_capacity);
        if (!new_output) {
            perror("OBFUSCATOR: allocazione del percorso fallita");
            return 0;
        }
        *output = new_output;
        *capacity = new_capacity;
    }
    memcpy(*output + *length, text, text_length);
    *length += text_length;
    (*output)[*length] = '\0';
    return 1;
}

static int is_env_name_start(char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_';
}

static int is_env_name_char(char c) {
    return is_env_name_start(c) || (c >= '0' && c <= '9');
}

static int append_environment_variable(char **output, size_t *length, size_t *capacity, const char *name_start, size_t name_length) {
    char *name = strndup(name_start, name_length);
    if (!name) {
        perror("OBFUSCATOR: allocazione del nome variabile fallita");
        return 0;
    }
    const char *value = getenv(name);
    if (!value) {
        fprintf(stderr, "OBFUSCATOR: variabile d'ambiente non definita\n");
        free(name);
        return 0;
    }
    int result = append_path_text(output, length, capacity, value, strnlen(value, SIZE_MAX - *length));
    free(name);
    return result;
}

static char *expand_environment_variables(const char *path) {
    char *expanded_path = NULL;
    size_t length = 0;
    size_t capacity = 0;
    const char *cursor = path;
    while (*cursor) {
        if (*cursor != '$') {
            if (!append_path_text(&expanded_path, &length, &capacity, cursor, 1)) {
                free(expanded_path);
                return NULL;
            }
            cursor++;
            continue;
        }
        const char *name_start;
        size_t name_length;
        if (cursor[1] == '{') {
            name_start = cursor + 2;
            const char *name_end = name_start;
            while (is_env_name_char(*name_end)) name_end++;
            if (name_end == name_start || *name_end != '}') {
                fprintf(stderr, "OBFUSCATOR: riferimento a variabile d'ambiente non valido nel percorso\n");
                free(expanded_path);
                return NULL;
            }
            name_length = (size_t)(name_end - name_start);
            cursor = name_end + 1;
        } else if (is_env_name_start(cursor[1])) {
            name_start = cursor + 1;
            const char *name_end = name_start;
            while (is_env_name_char(*name_end)) name_end++;
            name_length = (size_t)(name_end - name_start);
            cursor = name_end;
        } else {
            if (!append_path_text(&expanded_path, &length, &capacity, cursor, 1)) {
                free(expanded_path);
                return NULL;
            }
            cursor++;
            continue;
        }
        if (!append_environment_variable(&expanded_path, &length, &capacity, name_start, name_length)) {
            free(expanded_path);
            return NULL;
        }
    }
    if (!expanded_path) {
        expanded_path = malloc(1);
        if (!expanded_path) {
            perror("OBFUSCATOR: allocazione del percorso fallita");
            return NULL;
        }
        expanded_path[0] = '\0';
    }
    return expanded_path;
}

static int append_expanded_file(unsigned char **passphrase, size_t *passphrase_length, size_t *passphrase_capacity, const char *path) {
    unsigned char buffer[128] = {0};
    if (!*path) {
        fprintf(stderr, "OBFUSCATOR: percorso file vuoto\n");
        OPENSSL_cleanse(buffer, sizeof(buffer));
        return 0;
    }
    FILE *file = fopen(path, "rb");
    if (!file) {
        perror("OBFUSCATOR: apertura del file fallita");
        OPENSSL_cleanse(buffer, sizeof(buffer));
        return 0;
    }
    size_t length;
    while ((length = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        if (!append_bytes(passphrase, passphrase_length, passphrase_capacity, buffer, length)) {
            fclose(file);
            OPENSSL_cleanse(buffer, sizeof(buffer));
            return 0;
        }
    }
    if (ferror(file)) {
        perror("OBFUSCATOR: lettura del file fallita");
        fclose(file);
        OPENSSL_cleanse(buffer, sizeof(buffer));
        return 0;
    }
    fclose(file);
    OPENSSL_cleanse(buffer, sizeof(buffer));
    return 1;
}

static int append_file(unsigned char **passphrase, size_t *passphrase_length, size_t *passphrase_capacity, const char *path) {
    if (!*path) {
        fprintf(stderr, "OBFUSCATOR: percorso file vuoto\n");
        return 0;
    }
    char *expanded_path = expand_environment_variables(path);
    if (!expanded_path) return 0;
    int result = append_expanded_file(passphrase, passphrase_length, passphrase_capacity, expanded_path);
    free(expanded_path);
    return result;
}

static int append_credential(unsigned char **passphrase, size_t *passphrase_length, size_t *passphrase_capacity, const char *key) {
    size_t key_limit = OBFUSCATOR_SECRETS_MAX_LEN > 5 ? OBFUSCATOR_SECRETS_MAX_LEN - 5 : 0;
    size_t key_length = strnlen(key, key_limit);
    if (key_length == 0 || key_length == key_limit ||
        strchr(key, '/') || (key_length == 1 && key[0] == '.')) {
        fprintf(stderr, "OBFUSCATOR: identificatore credenziale non valido\n");
        return 0;
    }
#if OBFUSCATOR_SECRETS_MAX_LEN >= 8
    if (key_length == 2 && key[0] == '.' && key[1] == '.') {
        fprintf(stderr, "OBFUSCATOR: identificatore credenziale non valido\n");
        return 0;
    }
#endif
    const char *directory = getenv("CREDENTIALS_DIRECTORY");
    if (!directory || !*directory) {
        fprintf(stderr, "OBFUSCATOR: CREDENTIALS_DIRECTORY non definita\n");
        return 0;
    }
    size_t directory_length = strnlen(directory, PATH_MAX);
    if (directory_length == PATH_MAX) {
        fprintf(stderr, "OBFUSCATOR: percorso credenziale troppo lungo\n");
        return 0;
    }
    size_t separator_length = directory[directory_length - 1] == '/' ? 0 : 1;
    if (key_length > SIZE_MAX - directory_length ||
        directory_length + key_length > SIZE_MAX - separator_length - 1) {
        fprintf(stderr, "OBFUSCATOR: percorso credenziale troppo lungo\n");
        return 0;
    }
    size_t path_length = directory_length + separator_length + key_length;
    if (path_length >= PATH_MAX) {
        fprintf(stderr, "OBFUSCATOR: percorso credenziale troppo lungo\n");
        return 0;
    }
    char *path = malloc(path_length + 1);
    if (!path) {
        perror("OBFUSCATOR: allocazione del percorso credenziale fallita");
        return 0;
    }
    memcpy(path, directory, directory_length);
    size_t offset = directory_length;
    if (separator_length) path[offset++] = '/';
    memcpy(path + offset, key, key_length);
    path[path_length] = '\0';
    int result = append_expanded_file(passphrase, passphrase_length, passphrase_capacity, path);
    free(path);
    return result;
}

static int get_master_key(unsigned char master_key[KEY_LEN]) {
    static const unsigned char master_key_salt[] = "obfuscator master key v1";
    unsigned char *passphrase = NULL;
    size_t passphrase_length = 0;
    size_t passphrase_capacity = 0;
    int status = -1;
    int kdf_result;
    char entry[OBFUSCATOR_SECRETS_MAX_LEN > 6 ? OBFUSCATOR_SECRETS_MAX_LEN : 6] = {0};
#ifdef OBFUSCATOR_CACHE_MASTER_KEY
    bool cache_locked = false;
    static pthread_mutex_t cache_mutex = PTHREAD_MUTEX_INITIALIZER;
    static unsigned char cached_master_key[KEY_LEN] = {0};
    static bool is_cached = false;
    if (pthread_mutex_lock(&cache_mutex) != 0) {
        perror("OBFUSCATOR: lock del mutex fallito");
        goto cleanup;
    }
    cache_locked = true;
    if (is_cached) {
        memcpy(master_key, cached_master_key, KEY_LEN);
        status = 0;
        goto cleanup;
    }
#endif
    for (size_t i = 0; obfuscator_secrets_string(i, entry); i++) {
        int ok;
        if (strncmp(entry, "file:", 5) == 0) {
            ok = append_file(&passphrase, &passphrase_length, &passphrase_capacity, entry + 5);
        } else if (strncmp(entry, "cred:", 5) == 0) {
            ok = append_credential(&passphrase, &passphrase_length, &passphrase_capacity, entry + 5);
        } else if (strncmp(entry, "str:", 4) == 0) {
            ok = append_str(&passphrase, &passphrase_length, &passphrase_capacity, entry + 4);
        } else {
            fprintf(stderr, "OBFUSCATOR: direttiva non riconosciuta\n");
            ok = 0;
        }
        if (!ok) {
            goto cleanup;
        }
    }
#ifdef OBFUSCATOR_USE_ARGON2
    kdf_result = argon2id_hash_raw(ARGON2_TIME_COST, ARGON2_MEMORY_COST_KIB, ARGON2_PARALLELISM, passphrase, passphrase_length, master_key_salt, sizeof(master_key_salt) - 1, master_key, KEY_LEN);
    if (kdf_result != ARGON2_OK) {
        fprintf(stderr, "OBFUSCATOR: Argon2id: %s\n", argon2_error_message(kdf_result));
        goto cleanup;
    }
#else
    if (passphrase_length > INT_MAX) {
        fprintf(stderr, "OBFUSCATOR: passphrase troppo lunga per PBKDF2\n");
        goto cleanup;
    }
    kdf_result = PKCS5_PBKDF2_HMAC((const char *)passphrase, (int)passphrase_length, master_key_salt, sizeof(master_key_salt) - 1, PBKDF2_ITERATIONS, EVP_sha256(), KEY_LEN, master_key);
    if (kdf_result != 1) {
        fprintf(stderr, "OBFUSCATOR: PBKDF2 fallita\n");
        goto cleanup;
    }
#endif
#ifdef OBFUSCATOR_CACHE_MASTER_KEY
    memcpy(cached_master_key, master_key, KEY_LEN);
    is_cached = true;
#endif
    status = 0;
cleanup:
    if (status != 0) OPENSSL_cleanse(master_key, KEY_LEN);
    if (passphrase) {
        OPENSSL_cleanse(passphrase, passphrase_capacity);
        free(passphrase);
    }
    OPENSSL_cleanse(entry, sizeof(entry));
#ifdef OBFUSCATOR_CACHE_MASTER_KEY
    if (cache_locked) pthread_mutex_unlock(&cache_mutex);
#endif
    return status;
}

static int derive_key(const unsigned char *salt, unsigned char key[KEY_LEN]) {
    static const unsigned char info[] = "obfuscator AES-256-GCM key";
    unsigned char master_key[KEY_LEN];
    if (get_master_key(master_key) != 0) {
        return -1;
    }
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!ctx) {
        fprintf(stderr, "OBFUSCATOR: creazione contesto HKDF fallita\n");
        OPENSSL_cleanse(master_key, sizeof(master_key));
        OPENSSL_cleanse(key, KEY_LEN);
        return -1;
    }
    size_t key_length = KEY_LEN;
    int result = EVP_PKEY_derive_init(ctx) > 0 &&
                 EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) > 0 &&
                 EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt, SALT_LEN) > 0 &&
                 EVP_PKEY_CTX_set1_hkdf_key(ctx, master_key, KEY_LEN) > 0 &&
                 EVP_PKEY_CTX_add1_hkdf_info(ctx, info, sizeof(info) - 1) > 0 &&
                 EVP_PKEY_derive(ctx, key, &key_length) > 0 &&
                 key_length == KEY_LEN;
    EVP_PKEY_CTX_free(ctx);
    OPENSSL_cleanse(master_key, sizeof(master_key));
    if (!result) {
        fprintf(stderr, "OBFUSCATOR: derivazione HKDF-SHA256 fallita\n");
        OPENSSL_cleanse(key, KEY_LEN);
        return -1;
    }
    return 0;
}
