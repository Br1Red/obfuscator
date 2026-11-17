#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <inttypes.h>
#include <ctype.h>
#include <openssl/rand.h>

static size_t prepare_line(char *line, size_t line_length) {
    size_t len = strnlen(line, line_length);
    while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
        line[--len] = '\0';
    }
    if (line[0] == '#' || (line[0] == '/' && line[1] == '/')) {
        return 0;
    }
    for (size_t i = 0; i < len; i++) {
        if (!isspace((unsigned char)line[i])) {
            return len;
        }
    }
    return 0;
}

static void write_guard(FILE *out, const char *directive, const char *prefix) {
    fprintf(out, "#%s __", directive);
    for (const unsigned char *c = (const unsigned char *)prefix; *c; c++) {
        fputc(isalnum(*c) || *c == '_' ? *c : '_', out);
    }
    fprintf(out, "_H__\n");
}

void write_obfuscated_string(FILE *out, const char *str, size_t len, size_t string_index, const uint32_t key[4]) {
    fprintf(out, "        {");
    for (size_t i = 0; i <= len; i++) {
        uint8_t c = (uint8_t)str[i];
        uint32_t k = key[(i + string_index) % 4];
        uint8_t enc = (uint8_t)(c + (uint8_t)k);
        enc ^= (uint8_t)(k >> 8);
        enc = (uint8_t)(enc - (uint8_t)(k >> 16));
        enc ^= (uint8_t)(k >> 24);
        fprintf(out, "0x%02X", enc);
        if (i < len) {
            fprintf(out, ", ");
        }
    }
    fprintf(out, "}");
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <input_file>\n", argv[0]);
        return 1;
    }
    char *output_prefix = NULL;
    char *output_prefix_lowercase = NULL;
    char *buffer = NULL;
    size_t buffer_capacity = 0;
    FILE *in = NULL;
    FILE *out = NULL;
    const char *input_filename = argv[1];
    const char *output_basename = strrchr(input_filename, '/');
    output_basename = output_basename ? output_basename + 1 : input_filename;
    const char *suffix = strrchr(output_basename, '.');
    size_t output_prefix_len = suffix && suffix != output_basename
                                   ? (size_t)(suffix - output_basename)
                                   : strnlen(output_basename, INT_MAX);
    output_prefix = malloc(output_prefix_len + 1);
    if (!output_prefix) {
        perror("malloc()");
        goto err;
    }
    output_prefix_lowercase = malloc(output_prefix_len + 1);
    if (!output_prefix_lowercase) {
        perror("malloc()");
        goto err;
    }
    for (size_t i = 0; i < output_prefix_len; i++) {
        output_prefix[i] = (char)toupper((unsigned char)output_basename[i]);
        output_prefix_lowercase[i] = (char)tolower((unsigned char)output_basename[i]);
    }
    output_prefix[output_prefix_len] = '\0';
    output_prefix_lowercase[output_prefix_len] = '\0';
    in = fopen(input_filename, "r");
    if (!in) {
        perror("fopen(input)");
        goto err;
    }
    int num_lines = 0;
    size_t max_len = 0;
    for (;;) {
        ssize_t line_length = getline(&buffer, &buffer_capacity, in);
        if (line_length == -1) {
            int read_errno = errno;
            if (ferror(in)) {
                errno = read_errno;
                perror("getline()");
                goto err;
            }
            break;
        }
        size_t len = prepare_line(buffer, (size_t)line_length);
        if (len == 0) continue;
        if (len + 1 > max_len) {
            max_len = len + 1;
        }
        num_lines++;
    }
    if (fseek(in, 0, SEEK_SET) != 0) {
        perror("fseek()");
        goto err;
    }
    if (max_len == 0) {
        fprintf(stderr,"No valid lines found in input file\n");
        goto err;
    }
    char output_filename[1024];
    snprintf(output_filename, sizeof(output_filename), "%s.h", output_prefix_lowercase);
    out = fopen(output_filename, "w");
    if (!out) {
        perror("fopen(output)");
        goto err;
    }
    uint32_t key[4];
    if (RAND_bytes((unsigned char *)key, sizeof(key)) != 1) {
        fprintf(stderr, "RAND_bytes() failed\n");
        goto err;
    }
    write_guard(out, "ifndef", output_prefix);
    write_guard(out, "define", output_prefix);
    fputc('\n', out);
    fprintf(out, "// Auto-generated header for obfuscated %s strings\n", input_filename);
    fprintf(out, "// Do not edit manually\n\n");
    fprintf(out, "#include <stdint.h>\n");
    fprintf(out, "#include <stddef.h>\n\n");
    fprintf(out, "#define %s_NUM_STRINGS %d\n", output_prefix, num_lines);
    fprintf(out, "#define %s_MAX_LEN %zu\n\n", output_prefix, max_len);
    fprintf(out, "static inline int %s_string(int number, char buffer[%zu]) {\n", output_prefix_lowercase, max_len);
    fprintf(out, "    const uint32_t key[4] = {UINT32_C(0x%08" PRIX32 "), UINT32_C(0x%08" PRIX32 "), UINT32_C(0x%08" PRIX32 "), UINT32_C(0x%08" PRIX32 ")};\n", key[0], key[1], key[2], key[3]);
    fprintf(out, "    const uint8_t strings[%d][%zu] = {\n", num_lines, max_len);
    int i = 0;
    for (;;) {
        ssize_t line_length = getline(&buffer, &buffer_capacity, in);
        if (line_length == -1) {
            int read_errno = errno;
            if (ferror(in)) {
                errno = read_errno;
                perror("getline()");
                goto err;
            }
            break;
        }
        size_t len = prepare_line(buffer, (size_t)line_length);
        if (len == 0) continue;
        write_obfuscated_string(out, buffer, len, (size_t)i, key);
        if (i < num_lines - 1) {
            fputc(',', out);
        }
        fputc('\n', out);
        i++;
    }
    fprintf(out, "    };\n");
    fprintf(out, "    if (number < 0 || number >= %d) {\n", num_lines);
    fprintf(out, "        buffer[0]='\\0';\n");
    fprintf(out, "    } else {\n");
    fprintf(out, "        for (size_t i = 0; i < %zu; i++) {\n", max_len);
    fprintf(out, "            uint32_t k = key[(i + (size_t)number) %% 4];\n");
    fprintf(out, "            uint8_t enc = strings[number][i];\n");
    fprintf(out, "            enc ^= (uint8_t)(k >> 24);\n");
    fprintf(out, "            enc = (uint8_t)(enc + (uint8_t)(k >> 16));\n");
    fprintf(out, "            enc ^= (uint8_t)(k >> 8);\n");
    fprintf(out, "            char dec = (char)(enc - (uint8_t)k);\n");
    fprintf(out, "            buffer[i] = dec;\n");
    fprintf(out, "            if (dec == '\\0') break;\n");
    fprintf(out, "        }\n");
    fprintf(out, "    }\n");
    fprintf(out, "    return !!buffer[0];\n");
    fprintf(out, "}\n\n");
    fprintf(out, "#endif\n");
    if (fclose(in) != 0) {
        perror("fclose(input)");
        in = NULL;
        goto err;
    }
    in = NULL;
    if (fclose(out) != 0) {
        perror("fclose(output)");
        out = NULL;
        goto err;
    }
    out = NULL;
    printf("Header '%s' successfully generated\n", output_filename);
    free(output_prefix);
    free(output_prefix_lowercase);
    free(buffer);
    return 0;
err:
    free(buffer);
    if (in) fclose(in);
    if (out) fclose(out);
    free(output_prefix);
    free(output_prefix_lowercase);
    return 1;
}
