# Obfuscator

Obfuscator is a small C library and command-line program for encrypting and
decrypting text with AES-256-GCM. It also includes a helper that generates a C
header containing reversibly obfuscated strings.

## Requirements

- Linux on x86-64 (the command-line executable uses a Linux x86-64 startup
  routine)
- GNU Make and a C compiler
- OpenSSL development files and `libcrypto`
- Argon2 development files and `libargon2`

The feature and passphrase-cache defines are in `obfuscator_cfg.h`. By
default, `OBFUSCATOR_USE_ARGON2` enables Argon2id key derivation and
`OBFUSCATOR_CACHE_PASSPHRASE` keeps the assembled passphrase in memory for
reuse during the process lifetime. Change these defines in that header to
adjust the configuration. The key-derivation parameters can also be tuned
there: `ARGON2_TIME_COST`, `ARGON2_MEMORY_COST_KIB`, and
`ARGON2_PARALLELISM` for Argon2id, or `PBKDF2_ITERATIONS` for PBKDF2. Keep the
same algorithm and parameters when decrypting existing ciphertexts.

## Build

```sh
make
```

This builds `libobfuscator.so` and generates `obfuscator_secrets.h` from
`obfuscator_secrets.txt` using the `hide_strings` helper. To build just the
helper, run `make hide_strings`. To remove generated build products, including
the generated secrets header, run `make clean`.

## Configure the passphrase

`obfuscator_secrets.txt` contains one directive per line. Blank lines and lines
beginning with `#` or `//` are ignored. Directives are processed in order and
their contents are concatenated:

```text
str:some secret text
file:/path/to/a/passphrase-file
file:$HOME/.config/obfuscator/passphrase
file:${SECRET_DIR}/passphrase
```

`str:` appends its value directly. `file:` appends the contents of the
specified file, with line endings removed. File paths are resolved relative to
the process's current working directory and support `$NAME` and `${NAME}`
environment-variable references. An unset variable or malformed braced
reference is an error; paths are not evaluated by a shell. The combined
passphrase must be non-empty and shorter than 256 bytes.

To create a random key file for use with the `file:` directive, run this from
the directory where you want the file to be created:

```sh
(umask 0377;./libobfuscator.so -k > secret_key.txt)
```

Then add `file:secret_key.txt` to `obfuscator_secrets.txt`. The restrictive
umask creates the file with mode `0400` (readable only by its owner), which is
recommended for protecting the key. If the file already exists, set its mode
explicitly with `chmod 0400 secret_key.txt`.

For a service managed by systemd, you can instead supply the key as a systemd
credential. Add this directive to `obfuscator_secrets.txt`:

```text
file:$CREDENTIALS_DIRECTORY/obfuscator_key.txt
```

Then configure the service to provide a credential with that name. For example,
to have systemd decrypt a credential from its encrypted credential store:

```ini
[Service]
LoadCredentialEncrypted=obfuscator_key.txt:/etc/credstore.encrypted/obfuscator_key
```

Systemd makes the credential available to the service in its credentials
directory, referenced by `CREDENTIALS_DIRECTORY`. You can also use
`LoadCredential=` when the source file is not stored encrypted. This works only
when the program is launched in the systemd service environment.

You can also use `file:/etc/machine-id` as a directive to make the derived
passphrase machine-specific, so it only works on systems with the same machine
ID. However, `/etc/machine-id` is readable by all local users, so this alone
does not provide strong protection.

Treat passphrases and passphrase files as sensitive. The generated header
obfuscates the directive strings, but this is not secure secret storage; do
not rely on it to protect credentials in a distributed binary.

## Command-line use

The executable reads one text line at a time from standard input and writes one
result line for each input line. With no option it encrypts; `-d` decrypts:

```sh
printf 'hello\n' | ./libobfuscator.so
printf 'BASE64_CIPHERTEXT\n' | ./libobfuscator.so -d
```

The `-k` option prints a randomly generated 256-bit value in hexadecimal. You
can redirect it to a file and reference that file with `file:` in
`obfuscator_secrets.txt`; the configured passphrase is used to derive the
encryption key.

Each encrypted value is Base64-encoded and contains a random salt, nonce,
ciphertext, and authentication tag. As a result, encrypting the same input
twice normally produces different output. Decryption fails if authentication
does not succeed.

## C API

Include `obfuscator.h` and call `obfuscate()` or `deobfuscate()`. Both functions
return the number of output bytes on success and `-1` on failure. The output
buffer must have room for the result plus a terminating NUL byte.

```c
#include <stdio.h>
#include <string.h>
#include "obfuscator.h"

int main(void) {
    const unsigned char message[] = "hello";
    char ciphertext[256];
    unsigned char plaintext[sizeof(message)];

    int ciphertext_len = obfuscate(
        message, (int)(sizeof(message) - 1), ciphertext, sizeof(ciphertext));
    if (ciphertext_len < 0) {
        return 1;
    }

    int plaintext_len = deobfuscate(
        ciphertext, ciphertext_len, plaintext, sizeof(plaintext));
    if (plaintext_len < 0) {
        return 1;
    }

    fwrite(plaintext, 1, (size_t)plaintext_len, stdout);
    fputc('\n', stdout);
    return 0;
}
```

For example, save this as `example.c` and link it against the built library:

```sh
cc -I. example.c -L. -lobfuscator -Wl,-rpath,'$ORIGIN' -o example
./example
```

Key derivation is selected in `obfuscator_cfg.h`: with
`OBFUSCATOR_USE_ARGON2` enabled, the implementation uses Argon2id; otherwise,
it uses PBKDF2-HMAC-SHA256. The current Makefile still links with `-largon2`,
so building without Argon2 also requires removing that linker flag from the
Makefile.

## Obfuscating strings for C

`hide_strings` converts a text file into a generated header:

```sh
make hide_strings
./hide_strings messages.txt
```

For `messages.txt`, this creates `messages.h`, with an inline
`messages_string(int number)` accessor. Blank lines and lines beginning with
`#` or `//` are skipped. This is lightweight string obfuscation, not
encryption: the generated header contains the data and the decoding routine.
