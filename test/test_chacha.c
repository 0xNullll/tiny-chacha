#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "../src/tiny_chacha.h"

static void print_hex(const uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++)
        printf("%02x", buf[i]);
    printf("\n");
}

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int hex_to_bytes(const char *hex, uint8_t *out, size_t max_len) {
    size_t len = strlen(hex);
    if (len % 2 != 0) return -1;

    size_t bytes = len / 2;
    if (bytes > max_len) return -1;

    for (size_t i = 0; i < bytes; i++) {
        int hi = hexval(hex[i*2]);
        int lo = hexval(hex[i*2+1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }

    return (int)bytes;
}

int main(int argc, char **argv) {

    if (argc < 5) {
        printf("Usage:\n");
        printf("  %s <key_hex> <nonce_hex> <counter> <plaintext>\n", argv[0]);
        return 1;
    }

    uint8_t key[64];
    uint8_t nonce[64];
    uint8_t output[4096];

    int key_len = hex_to_bytes(argv[1], key, sizeof(key));
    int nonce_len = hex_to_bytes(argv[2], nonce, sizeof(nonce));
    uint32_t counter = (uint32_t)strtoul(argv[3], NULL, 10);

    const uint8_t *input = (const uint8_t*)argv[4];
    size_t input_len = strlen(argv[4]);

    if (key_len <= 0 || nonce_len <= 0) {
        printf("Invalid hex key or nonce\n");
        return 1;
    }

    printf("Input: \"%s\"\n", argv[4]);
    printf("Key (%d bytes): ", key_len); print_hex(key, key_len);
    printf("Nonce (%d bytes): ", nonce_len); print_hex(nonce, nonce_len);
    printf("Counter: %u\n\n", counter);

#if ENABLE_CHACHA
    if (nonce_len == CHACHA_IV_SIZE) {

        if (key_len != CHACHA_KEY_SIZE_128 && key_len != CHACHA_KEY_SIZE_256) {
            printf("ChaCha requires a 16-byte (128-bit) or 32-byte (256-bit) key\n");
            return 1;
        }

        int rounds[] = {CHACHA_ROUNDS_8, CHACHA_ROUNDS_12, CHACHA_ROUNDS_20};

        for (size_t i = 0; i < 3; i++) {
            CHACHA_CTX ctx;

            if (!ChaChaInit(&ctx, key, key_len,
                            nonce, counter, rounds[i])) {
                printf("ChaCha%d init failed\n", rounds[i]);
                continue;
            }

            if (!ChaChaCipher(&ctx, input, input_len, output)) {
                printf("ChaCha%d cipher failed\n", rounds[i]);
                continue;
            }

            printf("ChaCha%-2d : ", rounds[i]);
            print_hex(output, input_len);
            putchar('\n');
        }
    }
#endif

putchar('\n');

#if ENABLE_XCHACHA
    if (nonce_len == XCHACHA_IV_SIZE) {
        if (key_len != XCHACHA_KEY_SIZE) {
            printf("XChaCha requires a 32-byte (256-bit) key\n");
            return 1;
        }

        int rounds[] = {CHACHA_ROUNDS_8, CHACHA_ROUNDS_12, CHACHA_ROUNDS_20};

        for (size_t i = 0; i < 3; i++) {
            XCHACHA_CTX ctx;

            if (!XChaChaInit(&ctx, key, nonce, rounds[i])) {
                printf("XChaCha%d init failed\n", rounds[i]);
                continue;
            }

            if (!XChaChaCipher(&ctx, input, input_len, output)) {
                printf("XChaCha%d cipher failed\n", rounds[i]);
                continue;
            }

            printf("XChaCha%-2d: ", rounds[i]);
            print_hex(output, input_len);
            putchar('\n');
        }
    }
#endif

    return 0;
}