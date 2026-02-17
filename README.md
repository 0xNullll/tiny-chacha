# Tiny ChaCha Library

A lightweight, portable C library implementing ChaCha and XChaCha stream ciphers. Fully enabled by default, optimized for little-endian and big-endian systems.

---

## Features

- **ChaCha variants**: ChaCha8, ChaCha12, ChaCha20 (supports 128-bit and 256-bit keys)
- **XChaCha variants**: XChaCha8, XChaCha12, XChaCha20 (supports **only 256-bit keys**)
- Separate implementation file (`tiny_chacha.c`) and header (`tiny_chacha.h`)  
- Incremental streaming cipher API: `Init`, `Cipher`
- Built-in handling of endianness
- Wrapper macros for function name prefixing (`TSHASH_PREFIX`)
- Self-contained, minimal footprint
- Lightweight — entire library under 20 KB

---

## Configurable Feature Flags

Enable or disable specific variants via compiler flags or preprocessor macros:

```c
#define ENABLE_CHACHA 1       // enable ChaCha
#define ENABLE_XCHACHA 1      // enable XChaCha
#define TSHASH_PREFIX MyLib_  // optional prefix for all functions
#include "tiny_chacha.h"
```

- XChaCha automatically enables ChaCha internally.  
- `TSHASH_PREFIX` allows avoiding name collisions in larger projects.  

---

## Building with CMake

1. Navigate to your project directory:

```bash
$ cd /path/to/repo/tiny-chacha
```

2. Create and enter the build folder:

```bash
$ mkdir build && cd build
```

3. Configure the project:

```bash
$ cmake ..
```

4. Build (Release mode recommended):

```bash
$ cmake --build . --config Release
```

- The final binary will be under `build/bin/Release/`

---

## Usage Examples

### ChaCha / Single-shot Encryption

```c
#include <stdio.h>
#include "tiny_chacha.h"

int main() {
    uint8_t key[CHACHA_KEY_SIZE_256] = {0};
    uint8_t iv[CHACHA_IV_SIZE] = {0};
    const char *plaintext = "Hello, Tiny ChaCha!";
    size_t len = strlen(plaintext);
    uint8_t ciphertext[64];

    CHACHA_CTX ctx;
    if (ChaChaInit(&ctx, key, sizeof(key), iv, 1, CHACHA_ROUNDS_20) &&
        ChaChaCipher(&ctx, (const uint8_t*)plaintext, len, ciphertext)) {
        printf("Ciphertext: ");
        for (size_t i = 0; i < len; i++)
            printf("%02x", ciphertext[i]);
        printf("\n");
    } else {
        printf("ChaCha encryption failed!\n");
    }

    return 0;
}
```

### XChaCha / Single-shot Encryption

```c
#include <stdio.h>
#include "tiny_chacha.h"

int main() {
    uint8_t key[XCHACHA_KEY_SIZE] = {0};
    uint8_t iv[XCHACHA_IV_SIZE] = {0};
    const char *plaintext = "Hello, Tiny XChaCha!";
    size_t len = strlen(plaintext);
    uint8_t ciphertext[64];

    XCHACHA_CTX ctx;
    if (XChaChaInit(&ctx, key, iv, CHACHA_ROUNDS_20) &&
        XChaChaCipher(&ctx, (const uint8_t*)plaintext, len, ciphertext)) {
        printf("Ciphertext: ");
        for (size_t i = 0; i < len; i++)
            printf("%02x", ciphertext[i]);
        printf("\n");
    } else {
        printf("XChaCha encryption failed!\n");
    }

    return 0;
}
```

---

## Key / IV Sizes

| Variant        | Key Size          | IV Size         |
|----------------|-------------------|-----------------|
| ChaCha8        | 128-bit / 256-bit | 96-bit (12 B)   |
| ChaCha12       | 128-bit / 256-bit | 96-bit (12 B)   |
| ChaCha20       | 128-bit / 256-bit | 96-bit (12 B)   |
| XChaCha8       | 256-bit           | 192-bit (24 B)  |
| XChaCha12      | 256-bit           | 192-bit (24 B)  |
| XChaCha20      | 256-bit           | 192-bit (24 B)  |

---

## Notes

- Fully self-contained — no external dependencies.
- Designed for simplicity, speed, and easy integration.
- All functions return `bool` to indicate success or failure.
- Supports little-endian and big-endian CPUs automatically.
- `TSHASH_PREFIX` can be defined to avoid function name collisions.

---

## Sources

- [RFC 7539: ChaCha20 and Poly1305 for IETF Protocols, May 2015](https://datatracker.ietf.org/doc/html/rfc7539)
- [draft-arciszewski-xchacha-03: XChaCha: eXtended-nonce ChaCha and AEAD_XChaCha20_Poly1305, December 18, 2018](https://datatracker.ietf.org/doc/html/draft-arciszewski-xchacha-03)

---

## License

This project is released under the **MIT License**. See [LICENSE](LICENSE) for full text.