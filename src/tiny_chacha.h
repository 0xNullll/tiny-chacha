/*
 * File: tiny_chacha.h
 * Author: 0xNullll
 * Description: This header provides the public interface for the Tiny ChaCha library.
 *              It defines context structs, function prototypes, feature flags,
 *              and inline helpers for all supported ChaCha and XChaCha variants:
 *              ChaCha8, ChaCha12, ChaCha20,
 *              XChaCha8, XChaCha12, XChaCha20.
 *              Implementation is in tiny_chacha.c.
 * License: MIT
 */

#ifndef TINY_CHACHA_H
#define TINY_CHACHA_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
    #define CPU_BIG_ENDIAN 1
#elif defined(_BIG_ENDIAN) || defined(__BIG_ENDIAN__) || defined(__ARMEB__) || defined(__MIPSEB__)
    #define CPU_BIG_ENDIAN 1
#else
    #define CPU_BIG_ENDIAN 0
#endif

#ifdef _MSC_VER
    #define FORCE_INLINE __forceinline
#else
    #define FORCE_INLINE inline __attribute__((always_inline))
#endif

/* ------------------------
   Feature Flags
   Users can define these as 0 (disable) or 1 (enable)
   before including the header, or via compiler -D flags.
   ------------------------ */

#ifndef ENABLE_CHACHA
    #define ENABLE_CHACHA 1
#endif

#ifndef ENABLE_XCHACHA
    #define ENABLE_XCHACHA 1
#endif

/* ------------------------
   Internal auto-enabling
   ------------------------ */

/* XChaCha uses ChaCha internally */
#if ENABLE_XCHACHA
  #undef ENABLE_CHACHA
  #define ENABLE_CHACHA 1
#endif

// =======================
//  Function name prefix support
// =======================
#ifndef TSHASH_PREFIX
    #define TSHASH_PREFIX /* empty by default */
#endif

#define _TS_CAT(a,b) a##b
#define _TS_CAT2(a,b) _TS_CAT(a,b)
#define TSHASH_FN(name) _TS_CAT2(TSHASH_PREFIX, name)

// =======================
// Bit rotation helpers
// =======================
static FORCE_INLINE uint32_t rotl32(uint32_t x, uint32_t n) {
    n &= 31;
    return (x << n) | (x >> (32 - n));
}

#define ROTL32(x,n) rotl32(x,n)

// =======================
// Small-endian conversions
// =======================
#if CPU_BIG_ENDIAN
// big-endian CPU: memory matches algorithm -> no-op
static FORCE_INLINE uint32_t BE32LE(const uint8_t *p) {
    uint32_t x;
    SECURE_MEMCPY(p, x, sizeof(x));
    return x;
}

static FORCE_INLINE void PUT32LE(uint8_t *p, uint32_t x) {
    SECURE_MEMCPY(p, x, sizeof(x));
}
#else
static FORCE_INLINE uint32_t BE32LE(const uint8_t *p) {
    return (uint32_t)p[0]         |
           ((uint32_t)p[1] << 8)  |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static FORCE_INLINE void PUT32LE(uint8_t *p, uint32_t x) {
    p[0] = (uint8_t)x;
    p[1] = (uint8_t)(x >> 8);
    p[2] = (uint8_t)(x >> 16);
    p[3] = (uint8_t)(x >> 24);
}
#endif

#define LOAD32LE(p)    BE32LE((const uint8_t*)(p))
#define STORE32LE(p,x) PUT32LE((uint8_t*)(p), x)

/* ======================================
   ChaCha (ChaCha8/ChaCha12/ChaCha20)
   ====================================== */
#if ENABLE_CHACHA
#define ChaChaInit      TSHASH_FN(ChaChaInit)
#define ChaChaCipher    TSHASH_FN(ChaChaCipher)

/* ChaCha round variants */
#define CHACHA_ROUNDS_8      8
#define CHACHA_ROUNDS_12     12
#define CHACHA_ROUNDS_20     20

#define CHACHA_BLOCK_SIZE     64   // 512-bit block
#define CHACHA_KEY_SIZE_128   16   // 128-bit key (optional, smaller variant)
#define CHACHA_KEY_SIZE_256   32   // 256-bit key (default)
#define CHACHA_IV_SIZE        12   // 96-bit iv

typedef struct {
    uint32_t state[16];                    // internal 16-word state
    uint8_t  keystream[CHACHA_BLOCK_SIZE]; // buffer for generated block
    size_t   pos;                          // current position in keystream buffer
    int      rounds;                       // number of ChaCha rounds (can be 8, 12 or 20)
} CHACHA_CTX;

bool ChaChaInit(
    CHACHA_CTX *ctx,
    const uint8_t *key, size_t key_len, 
    const uint8_t iv[CHACHA_IV_SIZE],
    uint32_t counter, int rounds);

bool ChaChaCipher(CHACHA_CTX *ctx, const uint8_t *in, size_t in_len, uint8_t *out);

#endif // ENABLE_CHACHA

/* ======================================
   XChaCha (XChaCha8/XChaCha12/XChaCha20)
   ====================================== */
#if ENABLE_CHACHA
#define XChaChaInit      TSHASH_FN(XChaChaInit)
#define XChaChaCipher    TSHASH_FN(XChaChaCipher)

#define XCHACHA_KEY_SIZE       32  // 256-bit key
#define XCHACHA_IV_SIZE        24  // 192-bit iv

typedef CHACHA_CTX XCHACHA_CTX;

bool XChaChaInit(
    XCHACHA_CTX *ctx,
    const uint8_t key[XCHACHA_KEY_SIZE],
    const uint8_t iv[XCHACHA_IV_SIZE],
    int rounds);

bool XChaChaCipher(XCHACHA_CTX *ctx, const uint8_t *in, size_t in_len, uint8_t *out);

#endif // ENABLE_CHACHA

#ifdef __cplusplus
}
#endif

#endif  // TINY_CHACHA_H