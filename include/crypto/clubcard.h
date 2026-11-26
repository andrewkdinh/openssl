/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/**
 * @file clubcard.h
 * @brief Decoder for version 4 Clubcard CRLite filter files.
 *
 * Structure and field names follow the "Filter file format" section of
 * C2SP uPKI revocation v1.0.0.
 * @see https://c2sp.org/upki-revocation@v1.0.0
 */

#ifndef OSSL_CRYPTO_CLUBCARD_H
#define OSSL_CRYPTO_CLUBCARD_H
#pragma once

#include <stddef.h>
#include <stdint.h>

/** @brief Length of a CT log ID (LogID) in bytes. */
#define OSSL_CLUBCARD_LOG_ID_LEN 32
/** @brief Length of an issuer SPKI hash (IssuerSPKIHash) in bytes. */
#define OSSL_CLUBCARD_ISSUER_LEN 32

/**
 * @brief Result of ossl_clubcard_decode().
 */
typedef enum {
    /** The filter was decoded. */
    OSSL_CLUBCARD_DECODE_OK = 1,
    /** The input is not a well-formed version 4 filter file. */
    OSSL_CLUBCARD_DECODE_MALFORMED = 0,
    /** The version is not 4, or reserved0 is not zero. */
    OSSL_CLUBCARD_DECODE_UNSUPPORTED = -1,
    /** An internal error, such as an allocation failure, occurred. */
    OSSL_CLUBCARD_DECODE_ERROR = -2
} OSSL_CLUBCARD_DECODE_RESULT;

/**
 * @struct ossl_clubcard_coverage_entry_st
 * @brief One CoverageEntry: a CT log and an inclusive timestamp interval.
 */
typedef struct ossl_clubcard_coverage_entry_st {
    unsigned char log_id[OSSL_CLUBCARD_LOG_ID_LEN]; /**< CT log ID */
    uint64_t low; /**< first covered timestamp, ms since the Unix epoch */
    uint64_t high; /**< last covered timestamp, ms since the Unix epoch */
} OSSL_CLUBCARD_COVERAGE_ENTRY;

/**
 * @struct ossl_clubcard_exception_st
 * @brief One Exception: a serial number stored outside the linear system.
 */
typedef struct ossl_clubcard_exception_st {
    const unsigned char *serial; /**< serial bytes, owned by the issuer entry */
    size_t serial_len; /**< length of serial, 1 to 255 */
} OSSL_CLUBCARD_EXCEPTION;

/**
 * @struct ossl_clubcard_issuer_block_st
 * @brief One IssuerBlock: per-issuer query parameters and exceptions.
 */
typedef struct ossl_clubcard_issuer_block_st {
    uint32_t approx_m; /**< rows of the approximate matrix */
    unsigned int approx_rank; /**< columns of the approximate matrix */
    uint32_t approx_offset; /**< row offset into the approximate matrix */
    uint32_t exact_m; /**< rows of the exact matrix */
    uint32_t exact_offset; /**< row offset into the exact matrix */
    int inverted; /**< result inversion flag, 0 or 1 */
    size_t exception_count; /**< number of entries in exceptions */
    OSSL_CLUBCARD_EXCEPTION *exceptions; /**< NULL when exception_count is 0 */
    unsigned char *exception_data; /**< storage for the exception serials */
} OSSL_CLUBCARD_ISSUER_BLOCK;

/**
 * @struct ossl_clubcard_issuer_entry_st
 * @brief One IssuerEntry: an enrolled issuer and its block.
 */
typedef struct ossl_clubcard_issuer_entry_st {
    unsigned char issuer[OSSL_CLUBCARD_ISSUER_LEN]; /**< issuer SPKI hash */
    OSSL_CLUBCARD_ISSUER_BLOCK block; /**< query parameters */
} OSSL_CLUBCARD_ISSUER_ENTRY;

/**
 * @struct ossl_clubcard_bit_column_st
 * @brief One BitColumn. Bit i is (words[i / 64] >> (i % 64)) & 1; bits
 * beyond the encoded words are zero.
 */
typedef struct ossl_clubcard_bit_column_st {
    size_t word_count; /**< number of entries in words */
    uint64_t *words; /**< words in host byte order, NULL if word_count is 0 */
} OSSL_CLUBCARD_BIT_COLUMN;

/**
 * @struct ossl_clubcard_st
 * @brief A decoded version 4 filter file. Owns all memory it points to.
 */
typedef struct ossl_clubcard_st {
    size_t coverage_count; /**< number of entries in coverage */
    OSSL_CLUBCARD_COVERAGE_ENTRY *coverage; /**< sorted by log_id */
    size_t issuer_count; /**< number of entries in issuers */
    OSSL_CLUBCARD_ISSUER_ENTRY *issuers; /**< sorted by issuer, unique */
    size_t approx_count; /**< columns of the approximate filter */
    OSSL_CLUBCARD_BIT_COLUMN *approx; /**< approximate filter columns */
    OSSL_CLUBCARD_BIT_COLUMN exact; /**< exact filter column */
} OSSL_CLUBCARD;

/**
 * @brief Decode a complete version 4 filter file.
 *
 * The result holds no pointers into the input. On failure no error is
 * pushed for format problems and *out is set to NULL.
 *
 * @param data the filter file bytes
 * @param len the number of bytes at data
 * @param out receives a new OSSL_CLUBCARD, free it with ossl_clubcard_free()
 * @returns an OSSL_CLUBCARD_DECODE_RESULT value
 */
OSSL_CLUBCARD_DECODE_RESULT ossl_clubcard_decode(const unsigned char *data,
    size_t len, OSSL_CLUBCARD **out);

/**
 * @brief Free a decoded filter and everything it owns.
 * @param cc the filter to free, may be NULL
 */
void ossl_clubcard_free(OSSL_CLUBCARD *cc);

#endif
