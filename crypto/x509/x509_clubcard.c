/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Decoder for the version 4 filter file format of C2SP uPKI revocation
 * v1.0.0, https://c2sp.org/upki-revocation@v1.0.0
 */

#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>
#include "internal/packet.h"
#include "crypto/clubcard.h"

#define FILTER_VERSION 4

/* Smallest wire encodings, used to bound counts before allocating */
#define COVERAGE_ENTRY_LEN (OSSL_CLUBCARD_LOG_ID_LEN + 8 + 8)
#define ISSUER_ENTRY_MIN_LEN \
    (OSSL_CLUBCARD_ISSUER_LEN + 4 + 1 + 4 + 4 + 4 + 1 + 2)
#define EXCEPTION_MIN_LEN 2
#define BIT_COLUMN_MIN_LEN 4
#define WORD_LEN 8

/**
 * @brief qsort() comparator ordering coverage entries by log ID.
 * @param a an OSSL_CLUBCARD_COVERAGE_ENTRY
 * @param b an OSSL_CLUBCARD_COVERAGE_ENTRY
 * @returns <0, 0 or >0 as a's log ID sorts before, equal to or after b's
 */
static int cmp_log_id(const void *a, const void *b)
{
    const OSSL_CLUBCARD_COVERAGE_ENTRY *x = a, *y = b;

    return memcmp(x->log_id, y->log_id, sizeof(x->log_id));
}

/**
 * @brief Decode CRLiteCoverage into cc, sorted by log ID.
 * @param pkt the input, advanced past the structure on success
 * @param cc the filter being built; owns any allocation even on failure
 * @returns an OSSL_CLUBCARD_DECODE_RESULT value
 */
static OSSL_CLUBCARD_DECODE_RESULT decode_coverage(PACKET *pkt,
    OSSL_CLUBCARD *cc)
{
    unsigned int count;
    size_t i;

    if (!PACKET_get_net_2(pkt, &count)
        || count > PACKET_remaining(pkt) / COVERAGE_ENTRY_LEN)
        return OSSL_CLUBCARD_DECODE_MALFORMED;
    if (count == 0)
        return OSSL_CLUBCARD_DECODE_OK;

    cc->coverage = OPENSSL_malloc_array(count, sizeof(*cc->coverage));
    if (cc->coverage == NULL)
        return OSSL_CLUBCARD_DECODE_ERROR;
    cc->coverage_count = count;

    for (i = 0; i < count; i++) {
        OSSL_CLUBCARD_COVERAGE_ENTRY *e = &cc->coverage[i];

        if (!PACKET_copy_bytes(pkt, e->log_id, sizeof(e->log_id))
            || !PACKET_get_net_8(pkt, &e->low)
            || !PACKET_get_net_8(pkt, &e->high))
            return OSSL_CLUBCARD_DECODE_MALFORMED;
    }

    /* Wire order is not significant; sort to detect duplicate log IDs */
    qsort(cc->coverage, count, sizeof(*cc->coverage), cmp_log_id);
    for (i = 1; i < count; i++)
        if (cmp_log_id(&cc->coverage[i - 1], &cc->coverage[i]) == 0)
            return OSSL_CLUBCARD_DECODE_MALFORMED;

    return OSSL_CLUBCARD_DECODE_OK;
}

/**
 * @brief Decode the exception list of an IssuerBlock.
 * @param pkt the input, advanced past the list on success
 * @param blk the block being built; owns any allocation even on failure
 * @returns an OSSL_CLUBCARD_DECODE_RESULT value
 */
static OSSL_CLUBCARD_DECODE_RESULT decode_exceptions(PACKET *pkt,
    OSSL_CLUBCARD_ISSUER_BLOCK *blk)
{
    unsigned int count, serial_len;
    PACKET all, serial;
    size_t i, off;

    if (!PACKET_get_net_2(pkt, &count)
        || count > PACKET_remaining(pkt) / EXCEPTION_MIN_LEN)
        return OSSL_CLUBCARD_DECODE_MALFORMED;
    if (count == 0)
        return OSSL_CLUBCARD_DECODE_OK;

    /* Find the extent of the list so it can be copied in one piece */
    all = *pkt;
    for (i = 0; i < count; i++)
        if (!PACKET_get_length_prefixed_1(pkt, &serial)
            || PACKET_remaining(&serial) == 0)
            return OSSL_CLUBCARD_DECODE_MALFORMED;

    blk->exceptions = OPENSSL_malloc_array(count, sizeof(*blk->exceptions));
    if (blk->exceptions == NULL)
        return OSSL_CLUBCARD_DECODE_ERROR;
    blk->exception_data = OPENSSL_memdup(PACKET_data(&all),
        PACKET_remaining(&all) - PACKET_remaining(pkt));
    if (blk->exception_data == NULL)
        return OSSL_CLUBCARD_DECODE_ERROR;
    blk->exception_count = count;

    for (i = 0, off = 0; i < count; i++) {
        serial_len = blk->exception_data[off++];
        blk->exceptions[i].serial = blk->exception_data + off;
        blk->exceptions[i].serial_len = serial_len;
        off += serial_len;
    }

    return OSSL_CLUBCARD_DECODE_OK;
}

/**
 * @brief Decode ClubcardIndex into cc, requiring ascending unique issuers.
 * @param pkt the input, advanced past the structure on success
 * @param cc the filter being built; owns any allocation even on failure
 * @returns an OSSL_CLUBCARD_DECODE_RESULT value
 */
static OSSL_CLUBCARD_DECODE_RESULT decode_index(PACKET *pkt,
    OSSL_CLUBCARD *cc)
{
    OSSL_CLUBCARD_DECODE_RESULT ret;
    unsigned long count;
    unsigned int rank, inverted;
    size_t i;

    if (!PACKET_get_net_4(pkt, &count)
        || count > PACKET_remaining(pkt) / ISSUER_ENTRY_MIN_LEN)
        return OSSL_CLUBCARD_DECODE_MALFORMED;
    if (count == 0)
        return OSSL_CLUBCARD_DECODE_OK;

    /* Zeroed so that a partially decoded entry can be freed */
    cc->issuers = OPENSSL_calloc(count, sizeof(*cc->issuers));
    if (cc->issuers == NULL)
        return OSSL_CLUBCARD_DECODE_ERROR;
    cc->issuer_count = count;

    for (i = 0; i < count; i++) {
        OSSL_CLUBCARD_ISSUER_ENTRY *e = &cc->issuers[i];
        OSSL_CLUBCARD_ISSUER_BLOCK *blk = &e->block;

        if (!PACKET_copy_bytes(pkt, e->issuer, sizeof(e->issuer))
            || !PACKET_get_net_4_len_u32(pkt, &blk->approx_m)
            || !PACKET_get_1(pkt, &rank)
            || !PACKET_get_net_4_len_u32(pkt, &blk->approx_offset)
            || !PACKET_get_net_4_len_u32(pkt, &blk->exact_m)
            || !PACKET_get_net_4_len_u32(pkt, &blk->exact_offset)
            || !PACKET_get_1(pkt, &inverted)
            || inverted > 1)
            return OSSL_CLUBCARD_DECODE_MALFORMED;
        blk->approx_rank = rank;
        blk->inverted = (int)inverted;

        /* Sorted and unique, which also lets queries binary search */
        if (i > 0
            && memcmp(cc->issuers[i - 1].issuer, e->issuer,
                   sizeof(e->issuer))
                >= 0)
            return OSSL_CLUBCARD_DECODE_MALFORMED;

        ret = decode_exceptions(pkt, blk);
        if (ret != OSSL_CLUBCARD_DECODE_OK)
            return ret;
    }

    return OSSL_CLUBCARD_DECODE_OK;
}

/**
 * @brief Decode one BitColumn, converting words to host byte order.
 * @param pkt the input, advanced past the column on success
 * @param col the column to fill; owns any allocation even on failure
 * @returns an OSSL_CLUBCARD_DECODE_RESULT value
 */
static OSSL_CLUBCARD_DECODE_RESULT decode_bit_column(PACKET *pkt,
    OSSL_CLUBCARD_BIT_COLUMN *col)
{
    size_t count, i;

    if (!PACKET_get_net_4_len(pkt, &count)
        || count > PACKET_remaining(pkt) / WORD_LEN)
        return OSSL_CLUBCARD_DECODE_MALFORMED;
    if (count == 0)
        return OSSL_CLUBCARD_DECODE_OK;

    col->words = OPENSSL_malloc_array(count, sizeof(*col->words));
    if (col->words == NULL)
        return OSSL_CLUBCARD_DECODE_ERROR;
    col->word_count = count;

    for (i = 0; i < count; i++)
        if (!PACKET_get_net_8(pkt, &col->words[i]))
            return OSSL_CLUBCARD_DECODE_MALFORMED;

    return OSSL_CLUBCARD_DECODE_OK;
}

/**
 * @brief Decode ApproximateFilter into cc. Must follow decode_index(), as
 * every block's approx_rank is checked against the column count.
 * @param pkt the input, advanced past the structure on success
 * @param cc the filter being built; owns any allocation even on failure
 * @returns an OSSL_CLUBCARD_DECODE_RESULT value
 */
static OSSL_CLUBCARD_DECODE_RESULT decode_approximate(PACKET *pkt,
    OSSL_CLUBCARD *cc)
{
    OSSL_CLUBCARD_DECODE_RESULT ret;
    unsigned int count;
    size_t i;

    if (!PACKET_get_1(pkt, &count)
        || count > PACKET_remaining(pkt) / BIT_COLUMN_MIN_LEN)
        return OSSL_CLUBCARD_DECODE_MALFORMED;

    for (i = 0; i < cc->issuer_count; i++)
        if (cc->issuers[i].block.approx_rank > count)
            return OSSL_CLUBCARD_DECODE_MALFORMED;
    if (count == 0)
        return OSSL_CLUBCARD_DECODE_OK;

    cc->approx = OPENSSL_calloc(count, sizeof(*cc->approx));
    if (cc->approx == NULL)
        return OSSL_CLUBCARD_DECODE_ERROR;
    cc->approx_count = count;

    for (i = 0; i < count; i++) {
        ret = decode_bit_column(pkt, &cc->approx[i]);
        if (ret != OSSL_CLUBCARD_DECODE_OK)
            return ret;
    }

    return OSSL_CLUBCARD_DECODE_OK;
}

OSSL_CLUBCARD_DECODE_RESULT ossl_clubcard_decode(const unsigned char *data,
    size_t len, OSSL_CLUBCARD **out)
{
    OSSL_CLUBCARD_DECODE_RESULT ret = OSSL_CLUBCARD_DECODE_MALFORMED;
    OSSL_CLUBCARD *cc = NULL;
    unsigned int version, reserved0;
    PACKET pkt;

    if (out == NULL)
        return OSSL_CLUBCARD_DECODE_ERROR;
    *out = NULL;

    if (data == NULL || !PACKET_buf_init(&pkt, data, len)
        || !PACKET_get_1(&pkt, &version))
        return OSSL_CLUBCARD_DECODE_MALFORMED;
    if (version != FILTER_VERSION)
        return OSSL_CLUBCARD_DECODE_UNSUPPORTED;
    if (!PACKET_get_1(&pkt, &reserved0))
        return OSSL_CLUBCARD_DECODE_MALFORMED;
    /* A non-zero value is reserved to signal metadata not in version 4 */
    if (reserved0 != 0)
        return OSSL_CLUBCARD_DECODE_UNSUPPORTED;

    cc = OPENSSL_zalloc(sizeof(*cc));
    if (cc == NULL)
        return OSSL_CLUBCARD_DECODE_ERROR;

    if ((ret = decode_coverage(&pkt, cc)) != OSSL_CLUBCARD_DECODE_OK
        || (ret = decode_index(&pkt, cc)) != OSSL_CLUBCARD_DECODE_OK
        || (ret = decode_approximate(&pkt, cc)) != OSSL_CLUBCARD_DECODE_OK
        || (ret = decode_bit_column(&pkt, &cc->exact)) != OSSL_CLUBCARD_DECODE_OK)
        goto err;

    if (PACKET_remaining(&pkt) != 0) {
        ret = OSSL_CLUBCARD_DECODE_MALFORMED;
        goto err;
    }

    *out = cc;
    return OSSL_CLUBCARD_DECODE_OK;

err:
    ossl_clubcard_free(cc);
    return ret;
}

void ossl_clubcard_free(OSSL_CLUBCARD *cc)
{
    size_t i;

    if (cc == NULL)
        return;

    for (i = 0; i < cc->issuer_count; i++) {
        OPENSSL_free(cc->issuers[i].block.exceptions);
        OPENSSL_free(cc->issuers[i].block.exception_data);
    }
    OPENSSL_free(cc->issuers);
    for (i = 0; i < cc->approx_count; i++)
        OPENSSL_free(cc->approx[i].words);
    OPENSSL_free(cc->approx);
    OPENSSL_free(cc->exact.words);
    OPENSSL_free(cc->coverage);
    OPENSSL_free(cc);
}
