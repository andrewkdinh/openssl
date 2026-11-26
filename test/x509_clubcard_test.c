/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Tests for the internal Clubcard v4 filter decoder */

#include <stdio.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include "internal/packet.h"
#include "crypto/clubcard.h"
#include "testutil.h"

static const char *datadir;

static unsigned char fixture[1024];
static size_t fixture_len;

/* Synthetic filter built by build_synthetic() */
static unsigned char *synth;
static size_t synth_len;

/* Offsets into synth, recorded while building it */
static struct {
    size_t reserved0;
    size_t coverage_count;
    size_t coverage_log_id[2];
    size_t issuer_count;
    size_t issuer[2];
    size_t approx_rank[2];
    size_t inverted[2];
    size_t exception_count;
    size_t approx_count;
    size_t word_count;
    size_t exact_word_count;
} off;

static const unsigned char *id32(unsigned char fill)
{
    static unsigned char buf[32];

    memset(buf, fill, sizeof(buf));
    return buf;
}

/* Check that a buffer holds 32 bytes counting up from first */
static int is_id32_seq(const unsigned char *p, unsigned char first)
{
    size_t i;

    for (i = 0; i < 32; i++)
        if (!TEST_uchar_eq(p[i], (unsigned char)(first + i)))
            return 0;
    return 1;
}

static int is_id32_fill(const unsigned char *p, unsigned char fill)
{
    return TEST_mem_eq(p, 32, id32(fill), 32);
}

static int put_block(WPACKET *pkt, uint32_t approx_m, unsigned int rank,
    uint32_t approx_offset, uint32_t exact_m, uint32_t exact_offset,
    unsigned int inverted)
{
    return WPACKET_put_bytes_u32(pkt, approx_m)
        && WPACKET_put_bytes_u8(pkt, rank)
        && WPACKET_put_bytes_u32(pkt, approx_offset)
        && WPACKET_put_bytes_u32(pkt, exact_m)
        && WPACKET_put_bytes_u32(pkt, exact_offset)
        && WPACKET_put_bytes_u8(pkt, inverted);
}

static int mark(WPACKET *pkt, size_t *where)
{
    return WPACKET_get_total_written(pkt, where);
}

/**
 * @brief Build synth and record field offsets in off.
 *
 * Two coverage entries out of order, two issuers (the first inverted, with
 * exceptions of 1, 3 and 255 bytes), two approximate columns of which the
 * second is empty, and an exact column with its lowest and highest bits set.
 * @returns 1 on success, 0 on failure
 */
static int build_synthetic(void)
{
    static const unsigned char ex3[] = { 0x00, 0x7f, 0x80 };
    unsigned char ex255[255];
    BUF_MEM *buf = NULL;
    WPACKET pkt;
    size_t i;
    int ok = 0;

    for (i = 0; i < sizeof(ex255); i++)
        ex255[i] = (unsigned char)i;

    if (!TEST_ptr(buf = BUF_MEM_new())
        || !TEST_true(WPACKET_init(&pkt, buf)))
        goto err;

    if (!TEST_true(WPACKET_put_bytes_u8(&pkt, 4))
        || !TEST_true(mark(&pkt, &off.reserved0))
        || !TEST_true(WPACKET_put_bytes_u8(&pkt, 0))
        /* Coverage */
        || !TEST_true(mark(&pkt, &off.coverage_count))
        || !TEST_true(WPACKET_put_bytes_u16(&pkt, 2))
        || !TEST_true(mark(&pkt, &off.coverage_log_id[0]))
        || !TEST_true(WPACKET_memcpy(&pkt, id32(0xee), 32))
        || !TEST_true(WPACKET_put_bytes_u64(&pkt, 0))
        || !TEST_true(WPACKET_put_bytes_u64(&pkt, UINT64_MAX))
        || !TEST_true(mark(&pkt, &off.coverage_log_id[1]))
        || !TEST_true(WPACKET_memcpy(&pkt, id32(0x01), 32))
        || !TEST_true(WPACKET_put_bytes_u64(&pkt, 1000))
        || !TEST_true(WPACKET_put_bytes_u64(&pkt, 1000))
        /* Index, first issuer */
        || !TEST_true(mark(&pkt, &off.issuer_count))
        || !TEST_true(WPACKET_put_bytes_u32(&pkt, 2))
        || !TEST_true(mark(&pkt, &off.issuer[0]))
        || !TEST_true(WPACKET_memcpy(&pkt, id32(0x01), 32))
        || !TEST_true(mark(&pkt, &off.approx_rank[0]))
        || !TEST_true(put_block(&pkt, 0xffffffff, 2, 7, 1, 0xfffffffe, 1))
        || !TEST_true(mark(&pkt, &off.exception_count))
        || !TEST_true(WPACKET_put_bytes_u16(&pkt, 3))
        || !TEST_true(WPACKET_sub_memcpy_u8(&pkt, "\x42", 1))
        || !TEST_true(WPACKET_sub_memcpy_u8(&pkt, ex3, sizeof(ex3)))
        || !TEST_true(WPACKET_sub_memcpy_u8(&pkt, ex255, sizeof(ex255)))
        /* Second issuer */
        || !TEST_true(mark(&pkt, &off.issuer[1]))
        || !TEST_true(WPACKET_memcpy(&pkt, id32(0x02), 32))
        || !TEST_true(mark(&pkt, &off.approx_rank[1]))
        || !TEST_true(put_block(&pkt, 10, 1, 0, 20, 0, 0))
        || !TEST_true(WPACKET_put_bytes_u16(&pkt, 0))
        /* Approximate filter */
        || !TEST_true(mark(&pkt, &off.approx_count))
        || !TEST_true(WPACKET_put_bytes_u8(&pkt, 2))
        || !TEST_true(mark(&pkt, &off.word_count))
        || !TEST_true(WPACKET_put_bytes_u32(&pkt, 2))
        || !TEST_true(WPACKET_put_bytes_u64(&pkt, 0x0102030405060708))
        || !TEST_true(WPACKET_put_bytes_u64(&pkt, 0xf0e0d0c0b0a09080))
        || !TEST_true(WPACKET_put_bytes_u32(&pkt, 0))
        /* Exact filter */
        || !TEST_true(mark(&pkt, &off.exact_word_count))
        || !TEST_true(WPACKET_put_bytes_u32(&pkt, 3))
        || !TEST_true(WPACKET_put_bytes_u64(&pkt, 1))
        || !TEST_true(WPACKET_put_bytes_u64(&pkt, 0x5a5a5a5a5a5a5a5a))
        || !TEST_true(WPACKET_put_bytes_u64(&pkt, (uint64_t)1 << 63))
        || !TEST_true(mark(&pkt, &synth_len))
        || !TEST_true(WPACKET_finish(&pkt))) {
        WPACKET_cleanup(&pkt);
        goto err;
    }

    /* Rank and inverted are 4 and 17 bytes into a block */
    for (i = 0; i < 2; i++) {
        off.inverted[i] = off.approx_rank[i] + 17;
        off.approx_rank[i] += 4;
    }

    synth = OPENSSL_memdup(buf->data, synth_len);
    ok = TEST_ptr(synth);
err:
    BUF_MEM_free(buf);
    return ok;
}

/**
 * @brief Decode data and check the result and the out-parameter.
 * @param data the filter bytes
 * @param len the number of bytes at data
 * @param expect the expected result
 * @returns 1 if the decoder behaved as expected, 0 otherwise
 */
static int decode_expect(const unsigned char *data, size_t len,
    OSSL_CLUBCARD_DECODE_RESULT expect)
{
    OSSL_CLUBCARD *cc = (OSSL_CLUBCARD *)&cc; /* not NULL */
    OSSL_CLUBCARD_DECODE_RESULT r = ossl_clubcard_decode(data, len, &cc);
    int ok = TEST_int_eq(r, expect);

    if (expect == OSSL_CLUBCARD_DECODE_OK)
        ok &= TEST_ptr(cc);
    else
        ok &= TEST_ptr_null(cc);
    ossl_clubcard_free(cc);
    return ok;
}

static int check_column(const OSSL_CLUBCARD_BIT_COLUMN *col,
    const uint64_t *words, size_t n)
{
    size_t i;

    if (!TEST_size_t_eq(col->word_count, n))
        return 0;
    if (n == 0)
        return TEST_ptr_null(col->words);
    for (i = 0; i < n; i++)
        if (!TEST_uint64_t_eq(col->words[i], words[i]))
            return 0;
    return 1;
}

static int test_decode_fixture(void)
{
    static const uint64_t c0[] = {
        0x0123456789abcdef, 0xfedcba9876543210, 0x00000000000000ff
    };
    static const uint64_t c3[] = { 0x7777777777777777, 0x8888888888888888 };
    static const uint64_t c6[] = { 0xdddddddddddddddd };
    static const uint64_t exact[] = { 0x8000000000000001 };
    static const size_t word_counts[] = { 3, 3, 3, 2, 2, 2, 1 };
    OSSL_CLUBCARD *cc = NULL;
    const OSSL_CLUBCARD_ISSUER_BLOCK *b;
    size_t i;
    int ok = 0;

    if (!TEST_int_eq(ossl_clubcard_decode(fixture, fixture_len, &cc),
            OSSL_CLUBCARD_DECODE_OK))
        goto end;

    /* Coverage, sorted by log ID */
    if (!TEST_size_t_eq(cc->coverage_count, 2)
        || !is_id32_seq(cc->coverage[0].log_id, 0x10)
        || !TEST_uint64_t_eq(cc->coverage[0].low, 1767225600100)
        || !TEST_uint64_t_eq(cc->coverage[0].high, 1767225600103)
        || !is_id32_seq(cc->coverage[1].log_id, 0xa0)
        || !TEST_uint64_t_eq(cc->coverage[1].low, 1767225600000)
        || !TEST_uint64_t_eq(cc->coverage[1].high, 1767225600005))
        goto end;

    /* Index */
    if (!TEST_size_t_eq(cc->issuer_count, 2)
        || !is_id32_seq(cc->issuers[0].issuer, 0x30)
        || !is_id32_seq(cc->issuers[1].issuer, 0x50))
        goto end;
    b = &cc->issuers[0].block;
    if (!TEST_uint_eq(b->approx_m, 96)
        || !TEST_uint_eq(b->approx_rank, 7)
        || !TEST_uint_eq(b->approx_offset, 0)
        || !TEST_uint_eq(b->exact_m, 40)
        || !TEST_uint_eq(b->exact_offset, 0)
        || !TEST_int_eq(b->inverted, 0)
        || !TEST_size_t_eq(b->exception_count, 0))
        goto end;
    b = &cc->issuers[1].block;
    if (!TEST_uint_eq(b->approx_m, 64)
        || !TEST_uint_eq(b->approx_rank, 3)
        || !TEST_uint_eq(b->approx_offset, 96)
        || !TEST_uint_eq(b->exact_m, 20)
        || !TEST_uint_eq(b->exact_offset, 40)
        || !TEST_int_eq(b->inverted, 1)
        || !TEST_size_t_eq(b->exception_count, 1)
        || !TEST_size_t_eq(b->exceptions[0].serial_len, 16)
        || !TEST_uchar_eq(b->exceptions[0].serial[0], 0xc0)
        || !TEST_uchar_eq(b->exceptions[0].serial[15], 0xcf))
        goto end;

    /* Filters */
    if (!TEST_size_t_eq(cc->approx_count, 7))
        goto end;
    for (i = 0; i < 7; i++)
        if (!TEST_size_t_eq(cc->approx[i].word_count, word_counts[i]))
            goto end;
    if (!check_column(&cc->approx[0], c0, 3)
        || !check_column(&cc->approx[3], c3, 2)
        || !check_column(&cc->approx[6], c6, 1)
        || !check_column(&cc->exact, exact, 1))
        goto end;

    ok = 1;
end:
    ossl_clubcard_free(cc);
    return ok;
}

static int test_decode_synthetic(void)
{
    static const uint64_t c0[] = { 0x0102030405060708, 0xf0e0d0c0b0a09080 };
    static const uint64_t exact[] = {
        1, 0x5a5a5a5a5a5a5a5a, (uint64_t)1 << 63
    };
    static const unsigned char ex3[] = { 0x00, 0x7f, 0x80 };
    OSSL_CLUBCARD *cc = NULL;
    const OSSL_CLUBCARD_ISSUER_BLOCK *b;
    size_t i;
    int ok = 0;

    if (!TEST_int_eq(ossl_clubcard_decode(synth, synth_len, &cc),
            OSSL_CLUBCARD_DECODE_OK))
        goto end;

    if (!TEST_size_t_eq(cc->coverage_count, 2)
        || !is_id32_fill(cc->coverage[0].log_id, 0x01)
        || !TEST_uint64_t_eq(cc->coverage[0].low, 1000)
        || !TEST_uint64_t_eq(cc->coverage[0].high, 1000)
        || !is_id32_fill(cc->coverage[1].log_id, 0xee)
        || !TEST_uint64_t_eq(cc->coverage[1].low, 0)
        || !TEST_uint64_t_eq(cc->coverage[1].high, UINT64_MAX))
        goto end;

    if (!TEST_size_t_eq(cc->issuer_count, 2)
        || !is_id32_fill(cc->issuers[0].issuer, 0x01)
        || !is_id32_fill(cc->issuers[1].issuer, 0x02))
        goto end;
    b = &cc->issuers[0].block;
    if (!TEST_uint_eq(b->approx_m, 0xffffffff)
        || !TEST_uint_eq(b->approx_rank, 2)
        || !TEST_uint_eq(b->approx_offset, 7)
        || !TEST_uint_eq(b->exact_m, 1)
        || !TEST_uint_eq(b->exact_offset, 0xfffffffe)
        || !TEST_int_eq(b->inverted, 1)
        || !TEST_size_t_eq(b->exception_count, 3)
        || !TEST_mem_eq(b->exceptions[0].serial, b->exceptions[0].serial_len,
            "\x42", 1)
        || !TEST_mem_eq(b->exceptions[1].serial, b->exceptions[1].serial_len,
            ex3, sizeof(ex3))
        || !TEST_size_t_eq(b->exceptions[2].serial_len, 255))
        goto end;
    for (i = 0; i < 255; i++)
        if (!TEST_uchar_eq(b->exceptions[2].serial[i], (unsigned char)i))
            goto end;
    /* Serials are copies, not pointers into the input */
    if (!TEST_false(b->exceptions[0].serial >= synth
            && b->exceptions[0].serial < synth + synth_len))
        goto end;

    b = &cc->issuers[1].block;
    if (!TEST_uint_eq(b->approx_m, 10)
        || !TEST_uint_eq(b->approx_rank, 1)
        || !TEST_uint_eq(b->approx_offset, 0)
        || !TEST_uint_eq(b->exact_m, 20)
        || !TEST_uint_eq(b->exact_offset, 0)
        || !TEST_int_eq(b->inverted, 0)
        || !TEST_size_t_eq(b->exception_count, 0)
        || !TEST_ptr_null(b->exceptions))
        goto end;

    if (!TEST_size_t_eq(cc->approx_count, 2)
        || !check_column(&cc->approx[0], c0, 2)
        || !check_column(&cc->approx[1], NULL, 0)
        || !check_column(&cc->exact, exact, 3))
        goto end;

    ok = 1;
end:
    ossl_clubcard_free(cc);
    return ok;
}

static int test_empty_filter(void)
{
    static const unsigned char empty[] = {
        4, 0, /* version, reserved0 */
        0, 0, /* coverage count */
        0, 0, 0, 0, /* issuer count */
        0, /* approximate column count */
        0, 0, 0, 0 /* exact word count */
    };
    OSSL_CLUBCARD *cc = NULL;
    int ok;

    ok = TEST_int_eq(ossl_clubcard_decode(empty, sizeof(empty), &cc),
             OSSL_CLUBCARD_DECODE_OK)
        && TEST_size_t_eq(cc->coverage_count, 0)
        && TEST_size_t_eq(cc->issuer_count, 0)
        && TEST_size_t_eq(cc->approx_count, 0)
        && TEST_size_t_eq(cc->exact.word_count, 0)
        && decode_expect(empty, sizeof(empty) - 1,
            OSSL_CLUBCARD_DECODE_MALFORMED);
    ossl_clubcard_free(cc);
    return ok;
}

static const unsigned char versions[] = { 0, 1, 3, 5, 255 };

static int test_unsupported_version(int i)
{
    unsigned char *buf;
    int ok;

    if (!TEST_ptr(buf = OPENSSL_memdup(synth, synth_len)))
        return 0;
    buf[0] = versions[i];
    ok = decode_expect(buf, synth_len, OSSL_CLUBCARD_DECODE_UNSUPPORTED)
        && decode_expect(buf, 1, OSSL_CLUBCARD_DECODE_UNSUPPORTED);
    OPENSSL_free(buf);
    return ok;
}

static int test_short_input(void)
{
    static const unsigned char v4 = 4;

    return decode_expect(NULL, 0, OSSL_CLUBCARD_DECODE_MALFORMED)
        && decode_expect(&v4, 0, OSSL_CLUBCARD_DECODE_MALFORMED)
        && decode_expect(&v4, 1, OSSL_CLUBCARD_DECODE_MALFORMED)
        && TEST_int_eq(ossl_clubcard_decode(synth, synth_len, NULL),
            OSSL_CLUBCARD_DECODE_ERROR);
}

/* Every proper prefix is malformed */
static int test_truncation(int i)
{
    const unsigned char *data = i == 0 ? fixture : synth;
    size_t len = i == 0 ? fixture_len : synth_len, n;

    for (n = 0; n < len; n++)
        if (!decode_expect(data, n, OSSL_CLUBCARD_DECODE_MALFORMED)) {
            TEST_info("prefix of %zu of %zu bytes", n, len);
            return 0;
        }
    return 1;
}

static void put_be(unsigned char *p, size_t width, uint64_t v)
{
    while (width-- > 0) {
        p[width] = (unsigned char)v;
        v >>= 8;
    }
}

static uint64_t get_be(const unsigned char *p, size_t width)
{
    uint64_t v = 0;

    while (width-- > 0)
        v = (v << 8) | *p++;
    return v;
}

/**
 * @brief Decode a copy of synth with one big-endian field overwritten.
 * @param offset the offset of the field in synth
 * @param width the field width in bytes
 * @param v the new field value
 * @param expect the expected result
 * @returns 1 if the decoder behaved as expected, 0 otherwise
 */
static int decode_patched(size_t offset, size_t width, uint64_t v,
    OSSL_CLUBCARD_DECODE_RESULT expect)
{
    unsigned char *buf;
    int ok;

    if (!TEST_ptr(buf = OPENSSL_memdup(synth, synth_len)))
        return 0;
    put_be(buf + offset, width, v);
    ok = decode_expect(buf, synth_len, expect);
    OPENSSL_free(buf);
    return ok;
}

static const struct {
    const char *name;
    size_t *offset;
    size_t width;
} count_fields[] = {
    { "coverage count", &off.coverage_count, 2 },
    { "issuer count", &off.issuer_count, 4 },
    { "exception count", &off.exception_count, 2 },
    { "approximate column count", &off.approx_count, 1 },
    { "approximate word count", &off.word_count, 4 },
    { "exact word count", &off.exact_word_count, 4 },
};

/* A count larger than the data that follows it is malformed */
static int test_count_overflow(int i)
{
    size_t o = *count_fields[i].offset, w = count_fields[i].width;
    uint64_t real = get_be(synth + o, w);
    uint64_t max = w == 8 ? UINT64_MAX : ((uint64_t)1 << (8 * w)) - 1;

    if (!decode_patched(o, w, real + 1, OSSL_CLUBCARD_DECODE_MALFORMED)
        || !decode_patched(o, w, max, OSSL_CLUBCARD_DECODE_MALFORMED)) {
        TEST_info("%s", count_fields[i].name);
        return 0;
    }
    return 1;
}

static int test_constraint_violation(void)
{
    unsigned char *buf = NULL;
    int ok = 0;

    /* Duplicate coverage log ID */
    if (!TEST_ptr(buf = OPENSSL_memdup(synth, synth_len)))
        goto end;
    memcpy(buf + off.coverage_log_id[1], buf + off.coverage_log_id[0], 32);
    if (!decode_expect(buf, synth_len, OSSL_CLUBCARD_DECODE_MALFORMED))
        goto end;
    OPENSSL_free(buf);

    /* Duplicate issuer */
    if (!TEST_ptr(buf = OPENSSL_memdup(synth, synth_len)))
        goto end;
    memcpy(buf + off.issuer[1], buf + off.issuer[0], 32);
    if (!decode_expect(buf, synth_len, OSSL_CLUBCARD_DECODE_MALFORMED))
        goto end;

    /* Issuers out of order */
    memset(buf + off.issuer[0], 0x03, 32);
    if (!decode_expect(buf, synth_len, OSSL_CLUBCARD_DECODE_MALFORMED))
        goto end;
    OPENSSL_free(buf);

    /* Trailing byte */
    if (!TEST_ptr(buf = OPENSSL_malloc(synth_len + 1)))
        goto end;
    memcpy(buf, synth, synth_len);
    buf[synth_len] = 0;
    if (!decode_expect(buf, synth_len + 1, OSSL_CLUBCARD_DECODE_MALFORMED))
        goto end;

    /* Rank larger than the approximate column count, in either issuer */
    ok = decode_patched(off.approx_rank[0], 1, 3,
             OSSL_CLUBCARD_DECODE_MALFORMED)
        && decode_patched(off.approx_rank[1], 1, 3,
            OSSL_CLUBCARD_DECODE_MALFORMED)
        /* inverted is 0 or 1 */
        && decode_patched(off.inverted[0], 1, 2,
            OSSL_CLUBCARD_DECODE_MALFORMED)
        && decode_patched(off.inverted[1], 1, 255,
            OSSL_CLUBCARD_DECODE_MALFORMED)
        /* reserved0 must be zero */
        && decode_patched(off.reserved0, 1, 1,
            OSSL_CLUBCARD_DECODE_UNSUPPORTED)
        /* Boundary values that are valid */
        && decode_patched(off.approx_rank[1], 1, 2, OSSL_CLUBCARD_DECODE_OK)
        && decode_patched(off.inverted[1], 1, 1, OSSL_CLUBCARD_DECODE_OK);
end:
    OPENSSL_free(buf);
    return ok;
}

/**
 * @brief Decode a filter with one issuer whose only exception has
 * serial_len bytes, so that an empty serial is its only defect.
 * @param serial_len 0 or 1
 * @param expect the expected result
 * @returns 1 if the decoder behaved as expected, 0 otherwise
 */
static int decode_one_exception(size_t serial_len,
    OSSL_CLUBCARD_DECODE_RESULT expect)
{
    static const unsigned char serial[] = { 0xaa };
    BUF_MEM *buf = NULL;
    WPACKET pkt;
    size_t len;
    int ok = 0;

    if (!TEST_ptr(buf = BUF_MEM_new())
        || !TEST_true(WPACKET_init(&pkt, buf)))
        goto end;
    if (!TEST_true(WPACKET_put_bytes_u16(&pkt, 0x0400))
        || !TEST_true(WPACKET_put_bytes_u16(&pkt, 0))
        || !TEST_true(WPACKET_put_bytes_u32(&pkt, 1))
        || !TEST_true(WPACKET_memcpy(&pkt, id32(0), 32))
        || !TEST_true(put_block(&pkt, 1, 0, 0, 1, 0, 0))
        || !TEST_true(WPACKET_put_bytes_u16(&pkt, 1))
        || !TEST_true(WPACKET_sub_memcpy_u8(&pkt, serial, serial_len))
        || !TEST_true(WPACKET_put_bytes_u8(&pkt, 0))
        || !TEST_true(WPACKET_put_bytes_u32(&pkt, 0))
        || !TEST_true(WPACKET_get_total_written(&pkt, &len))
        || !TEST_true(WPACKET_finish(&pkt))) {
        WPACKET_cleanup(&pkt);
        goto end;
    }
    ok = decode_expect((unsigned char *)buf->data, len, expect);
end:
    BUF_MEM_free(buf);
    return ok;
}

static int test_empty_exception(void)
{
    return decode_one_exception(1, OSSL_CLUBCARD_DECODE_OK)
        && decode_one_exception(0, OSSL_CLUBCARD_DECODE_MALFORMED);
}

static int read_fixture(void)
{
    char *path = NULL;
    BIO *bio = NULL;
    int n, ok = 0;

    if (!TEST_ptr(path = test_mk_file_path(datadir, "v4.filter"))
        || !TEST_ptr(bio = BIO_new_file(path, "rb")))
        goto end;
    n = BIO_read(bio, fixture, sizeof(fixture));
    if (!TEST_int_gt(n, 0) || !TEST_int_lt(n, (int)sizeof(fixture)))
        goto end;
    fixture_len = (size_t)n;
    ok = 1;
end:
    BIO_free(bio);
    OPENSSL_free(path);
    return ok;
}

OPT_TEST_DECLARE_USAGE("datadir\n")

int setup_tests(void)
{
    if (!test_skip_common_options()) {
        TEST_error("Error parsing test options\n");
        return 0;
    }
    if (!TEST_ptr(datadir = test_get_argument(0))
        || !read_fixture()
        || !build_synthetic())
        return 0;

    ADD_TEST(test_decode_fixture);
    ADD_TEST(test_decode_synthetic);
    ADD_TEST(test_empty_filter);
    ADD_ALL_TESTS(test_unsupported_version, OSSL_NELEM(versions));
    ADD_TEST(test_short_input);
    ADD_ALL_TESTS(test_truncation, 2);
    ADD_ALL_TESTS(test_count_overflow, OSSL_NELEM(count_fields));
    ADD_TEST(test_constraint_violation);
    ADD_TEST(test_empty_exception);
    return 1;
}

void cleanup_tests(void)
{
    OPENSSL_free(synth);
}
