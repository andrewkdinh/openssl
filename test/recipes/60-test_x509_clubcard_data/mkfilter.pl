#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

# Writes v4.filter, a synthetic Clubcard filter file encoded as described in
# "Filter file format" of https://c2sp.org/upki-revocation@v1.0.0.
# The values are arbitrary; test/x509_clubcard_test.c checks them.
#
# Usage: perl mkfilter.pl > v4.filter

use strict;
use warnings;

# 32 bytes counting up from $first
sub id32 { my $first = shift; return pack("C*", map { $first + $_ } 0 .. 31); }

# Each word is given as 16 hex digits, most significant first
sub bit_column {
    my @words = @_;
    return pack("N", scalar @words) . join("", map { pack("H16", $_) } @words);
}

my $out = pack("CC", 4, 0);                       # version, reserved0

# CRLiteCoverage, log IDs deliberately not in ascending order
$out .= pack("n", 2);
$out .= id32(0xa0) . pack("Q>Q>", 1767225600000, 1767225600005);
$out .= id32(0x10) . pack("Q>Q>", 1767225600100, 1767225600103);

# ClubcardIndex, sorted by issuer
$out .= pack("N", 2);
#               approx_m rank offset exact_m exact_offset inverted
$out .= id32(0x30) . pack("NCNNNC", 96, 7, 0, 40, 0, 0) . pack("n", 0);
$out .= id32(0x50) . pack("NCNNNC", 64, 3, 96, 20, 40, 1) . pack("n", 1)
    . pack("C", 16) . pack("C*", 0xc0 .. 0xcf);

# ApproximateFilter: columns 0-2 cover rows 0-159, columns 3-6 rows 0-95,
# and column 6 has its trailing zero word omitted
$out .= pack("C", 7);
$out .= bit_column("0123456789abcdef", "fedcba9876543210", "00000000000000ff");
$out .= bit_column("1111111111111111", "2222222222222222", "3333333333333333");
$out .= bit_column("4444444444444444", "5555555555555555", "6666666666666666");
$out .= bit_column("7777777777777777", "8888888888888888");
$out .= bit_column("9999999999999999", "aaaaaaaaaaaaaaaa");
$out .= bit_column("bbbbbbbbbbbbbbbb", "cccccccccccccccc");
$out .= bit_column("dddddddddddddddd");

# ExactFilter
$out .= bit_column("8000000000000001");

binmode STDOUT;
print $out;
