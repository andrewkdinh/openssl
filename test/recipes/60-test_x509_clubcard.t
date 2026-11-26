#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use OpenSSL::Test qw/:DEFAULT data_dir/;

setup("test_x509_clubcard");

plan tests => 1;

ok(run(test(["x509_clubcard_test", data_dir()])), "Clubcard filter decoding");
