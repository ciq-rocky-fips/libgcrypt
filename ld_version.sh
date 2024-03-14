#!/usr/bin/env bash
# This script gets the fips version.
# bash -c "truncate -s 0 /tmp/gcrypt_test.log"
# Load configuration
source ./test_config
# LD_PRELOAD loads the library under tests. Caller is running the tests that work with our test binary.
LD_PRELOAD=${TEST_LIBRARY_LOCATION} ./driver -v
