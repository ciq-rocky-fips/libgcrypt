#!/usr/bin/env bash
# This script truncates /tmp/gcrypt_test.log and runs all of the GCRYPT tests against the test library.
# The path to the test library may need to change on your machine. (See test_config file)
#
bash -c "truncate -s 0 /tmp/gcrypt_test.log"
# Load configuration
source ./test_config
# LD_PRELOAD loads the library under tests. Caller is running the tests that work with our test binary.
LD_PRELOAD=${TEST_LIBRARY_LOCATION} ${SIMPLE_DRIVER} &>/dev/null |:
