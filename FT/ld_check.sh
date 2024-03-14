#!/usr/bin/env bash
# This script truncates /tmp/gcrypt_test.log and runs all of the GCRYPT tests against the test library.
# The path to the test library may need to change on your machine. (See test_config file)
#
bash -c "truncate -s 0 /tmp/gcrypt_test.log"
# Load configuration
source ./test_config
## LD_PRELOAD loads the library under tests. Caller is running the tests that run with make check.
# This takes longer than the binary driver, but will run the tests.

pushd ${MAKE_LOCATION} &>/dev/null
${CHECK_DRIVER} &>/dev/null
popd &>/dev/null
