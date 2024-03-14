#!/usr/bin/env bash
# This file is a series of tests.
# For each test:
# 1. Setup an environment variable to force a failure on encryption / decryption / verify for a specific case.
# 2. Truncate /tmp/gcrypt_test.log
# 3. Run all tests.
# 4. We should see the failure in /tmp/gcrypt_test.log.
#
# OS should be in FIPS mode.
# This file includes the all pass case as well.
# To setup FIPS mode in Rocky Linux:
# sudo fips-mode-setup --enable
# sudo shutdown -r now
# fips-mode-setup --check # check after restart
#

set -e

# Machine must be in fips mode
fips_mode=$(fips-mode-setup --check)
echo "fips mode is $fips_mode"
if [ "$fips_mode" != "FIPS mode is enabled." ]
then
    echo "FIPS mode is not enabled. Exiting."
    exit 1
fi

# Test driver must be built.
if [ ! -f driver ]
then
    echo "Test driver is not built. (Run make driver) Exiting."
    exit 1
fi

# Load the test configuration from file test_config in pwd.
source ./test_config

unset -f start_test || true
# Start a test case.
# $1 is the test driver
# $2 is the name of the function tested.
# $3 is the failure environment variable setting.
start_test () {
    local test_driver=$1
    local test_function=$2
    local test_fail_env_var=$3

    export GCRYPT_FIPS_FAIL_TESTS=
    echo ---
    if [[ -z $test_fail_env_var  ]]
    then
        echo starting test $test_function, fail none
    else
        echo starting test $test_function, fail $test_fail_env_var
    fi
    export GCRYPT_FIPS_FAIL_TESTS=$test_fail_env_var
    eval ${test_driver} || true
}

# drop existing function
unset -f verify || true
# Test verification.
# $1 is the name of the function to verify.
# $2 is the expected number of lines in syslog with FAILED in them.
# $3 is a string to grep for in syslog.
# $4 is the expected number of lines in syslog when grepping on $3
verify() {
    local function_name=$1
    local failed_count=$2
    local grep_string=$3
    local grep_count=$4
    local count=0

    # verify expected failure count
    echo verifying ${function_name}, trace $grep_string
    count=$(grep 'FAILED' /tmp/gcrypt_test.log | sort -u | wc -l)
    if [[ count -ne ${failed_count} ]]
    then
        echo FAIL Expected failed_count ${failed_count}, got ${count}
        # emit the failing grep
        grep 'FAILED' /tmp/gcrypt_test.log | sort -u
        return 1
    fi

    # verify expected failure count matching a grep
    count=$(grep GCRYPT /tmp/gcrypt_test.log | grep "${grep_string}" | grep FAILED | sort -u | wc -l)
    if [[ count -ne ${grep_count} ]]
    then
        echo FAIL Expected grep_count ${grep_count}, got ${count}
        # emit the failing grep
        grep GCRYPT /tmp/gcrypt_test.log | grep "${grep_string}" | grep FAILED | sort -u
        exit 1
    fi

    # count success on all pass case
    if [ $function_name = "all_pass" ]
    then
        count=$(grep SUCCESS /tmp/gcrypt_test.log | grep -v FAILED | sort -u | wc -l)
        echo "${count} success cases"

        # Emit success cases.
        grep SUCCESS /tmp/gcrypt_test.log | grep -v FAILED | sort -u

        # Should be 138 success cases.
        if [[ count -ne 138 ]]
        then
            echo FAIL Expected 138 success cases, got ${count}
            exit 1
        fi
    fi


    # show expected failures if configured to do so
    if [[ ${SHOW_EXPECTED_FAILURES} -eq 1 ]]
    then
      echo Expected Failures:
      grep GCRYPT /tmp/gcrypt_test.log | grep "${grep_string}" | grep FAILED | sort -u
    fi
    echo
    echo Test Result: PASS - Verified expected failures: ${function_name} ${grep_string}

    # unset any failure env vars for the sake of the next test
    export GCRYPT_FIPS_FAIL_TESTS=
}

# Dump the library version.
LD_PRELOAD=${TEST_LIBRARY_LOCATION} ./driver -v

set +e

# All tests pass case below.
# This is using make check as a test driver which runs more tests.
start_test ${LDCHECK} "all_pass" ""
verify "all_pass" 1 "XTS AES duplicate key test FAILED" 1

set -e # We cannot use this for the all pass case above.

# Test function: run_hmac_sha256_selftests
# Test trace: Initial hmac sha256 self test, md
# Test env var: GCRYPT_FIPS_FAIL_TESTS=initial_hmac_sha256_test.fail_md
start_test ${LDDRIVER} "run_hmac_sha256_selftests" "initial_hmac_sha256_test.fail_md"
verify "run_hmac_sha256_selftests" 1 "Initial hmac sha256 self test, md" 1

# Test function: run_hmac_sha256_selftests
# Test trace: Initial hmac sha256 self test, mac
# Test env var: GCRYPT_FIPS_FAIL_TESTS=initial_hmac_sha256_test.fail_mac
start_test ${LDDRIVER} "run_hmac_sha256_selftests" "initial_hmac_sha256_test.fail_mac"
verify "run_hmac_sha256_selftests" 1 "Initial hmac sha256 self test, mac" 1

# Test function: check_binary_integrity
# Test trace: Software integrity test for libgcrypt (using an HMAC SHA2-256 digest)
# Test env var: GCRYPT_FIPS_FAIL_TESTS=check_binary_integrity.fail
# We need to corrupt the library for this one, then put it back to normal.
# The above is done in the library itself.
start_test ${LDDRIVER} "check_binary_integrity" "check_binary_integrity.fail"
verify "check_binary_integrity" 1 "Software integrity test for libgcrypt (using an HMAC SHA2-256 digest)" 1

# Test function: selftest_basic_128
# Test trace: AES encrypt and decrypt KATs CFB mode (128-bit length) AES-128 test encryption failed.
# Test env var: GCRYPT_FIPS_FAIL_TESTS=selftest_basic_128.encrypt
start_test ${LDDRIVER} "selftest_basic_128.encrypt" "selftest_basic_128.encrypt"
verify "selftest_basic_128.encrypt" 1 "AES-128 test encryption" 1

# Test function: selftest_basic_128
# Test trace: AES encrypt and decrypt KATs CFB mode (128-bit length) AES-128 test decryption failed.
# Test env var: GCRYPT_FIPS_FAIL_TESTS=selftest_basic_128.decrypt
start_test  ${LDDRIVER} "selftest_basic_128.decrypt" "selftest_basic_128.decrypt"
verify "selftest_basic_128.decrypt" 1 "AES-128 test decryption" 1

# Test function: selftest_basic_192
# Test trace: AES encrypt and decrypt KATs CFB mode (192-bit length) AES-192 test encryption failed.
# Test env var: GCRYPT_FIPS_FAIL_TESTS=selftest_basic_192.encrypt
start_test ${LDDRIVER} "selftest_basic_192.encrypt" "selftest_basic_192.encrypt"
verify "selftest_basic_192.encrypt" 1 "AES-192 test encryption" 1

# Test function: selftest_basic_192
# Test trace: AES encrypt and decrypt KATs CFB mode (192-bit length) AES-192 test decryption failed.
# Test env var: GCRYPT_FIPS_FAIL_TESTS=selftest_basic_192.decrypt
start_test ${LDDRIVER} "selftest_basic_192" "selftest_basic_192.decrypt"
verify "selftest_basic_192" 1 "AES-192 test decryption" 1

# Test function: selftest_basic_256
# Test trace: AES encrypt and decrypt KATs CFB mode (256-bit length) AES-256 test encryption failed.
# Test env var: GCRYPT_FIPS_FAIL_TESTS=selftest_basic_192.encrypt
start_test ${LDDRIVER} "selftest_basic_256.encrypt" "selftest_basic_256.encrypt"
verify "selftest_basic_256.encrypt" 1 "AES-256 test encryption" 1

# Test function: selftest_basic_256
# Test trace: AES encrypt and decrypt KATs CFB mode (256-bit length) AES-256 test decryption failed.
# Test env var: GCRYPT_FIPS_FAIL_TESTS=selftest_basic_192.decrypt
start_test ${LDDRIVER} "selftest_basic_256.decrypt" "selftest_basic_256.decrypt"
verify "selftest_basic_256.decrypt" 1 "AES-256 test decryption" 1

# Test function: cipher/mac-cmac.c:selftests_cmac_aes
# Test trace: AES encrypt and decrypt KATs CFB mode (%d-bit length) AES-256 test decryption failed.
# Test env var: GCRYPT_FIPS_FAIL_TESTS=selftests_cmac_aes.fail
start_test ${LDDRIVER} "selftests_cmac_aes" "selftests_cmac_aes.fail"
verify "selftests_cmac_aes" 3 "AES CMAC generate and verify KATs" 3

# Test function: check_xts_cipher
# Test trace:
# Test env var: GCRYPT_FIPS_FAIL_TESTS=check_xts_cipher.encrypt
start_test ${LDCHECK} "check_xts_cipher" "check_xts_cipher.encrypt"
verify "check_xts_cipher" 2 "XTS-AES KAT, encrypt output" 1

# Test function: check_xts_cipher
# Test trace: XTS-AES KAT, decrypt output
# Test env var: GCRYPT_FIPS_FAIL_TESTS=check_xts_cipher.decrypt
start_test ${LDCHECK} "check_xts_cipher" "check_xts_cipher.decrypt"
verify "check_xts_cipher" 2 "XTS-AES KAT, decrypt output" 1

# Test function: selftest_cbc_128
# Test trace: AES-CBC-128 decrypt
# Test env var: GCRYPT_FIPS_FAIL_TESTS=aes_cbc_128.decrypt
start_test ${LDDRIVER} "aes_cbc_128" "aes_cbc_128.decrypt"
verify "aes_cbc_128" 1 "AES-CBC-128 decrypt" 1

# Note: Triple-DES does not run with make check (Triple-DES is disabled.)
# Test function: des.c:selftest
# Test function: selftests_cmac_3des

# Test function: _gcry_rngdrbg_healthcheck_one
# Test trace: _gcry_rngdrbg_healthcheck_one DRBG KAT
# Test env var: _gcry_rngdrbg_healthcheck_one.fail
start_test ${LDCHECK} "_gcry_rngdrbg_healthcheck_one" "_gcry_rngdrbg_healthcheck_one.fail"
verify "_gcry_rngdrbg_healthcheck_one" 8 "_gcry_rngdrbg_healthcheck_one DRBG KAT" 7

# Test function: drbg_seed
# Test trace: CTR_DRBG KAT (AES-CTR mode; 128/192/256-bit)
# Test env var: drbg_seed.fail
start_test ${LDDRIVER} "drbg_seed" "drbg_seed.fail"
verify "drbg_seed" 1 "CTR_DRBG KAT (AES-CTR mode; 128/192/256-bit)" 1

# Test function: drbg_get_entropy
# Test trace: DRBG: entropy
# Test env var: drbg_get_entropy.fail
start_test ${LDDRIVER} "drbg_get_entropy" "drbg_get_entropy.fail"
verify "drbg_get_entropy" 2 "DRBG: entropy FAILED" 1
verify "drbg_get_entropy" 2 "CTR_DRBG KAT (AES-CTR mode; 128/192/256-bit)" 1

# Test function: cipher/ecc.c:selftest_sign
# Test trace: ECDSA sign KAT (P-224 curve, SHA2-256) signing
# Test env var: ecc_selftest_sign.sign
start_test ${LDDRIVER} "ecc_selftest_sign" "ecc_selftest_sign.sign"
verify "ecc_selftest_sign" 2 "ECDSA sign KAT (P-224 curve, SHA2-256) signing" 1

# Test function: cipher/ecc.c:selftest_sign
# Test trace: ECDSA verify KAT (P-224 and K-233 curve, SHA2-256) verify failed
# Test env var: ecc_selftest_sign.sign
start_test ${LDDRIVER} "ecc_selftest_sign" "ecc_selftest_sign.verify"
verify "ecc_selftest_sign" 2 "ECDSA verify KAT (P-224 curve, SHA2-256) verify failed" 1

# Test function: selftest_pbkdf2
# Test trace: HKDF KAT (PBKDF2 SHA256)
# Test env var: selftest_pbkdf2.fail
start_test ${LDDRIVER} "selftest_pbkdf2" "selftest_pbkdf2.fail"
verify "selftest_pbkdf2" 1 "HKDF KAT (PBKDF2 SHA256)" 1

# Test function: run_mac_selftests
# Test trace: run_mac_selftestss
# Test env var: run_mac_selftests.fail
start_test ${LDDRIVER} "run_mac_selftests" "run_mac_selftests.fail"
verify "run_mac_selftests" 9 "run_mac_selftests" 9

# Test function: selftests_sha1
# Test trace: HMAC KATs (SHA-1)
# Test env var: selftests_sha1.fail
start_test ${LDDRIVER} "selftests_sha1" "selftests_sha1.fail"
verify "selftests_sha1" 4 "HMAC KATs (SHA-1)" 4

# Test function: selftests_sha224
# Test trace: HMAC KATs (SHA-224)
# Test env var: selftests_sha224.fail
start_test ${LDDRIVER} "selftests_sha224" "selftests_sha224.fail"
verify "selftests_sha224" 1 "HMAC KATs (SHA-224)" 1

# Test function: selftests_sha256
# Test trace: HMAC KATs (SHA-256)
# Test env var: selftests_sha256.fail
start_test ${LDDRIVER} "selftests_sha256" "selftests_sha256.fail"
verify "selftests_sha256" 1 "HMAC KATs (SHA-256)" 1

# Test function: selftests_sha384
# Test trace: HMAC KATs (SHA-384)
# Test env var: selftests_sha384.fail
start_test ${LDDRIVER} "selftests_sha384" "selftests_sha384.fail"
verify "selftests_sha384" 1 "HMAC KATs (SHA-384)" 1

# Test function: selftests_sha512
start_test ${LDDRIVER} "selftests_sha512" "selftests_sha512.fail"
verify "selftests_sha512" 1 "HMAC KATs (SHA-512)" 1

# Test function: selftests_sha3
# Test trace: HMAC KATs (SHA-3)
# Test env var: selftests_sha3.fail
start_test ${LDDRIVER} "selftests_sha3" "selftests_sha3.fail"
verify "selftests_sha3" 4 "HMAC KATs (SHA-3)" 4

# Test function: selftests_rsa
# Test trace: 2048bit RSA, sign KAT
# Test env var: selftests_rsa.sign
start_test ${LDDRIVER} "selftests_rsa" "selftests_rsa.sign"
verify "selftests_rsa" 1 "2048bit RSA, sign KAT" 1

# Test function: selftests_rsa
# Test trace: 2048bit RSA, encrypt KAT
# Test env var: selftests_rsa.encrypt
start_test ${LDDRIVER} "selftests_rsa" "selftests_rsa.encrypt"
verify "selftests_rsa" 2 "2048bit RSA, encrypt KAT" 1

# Test function: selftests_rsa
# Test trace: 2048bit RSA, decrypt KAT
# Test env var: selftests_rsa.decrypt
start_test ${LDDRIVER} "selftests_rsa" "selftests_rsa.decrypt"
verify "selftests_rsa" 2 "2048bit RSA, decrypt KAT" 1

# Test function: selftests_rsa
# Test trace: 2048bit RSA, verify KAT
# Test env var: selftests_rsa.verify
start_test ${LDDRIVER} "selftests_rsa" "selftests_rsa.verify"
verify "selftests_rsa" 2 "2048bit RSA, verify KAT" 1

# Test function: run_digest_selftests
# Test trace: run_digest_selftests
# Test env var: run_digest_selftests.fail
start_test ${LDDRIVER} "run_digest_selftests" "run_digest_selftests.fail"
verify "run_digest_selftests" 4 "run_digest_selftests " 4

# Test function: selftests_keccak
# Test trace: selftests_keccak SHA3 KATs (SHA3-224, SHA3-256, SHA3-384, SHA3-512)
# Test trace: selftests_keccak SHAKE KATs (SHAKE-128, SHAKE-256)
start_test ${LDCHECK} "selftests_keccak" "selftests_keccak.shortstring"
verify "selftests_keccak" 6 "keccak" 5

# cipher/ecc.c:selftests_ecdsa
# Test function: cipher/ecc.c:selftests_ecdsa
# Test trace: ECDSA key generation PCT, sign
# Test env var: ecc_selftests_ecdsa.sign.
start_test ${LDDRIVER} "selftests_ecdsa" "ecc_selftests_ecdsa.sign"
verify "selftests_ecdsa" 1 "ECDSA key generation PCT, sign" 1

# cipher/ecc.c:selftests_ecdsa
# Test function: cipher/ecc.c:selftests_ecdsa
# Test trace: ECDSA key generation PCT, sign
# Test env var: ecc_selftests_ecdsa.sign.
start_test ${LDDRIVER} "selftests_ecdsa" "ecc_selftests_ecdsa.verify"
verify "selftests_ecdsa" 2 "ECDSA key generation PCT, verify" 1

# Test function: cipher/ecc.c:test_keys_fips
# Test trace: ECDSA key generation KAT, sign
# Test env var: ecc_selftests_ecdsa.sign.
start_test ${LDCHECK} "selftests_ecdsa" "ecc_test_keys_fips.sign"
verify "selftests_ecdsa" 2 "ECDSA key generation KAT, sign" 1

# Test function: cipher/ecc.c:test_keys_fips
# Test trace: ECDSA key generation KAT, verify
# Test env var: ecc_selftests_ecdsa.sign.
start_test ${LDCHECK} "selftests_ecdsa" "ecc_test_keys_fips.verify"
verify "selftests_ecdsa" 2 "ECDSA key generation KAT, verify" 1


# RSA PCT FIPS

# Test function: cipher/rsa.c:test_keys_fips
# Test trace: RSA key generation PCT fips (SHA-256; initial encrypt)
# Test env var: rsa_test_keys_fips.intial_encrypt.
start_test ${LDCHECK} "rsa_test_keys_fips" "rsa_test_keys_fips.intial_encrypt"
verify "rsa_test_keys_fips" 2 "RSA key generation PCT fips (SHA-256; initial encrypt)" 1

# Test function: cipher/rsa.c:test_keys_fips
# Test trace: RSA key generation PCT fips (SHA-256; initial decrypt)
# Test env var: rsa_test_keys_fips.intial_decrypt.
start_test ${LDCHECK} "rsa_test_keys_fips" "rsa_test_keys_fips.intial_decrypt"
verify "rsa_test_keys_fips" 2 "RSA key generation PCT fips (SHA-256; initial decrypt)" 1

# Test function: cipher/rsa.c:test_keys_fips
# Test trace: RSA key generation PCT fips (SHA-256; extract)
# Test env var: rsa_test_keys_fips.extract.
start_test ${LDCHECK} "rsa_test_keys_fips" "rsa_test_keys_fips.extract"
verify "rsa_test_keys_fips" 2 "RSA key generation PCT fips (SHA-256; extract)" 1

# Test function: cipher/rsa.c:test_keys_fips
# Test trace: RSA key generation PCT fips (SHA-256; strip)
# Test env var: rsa_test_keys_fips.strip.
start_test ${LDCHECK} "rsa_test_keys_fips" "rsa_test_keys_fips.strip"
verify "rsa_test_keys_fips" 2 "RSA key generation PCT fips (SHA-256; strip)" 1

# Test function: cipher/rsa.c:test_keys_fips
# Test trace: RSA key generation PCT fips (SHA-256; md open)
# Test env var: rsa_test_keys_fips.md_open.
start_test ${LDCHECK} "rsa_test_keys_fips" "rsa_test_keys_fips.md_open"
verify "rsa_test_keys_fips" 2 "RSA key generation PCT fips (SHA-256; md open)" 1

# Test function: cipher/rsa.c:test_keys_fips
# Test trace: RSA key generation PCT fips (SHA-256; md sign)
# Test env var: rsa_test_keys_fips.md_open.
start_test ${LDCHECK} "rsa_test_keys_fips" "rsa_test_keys_fips.sign"
verify "rsa_test_keys_fips" 2 "RSA key generation PCT fips (SHA-256; sign)" 1

# Test function: cipher/rsa.c:test_keys_fips
# Test trace: RSA key generation PCT fips (SHA-256; md sign)
# Test env var: rsa_test_keys_fips.md_open.
start_test ${LDCHECK} "rsa_test_keys_fips" "rsa_test_keys_fips.verify"
verify "rsa_test_keys_fips" 2 "RSA key generation PCT fips (SHA-256; verify should succeed)" 1

# Test function: cipher/rsa.c:test_keys_fips
# Test trace: RSA key generation PCT fips (SHA-256; md sign)
# Test env var: rsa_test_keys_fips.md_open.
start_test ${LDCHECK} "rsa_test_keys_fips" "rsa_test_keys_fips.verify_should_fail"
verify "rsa_test_keys_fips" 2 "RSA key generation PCT fips (SHA-256; verify should fail)" 1

# Two test traces here.
# Test function: gcry_mpi_ec_curve_point
# Test trace: ECDH public key assurance checks, not/on curve
# Test trace: ECDH public key assurance checks, on/not curve
# Test env var: gcry_mpi_ec_curve_point.assurance.
start_test ${LDCHECK} "gcry_mpi_ec_curve_point" "gcry_mpi_ec_curve_point.assurance"
verify "gcry_mpi_ec_curve_point" 3 "ECDH public key assurance checks, not/on curve" 1
verify "gcry_mpi_ec_curve_point" 3 "ECDH public key assurance checks, on/not curve" 1

# Test function: gcry_mpi_ec_curve_point
# Test trace: ECDH public key assurance checks, check_ec_mul_reduction_a
# Test env var: gcry_mpi_ec_curve_point.check_ec_mul_reduction_a.
start_test ${LDCHECK} "gcry_mpi_ec_curve_point" "gcry_mpi_ec_curve_point.check_ec_mul_reduction_a"
verify "gcry_mpi_ec_curve_point" 2 "ECDH public key assurance checks, check_ec_mul_reduction_a" 1

# Test function: gcry_mpi_ec_curve_point
# Test trace: ECDH public key assurance checks, check_ec_mul_reduction_b
# Test env var: gcry_mpi_ec_curve_point.check_ec_mul_reduction_b.
start_test ${LDCHECK} "gcry_mpi_ec_curve_point" "gcry_mpi_ec_curve_point.check_ec_mul_reduction_b"
verify "gcry_mpi_ec_curve_point" 2 "ECDH public key assurance checks, check_ec_mul_reduction_b" 1

# Test function: cipher_setkey
# Test trace: XTS AES duplicate key test
# Test env var: cipher_setkey.invalid_keylen.
start_test ${LDCHECK} "cipher_setkey" "cipher_setkey.invalid_keylen"
verify "cipher_setkey" 2 "XTS AES duplicate key test" 2

echo
echo 'Test pass completed. All tests have passed'