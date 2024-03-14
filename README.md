# Machine under test should be in fips mode
bash
```
[mhink@localhost libgcrypt]$ sudo fips-mode-setup --check
FIPS mode is enabled.
```
To enable:
bash
```
[mhink@localhost libgcrypt]$ sudo fips-mode-setup --enable
```

# Building libgcrypt (Your path may vary and will likely be a string replace in here and in the test_config file)
bash
```
cd /home/mhink/src/bitbucket.org/ciqinc/libgcrypt/libgcrypt-1.10.0
make clean ; echo $?
./build-local ; echo $?
make check ; echo $?
```

# Test configuration

The test configuration is in the test_config file. Paths will need to be updated depending on how the software under test is installed on the test machine.

# Test driver

Building the test driver from /home/mhink/src/bitbucket.org/ciqinc/libgcrypt (again fix the path)
bash
```
make ; echo $?
```

## Running the test driver
```
./failcases.sh ; echo $?
```

If the return code is not zero, the tests failed.

The root test driver is in directory `/home/mhink/src/bitbucket.org/ciqinc/libgcrypt`
and called `./failcases.sh`. It runs all pass cases as well.

# Test output

Success case traces are not output to the console because the feedback is extremely verbose.

## Failure cases

Sample output files show test output when the `SHOW_EXPECTED_FAILURES` setting in file test_config is 0 or 1.
The default is `SHOW_EXPECTED_FAILURES=1` which gives output like below when the test passes.

```
---
starting test run_mac_selftests, fail run_mac_selftests.fail
verifying run_mac_selftests, trace run_mac_selftests
Expected Failures:
GCRYPT: fips.c:590 0: run_mac_selftests HMAC KATs (GCRY_MAC_CMAC_AES) FAILED
GCRYPT: fips.c:590 0: run_mac_selftests HMAC KATs (GCRY_MAC_HMAC_SHA1) FAILED
GCRYPT: fips.c:590 0: run_mac_selftests HMAC KATs (GCRY_MAC_HMAC_SHA224) FAILED
GCRYPT: fips.c:590 0: run_mac_selftests HMAC KATs (GCRY_MAC_HMAC_SHA3_224) FAILED
GCRYPT: fips.c:590 0: run_mac_selftests HMAC KATs (GCRY_MAC_HMAC_SHA3_256) FAILED
GCRYPT: fips.c:590 0: run_mac_selftests HMAC KATs (GCRY_MAC_HMAC_SHA3_384) FAILED
GCRYPT: fips.c:590 0: run_mac_selftests HMAC KATs (GCRY_MAC_HMAC_SHA3_512) FAILED
GCRYPT: fips.c:590 0: run_mac_selftests HMAC KATs (GCRY_MAC_HMAC_SHA384) FAILED
GCRYPT: fips.c:590 0: run_mac_selftests HMAC KATs (GCRY_MAC_HMAC_SHA512) FAILED

Test Result: PASS - Verified run_mac_selftests run_mac_selftests
```

The more succinct `SHOW_EXPECTED_FAILURES=0` gives output like below when the test passes.
```
---
starting test run_mac_selftests, fail run_mac_selftests.fail
verifying run_mac_selftests, trace run_mac_selftests

Test Result: PASS - Verified run_mac_selftests run_mac_selftests
```
