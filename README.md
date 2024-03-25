SRC-GIT repository for the FIPS gcrypt.

The code is maintained in separate branches:

1.10.0-FIPS: Production FIPS gcrypt for Rocky 8 and 9.
	Based on Gcrypt-1.10.0.

1.10.0-FIPS-FT: Functional test FIPS gcrypt for Rocky 8 and 9.

    This code is only intended for funcitonal testing
    of the FIPS functionality and not to be used in production.
    This branch is a set of commits based ontop of 1.10.0-FIPS and is
    not supposed to be updated manually. Instead it should be rebased
    ontop of 1.10.0-FIPS anytime 1.10.0-FIPS changes.

To run the functional test scripts from the 1.10.0-FIPS-FT branch.

1). Build gcrypt locally:
$ make_install.sh

2). Build functional tests:
$ cd FT

3). Build functional test driver:
$ make

4). Execute functional tests:
$ ./failcases.sh
