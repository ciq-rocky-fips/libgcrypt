#include <stdio.h>

// We can likely pare these down.
#define HAVE_CONFIG_H
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <ctype.h>
#ifdef HAVE_W32_SYSTEM
# include <fcntl.h> /* We need setmode().  */
#else
# include <signal.h>
#endif
#include <assert.h>
#include <unistd.h>

#ifndef _GCRYPT_IN_LIBGCRYPT
# include <gcrypt.h>
# define PACKAGE_BUGREPORT "devnull@example.org"
# define PACKAGE_VERSION "[build on " __DATE__ " " __TIME__ "]"
#endif
#include "../src/gcrypt-testapi.h"

#define PGM "fipsdrv"
#include "t-common.h"
#include <unistd.h>

#include <fcntl.h>

gpg_err_code_t run_selftests() 
{
	gpg_err_code_t rc;
	rc = gcry_control (GCRYCTL_SELFTEST, 1);
	return rc;
}

int check_version() {
	char * version;
	int rc;

	version = gcry_FIPS_version();
	printf("version: %s\n", version);
	rc = strcmp("Rocky Linux 8 Libgcrypt Cryptographic Module", version);
	if (rc != 0) {
		printf("version check failed\n");
	} else {
		printf("version check succeeded\n");
	}
	return rc;
}

// Location of the library under test is in env var TEST_LIBRARY_LOCATION.
# define BUFSIZE 512
int corrupt_lib() {
	uint8_t b = 0;
    ssize_t len = 0;
    int err = 0;
	char path[BUFSIZE];
	char *envvar = "TEST_LIBRARY_LOCATION";

	if (!getenv(envvar)) {
		printf("env var TEST_LIBRARY_LOCATION not set\n");
		return -1;
	}

	if(snprintf(path, BUFSIZE, "%s", getenv(envvar)) >= BUFSIZE){
        fprintf(stderr, "BUFSIZE of %d was too small. Aborting\n", BUFSIZE);
        exit(1);
    }
    printf("PATH: %s\n", path);

    int fd = open(path, O_RDWR);
    if (fd == -1) {
        err = errno;
		printf("Failed to open library\n");
        return err;
    }
	// read the first byte,
    len = pread(fd, &b, 1, 0);
    if (len != 1) {
        err = errno;
        (void)close(fd);
        if (len == 0) {
			printf("Failed to read first byte\n");
            /* Just map to EINVAL. */
            err = EINVAL;
        } else if (len < 0) {
			err = errno;
			printf("Failed to read first byte (%d)\n", err);
        }
        return err;
    }
    b ^= 0x1;
    len = pwrite(fd, &b, 1, 0);
    if (len != 1) {
        err = errno;
        (void)close(fd);
		printf("Failed to write first byte (%d)\n", err);
        return err;
    }
    (void)close(fd);
    return 0;
}

int main(int argc,char **argv) 
{
	int fips_mode_active;
	gcry_err_code_t rc = 0;

	if ((argc == 2) && (strcmp(argv[1], "-v") == 0)) {
		// Print and validate version. Exit.
		return check_version();
	}

	if ((argc == 2) && (strcmp(argv[1], "-c") == 0)) {
		// Corrupt / Uncorrupt library. Exit.
		return corrupt_lib();
	}

	// Check fips mode.
	xgcry_control ((GCRYCTL_SET_VERBOSITY, 1));
	fips_mode_active = gcry_fips_mode_active();
	if (!fips_mode_active)
	{
		printf("FAIL: !fips_mode_active\n");
		return -1;
	}

	// This will run self tests.
	rc = run_selftests();
	if (rc != 0) 
	{
		return rc;
	}
	return 0;
}