/* cipher-selftest.c - Helper functions for bulk encryption selftests.
 * Copyright (C) 2013,2020 Jussi Kivilinna <jussi.kivilinna@iki.fi>
 *
 * This file is part of Libgcrypt.
 *
 * Libgcrypt is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser general Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * Libgcrypt is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#ifdef HAVE_SYSLOG
# include <syslog.h>
#endif /*HAVE_SYSLOG*/

#include "types.h"
#include "g10lib.h"
#include "cipher.h"
#include "bufhelp.h"
#include "cipher-selftest.h"
#include "cipher-internal.h"

#define GCRYPT_AUDIT 1
#if defined(GCRYPT_AUDIT)
#define KAT_SUCCESS(x,y) do { FILE *fp; fp = fopen("/tmp/gcrypt_test.log", "a+"); if (fp != NULL) { fprintf(fp, "GCRYPT: %s:%d %d: %s SUCCESS\n", __FILE__, __LINE__, x, y); fclose(fp); } } while (0);
#define KAT_FAILED(x,y) do { FILE *fp; fp = fopen("/tmp/gcrypt_test.log", "a+"); if (fp != NULL) { fprintf(fp, "GCRYPT: %s:%d %d: %s FAILED\n", __FILE__, __LINE__, x, y); fclose(fp); } } while (0);
#else
#define KAT_SUCCESS(x, y) ((void)0)
#define KAT_FAILED(x, y) ((void)0)
#endif

#ifdef HAVE_STDINT_H
# include <stdint.h> /* uintptr_t */
#elif defined(HAVE_INTTYPES_H)
# include <inttypes.h>
#else
/* In this case, uintptr_t is provided by config.h. */
#endif

/* Helper macro to force alignment to 16 bytes.  */
#ifdef HAVE_GCC_ATTRIBUTE_ALIGNED
# define ATTR_ALIGNED_16  __attribute__ ((aligned (16)))
#else
# define ATTR_ALIGNED_16
#endif


/* Return an allocated buffers of size CONTEXT_SIZE with an alignment
   of 16.  The caller must free that buffer using the address returned
   at R_MEM.  Returns NULL and sets ERRNO on failure.  */
void *
_gcry_cipher_selftest_alloc_ctx (const int context_size, unsigned char **r_mem)
{
  int offs;
  unsigned int ctx_aligned_size, memsize;

  ctx_aligned_size = context_size + 15;
  ctx_aligned_size -= ctx_aligned_size & 0xf;

  memsize = ctx_aligned_size + 16;

  *r_mem = xtrycalloc (1, memsize);
  if (!*r_mem)
    return NULL;

  offs = (16 - ((uintptr_t)*r_mem & 15)) & 15;
  return (void*)(*r_mem + offs);
}


/* Run the self-tests for <block cipher>-CBC-<block size>, tests bulk CBC
   decryption.  Returns NULL on success. */
const char *
_gcry_selftest_helper_cbc (const char *cipher, gcry_cipher_setkey_t setkey_func,
			   gcry_cipher_encrypt_t encrypt_one,
			   const int nblocks, const int blocksize,
			   const int context_size)
{
  cipher_bulk_ops_t bulk_ops = { 0, };
  int i, offs;
  unsigned char *ctx, *plaintext, *plaintext2, *ciphertext, *iv, *iv2, *mem;
  unsigned int ctx_aligned_size, memsize;

  static const unsigned char key[16] ATTR_ALIGNED_16 = {
      0x66,0x9A,0x00,0x7F,0xC7,0x6A,0x45,0x9F,
      0x98,0xBA,0xF9,0x17,0xFE,0xDF,0x95,0x22
    };

  static const unsigned char encrypt_KA[288] = {
0xda,0x3c,0xeb,0xc5,0x28,0xa4,0x4c,0x49,
0x0a,0x5c,0xbb,0xde,0x2c,0x77,0x84,0xf6,
0x9e,0xe2,0x87,0x30,0xdc,0x21,0xb2,0x87,
0x82,0xbf,0xff,0xd8,0x75,0x90,0x27,0x17,
0x67,0x6b,0x37,0x60,0x99,0xb0,0x23,0x1e,
0x2f,0xa1,0xc3,0x6b,0xda,0x36,0x21,0x41,
0x3e,0x6f,0x26,0xee,0xaa,0x87,0x84,0x16,
0x65,0x85,0x6d,0x6a,0xb3,0x93,0x6f,0x67,
0x69,0xed,0xae,0x27,0xa8,0x74,0x84,0xab,
0x25,0x6b,0xc2,0x65,0x46,0x3f,0xe1,0xef,
0xb8,0x74,0xfa,0xd8,0xe6,0xf6,0xe3,0xe0,
0xb7,0x84,0xfd,0x57,0x6b,0x08,0x8b,0x8a,
0xa3,0xfc,0xb3,0xfa,0x55,0xfc,0xd6,0xd1,
0xf8,0x2a,0x52,0x0d,0xd9,0x16,0x9c,0xa9,
0xb9,0xa9,0x3b,0xb9,0x85,0x8f,0x5f,0x23,
0x7a,0x60,0x56,0xee,0x74,0x4a,0xbe,0x1a,
0xd1,0x8c,0xfa,0x3b,0x50,0xe0,0x99,0x30,
0x41,0xf4,0x0d,0x1f,0x43,0xd8,0x02,0xbe,
0x48,0x48,0x6d,0x7a,0xa0,0x95,0x1c,0x51,
0x78,0x68,0x2b,0x60,0x62,0x89,0x8b,0xeb,
0xa7,0xd1,0x68,0x2d,0x1b,0x54,0x59,0x69,
0x3e,0xe3,0x05,0xf7,0x08,0x6d,0xc0,0x84,
0x7b,0xd2,0x9c,0xd6,0x3f,0xcc,0x61,0xf7,
0x68,0x01,0x27,0xaf,0x27,0x68,0xda,0xc1,
0xb1,0xac,0x4e,0x07,0x4b,0x12,0x88,0x99,
0x5b,0x34,0x8a,0x40,0x8b,0x1c,0x9b,0x51,
0x52,0x61,0xf3,0x33,0x5a,0xa1,0xfa,0x52,
0xdf,0x6f,0x78,0x56,0x2c,0x28,0x55,0xda,
0xaf,0x01,0x47,0xc8,0x27,0xe3,0xb0,0xb0,
0xce,0x39,0x25,0x9a,0x69,0x58,0xdc,0x0b,
0x32,0x79,0xd2,0xeb,0xf9,0x83,0xa1,0x0d,
0x1b,0xe2,0xec,0xfd,0xf2,0xd6,0x1e,0xe4,
0x46,0x53,0x67,0xb2,0x85,0xe8,0x97,0xd2,
0xdf,0x48,0x22,0x66,0xe2,0x17,0x58,0xfa,
0x9a,0x6c,0xd8,0x7d,0x05,0x35,0x33,0x3a,
0xe9,0xf1,0x7d,0xd6,0x6c,0x17,0xf1,0xac
};

  /* Allocate buffers, align first two elements to 16 bytes and latter to
     block size.  */
  ctx_aligned_size = context_size + 15;
  ctx_aligned_size -= ctx_aligned_size & 0xf;

  memsize = ctx_aligned_size + (blocksize * 2) + (blocksize * nblocks * 3) + 16;

  mem = xtrycalloc (1, memsize);
  if (!mem)
    return "failed to allocate memory";

  offs = (16 - ((uintptr_t)mem & 15)) & 15;
  ctx = (void*)(mem + offs);
  iv = ctx + ctx_aligned_size;
  iv2 = iv + blocksize;
  plaintext = iv2 + blocksize;
  plaintext2 = plaintext + nblocks * blocksize;
  ciphertext = plaintext2 + nblocks * blocksize;

  /* Initialize ctx */
  if (setkey_func (ctx, key, sizeof(key), &bulk_ops) != GPG_ERR_NO_ERROR)
   {
     xfree(mem);
     return "setkey failed";
   }

  /* Test single block code path */
  memset (iv, 0x4e, blocksize);
  memset (iv2, 0x4e, blocksize);
  for (i = 0; i < blocksize; i++)
    plaintext[i] = i;

  /* CBC manually.  */
  buf_xor (ciphertext, iv, plaintext, blocksize);
  encrypt_one (ctx, ciphertext, ciphertext);
  memcpy (iv, ciphertext, blocksize);

  /* CBC decrypt.  */
  bulk_ops.cbc_dec (ctx, iv2, plaintext2, ciphertext, 1);
  if (memcmp (plaintext2, plaintext, blocksize))
    {
      xfree (mem);
#ifdef HAVE_SYSLOG
      syslog (LOG_USER|LOG_WARNING, "Libgcrypt warning: "
              "%s-CBC-%d test failed (plaintext mismatch)", cipher,
	      blocksize * 8);
#else
      (void)cipher; /* Not used.  */
#endif
      return "selftest for CBC failed - see syslog for details";
    }

  if (memcmp (iv2, iv, blocksize))
    {
      xfree (mem);
#ifdef HAVE_SYSLOG
      syslog (LOG_USER|LOG_WARNING, "Libgcrypt warning: "
              "%s-CBC-%d test failed (IV mismatch)", cipher, blocksize * 8);
#endif
      return "selftest for CBC failed - see syslog for details";
    }

  /* Test parallelized code paths */
  memset (iv, 0x5f, blocksize);
  memset (iv2, 0x5f, blocksize);

  for (i = 0; i < nblocks * blocksize; i++)
    plaintext[i] = i;

  /* Create CBC ciphertext manually.  */
  for (i = 0; i < nblocks * blocksize; i+=blocksize)
    {
      buf_xor (&ciphertext[i], iv, &plaintext[i], blocksize);
      encrypt_one (ctx, &ciphertext[i], &ciphertext[i]);
      memcpy (iv, &ciphertext[i], blocksize);
    }

  if (gcry_fips_request_failure("aes_cbc_128", "encrypt")) {
      ciphertext[0] ^=1;
    }

  if ( memcmp(ciphertext, encrypt_KA, sizeof(encrypt_KA)) != 0 ) {
    KAT_FAILED(0, "AES-CBC-128 encrypt");
    xfree (mem);
    #ifdef HAVE_SYSLOG
      syslog (LOG_USER|LOG_WARNING, "Libgcrypt warning: "
              "%s-CBC-%d test failed (encrypt failed)", cipher, blocksize * 8);
    #endif
      return "selftest for CBC failed - see syslog for details";
  } else {
    KAT_SUCCESS(0, "AES-CBC-128 encrypt");
  }

  /* Decrypt using bulk CBC and compare result.  */
  bulk_ops.cbc_dec (ctx, iv2, plaintext2, ciphertext, nblocks);

  if (strcmp(cipher, "AES") == 0) {
    if (gcry_fips_request_failure("aes_cbc_128", "decrypt")) {
      plaintext2[0] ^=1;
    }
  }
  if (memcmp (plaintext2, plaintext, nblocks * blocksize))
    {
      KAT_FAILED(0, "AES-CBC-128 decrypt");
      xfree (mem);
#ifdef HAVE_SYSLOG
      syslog (LOG_USER|LOG_WARNING, "Libgcrypt warning: "
              "%s-CBC-%d test failed (plaintext mismatch, parallel path)",
	      cipher, blocksize * 8);
#endif
      return "selftest for CBC failed - see syslog for details";
    }
  if (memcmp (iv2, iv, blocksize))
    {
      KAT_FAILED(0, "AES-CBC-128 decrypt");
      xfree (mem);
#ifdef HAVE_SYSLOG
      syslog (LOG_USER|LOG_WARNING, "Libgcrypt warning: "
              "%s-CBC-%d test failed (IV mismatch, parallel path)",
	      cipher, blocksize * 8);
#endif
      return "selftest for CBC failed - see syslog for details";
    }
    if (strcmp(cipher, "AES") == 0) {
      KAT_SUCCESS(0, "AES-CBC-128 decrypt");
    }

  xfree (mem);
  return NULL;
}

/* Run the self-tests for <block cipher>-CFB-<block size>, tests bulk CFB
   decryption.  Returns NULL on success. */
const char *
_gcry_selftest_helper_cfb (const char *cipher, gcry_cipher_setkey_t setkey_func,
			   gcry_cipher_encrypt_t encrypt_one,
			   const int nblocks, const int blocksize,
			   const int context_size)
{
  cipher_bulk_ops_t bulk_ops = { 0, };
  int i, offs;
  unsigned char *ctx, *plaintext, *plaintext2, *ciphertext, *iv, *iv2, *mem;
  unsigned int ctx_aligned_size, memsize;

  static const unsigned char key[16] ATTR_ALIGNED_16 = {
      0x11,0x9A,0x00,0x7F,0xC7,0x6A,0x45,0x9F,
      0x98,0xBA,0xF9,0x17,0xFE,0xDF,0x95,0x33
    };

  /* Allocate buffers, align first two elements to 16 bytes and latter to
     block size.  */
  ctx_aligned_size = context_size + 15;
  ctx_aligned_size -= ctx_aligned_size & 0xf;

  memsize = ctx_aligned_size + (blocksize * 2) + (blocksize * nblocks * 3) + 16;

  mem = xtrycalloc (1, memsize);
  if (!mem)
    return "failed to allocate memory";

  offs = (16 - ((uintptr_t)mem & 15)) & 15;
  ctx = (void*)(mem + offs);
  iv = ctx + ctx_aligned_size;
  iv2 = iv + blocksize;
  plaintext = iv2 + blocksize;
  plaintext2 = plaintext + nblocks * blocksize;
  ciphertext = plaintext2 + nblocks * blocksize;

  /* Initialize ctx */
  if (setkey_func (ctx, key, sizeof(key), &bulk_ops) != GPG_ERR_NO_ERROR)
   {
     xfree(mem);
     return "setkey failed";
   }

  /* Test single block code path */
  memset(iv, 0xd3, blocksize);
  memset(iv2, 0xd3, blocksize);
  for (i = 0; i < blocksize; i++)
    plaintext[i] = i;

  /* CFB manually.  */
  encrypt_one (ctx, ciphertext, iv);
  buf_xor_2dst (iv, ciphertext, plaintext, blocksize);

  /* CFB decrypt.  */
  bulk_ops.cfb_dec (ctx, iv2, plaintext2, ciphertext, 1);
  if (memcmp(plaintext2, plaintext, blocksize))
    {
      xfree(mem);
#ifdef HAVE_SYSLOG
      syslog (LOG_USER|LOG_WARNING, "Libgcrypt warning: "
              "%s-CFB-%d test failed (plaintext mismatch)", cipher,
	      blocksize * 8);
#else
      (void)cipher; /* Not used.  */
#endif
      return "selftest for CFB failed - see syslog for details";
    }

  if (memcmp(iv2, iv, blocksize))
    {
      xfree(mem);
#ifdef HAVE_SYSLOG
      syslog (LOG_USER|LOG_WARNING, "Libgcrypt warning: "
              "%s-CFB-%d test failed (IV mismatch)", cipher, blocksize * 8);
#endif
      return "selftest for CFB failed - see syslog for details";
    }

  /* Test parallelized code paths */
  memset(iv, 0xe6, blocksize);
  memset(iv2, 0xe6, blocksize);

  for (i = 0; i < nblocks * blocksize; i++)
    plaintext[i] = i;

  /* Create CFB ciphertext manually.  */
  for (i = 0; i < nblocks * blocksize; i+=blocksize)
    {
      encrypt_one (ctx, &ciphertext[i], iv);
      buf_xor_2dst (iv, &ciphertext[i], &plaintext[i], blocksize);
    }

  /* Decrypt using bulk CBC and compare result.  */
  bulk_ops.cfb_dec (ctx, iv2, plaintext2, ciphertext, nblocks);

  if (memcmp(plaintext2, plaintext, nblocks * blocksize))
    {
      xfree(mem);
#ifdef HAVE_SYSLOG
      syslog (LOG_USER|LOG_WARNING, "Libgcrypt warning: "
              "%s-CFB-%d test failed (plaintext mismatch, parallel path)",
              cipher, blocksize * 8);
#endif
      return "selftest for CFB failed - see syslog for details";
    }
  if (memcmp(iv2, iv, blocksize))
    {
      xfree(mem);
#ifdef HAVE_SYSLOG
      syslog (LOG_USER|LOG_WARNING, "Libgcrypt warning: "
              "%s-CFB-%d test failed (IV mismatch, parallel path)", cipher,
	      blocksize * 8);
#endif
      return "selftest for CFB failed - see syslog for details";
    }

  xfree(mem);
  return NULL;
}

/* Run the self-tests for <block cipher>-CTR-<block size>, tests IV increment
   of bulk CTR encryption.  Returns NULL on success. */
const char *
_gcry_selftest_helper_ctr (const char *cipher, gcry_cipher_setkey_t setkey_func,
			   gcry_cipher_encrypt_t encrypt_one,
			   const int nblocks, const int blocksize,
			   const int context_size)
{
  cipher_bulk_ops_t bulk_ops = { 0, };
  int i, j, offs, diff;
  unsigned char *ctx, *plaintext, *plaintext2, *ciphertext, *ciphertext2,
                *iv, *iv2, *mem;
  unsigned int ctx_aligned_size, memsize;

  static const unsigned char key[16] ATTR_ALIGNED_16 = {
      0x06,0x9A,0x00,0x7F,0xC7,0x6A,0x45,0x9F,
      0x98,0xBA,0xF9,0x17,0xFE,0xDF,0x95,0x21
    };

  /* Allocate buffers, align first two elements to 16 bytes and latter to
     block size.  */
  ctx_aligned_size = context_size + 15;
  ctx_aligned_size -= ctx_aligned_size & 0xf;

  memsize = ctx_aligned_size + (blocksize * 2) + (blocksize * nblocks * 4) + 16;

  mem = xtrycalloc (1, memsize);
  if (!mem)
    return "failed to allocate memory";

  offs = (16 - ((uintptr_t)mem & 15)) & 15;
  ctx = (void*)(mem + offs);
  iv = ctx + ctx_aligned_size;
  iv2 = iv + blocksize;
  plaintext = iv2 + blocksize;
  plaintext2 = plaintext + nblocks * blocksize;
  ciphertext = plaintext2 + nblocks * blocksize;
  ciphertext2 = ciphertext + nblocks * blocksize;

  /* Initialize ctx */
  if (setkey_func (ctx, key, sizeof(key), &bulk_ops) != GPG_ERR_NO_ERROR)
   {
     xfree(mem);
     return "setkey failed";
   }

  /* Test single block code path */
  memset (iv, 0xff, blocksize);
  for (i = 0; i < blocksize; i++)
    plaintext[i] = i;

  /* CTR manually.  */
  encrypt_one (ctx, ciphertext, iv);
  for (i = 0; i < blocksize; i++)
    ciphertext[i] ^= plaintext[i];
  for (i = blocksize; i > 0; i--)
    {
      iv[i-1]++;
      if (iv[i-1])
        break;
    }

  memset (iv2, 0xff, blocksize);
  bulk_ops.ctr_enc (ctx, iv2, plaintext2, ciphertext, 1);

  if (memcmp (plaintext2, plaintext, blocksize))
    {
      xfree (mem);
#ifdef HAVE_SYSLOG
      syslog (LOG_USER|LOG_WARNING, "Libgcrypt warning: "
              "%s-CTR-%d test failed (plaintext mismatch)", cipher,
	      blocksize * 8);
#else
      (void)cipher; /* Not used.  */
#endif
      return "selftest for CTR failed - see syslog for details";
    }

  if (memcmp (iv2, iv, blocksize))
    {
      xfree (mem);
#ifdef HAVE_SYSLOG
      syslog (LOG_USER|LOG_WARNING, "Libgcrypt warning: "
              "%s-CTR-%d test failed (IV mismatch)", cipher,
	      blocksize * 8);
#endif
      return "selftest for CTR failed - see syslog for details";
    }

  /* Test bulk encryption with typical IV. */
  memset(iv, 0x57, blocksize-4);
  iv[blocksize-1] = 1;
  iv[blocksize-2] = 0;
  iv[blocksize-3] = 0;
  iv[blocksize-4] = 0;
  memset(iv2, 0x57, blocksize-4);
  iv2[blocksize-1] = 1;
  iv2[blocksize-2] = 0;
  iv2[blocksize-3] = 0;
  iv2[blocksize-4] = 0;

  for (i = 0; i < blocksize * nblocks; i++)
    plaintext2[i] = plaintext[i] = i;

  /* Create CTR ciphertext manually.  */
  for (i = 0; i < blocksize * nblocks; i+=blocksize)
    {
      encrypt_one (ctx, &ciphertext[i], iv);
      for (j = 0; j < blocksize; j++)
        ciphertext[i+j] ^= plaintext[i+j];
      for (j = blocksize; j > 0; j--)
        {
          iv[j-1]++;
          if (iv[j-1])
            break;
        }
    }

  bulk_ops.ctr_enc (ctx, iv2, ciphertext2, plaintext2, nblocks);

  if (memcmp (ciphertext2, ciphertext, blocksize * nblocks))
    {
      xfree (mem);
#ifdef HAVE_SYSLOG
      syslog (LOG_USER|LOG_WARNING, "Libgcrypt warning: "
              "%s-CTR-%d test failed (ciphertext mismatch, bulk)", cipher,
              blocksize * 8);
#endif
      return "selftest for CTR failed - see syslog for details";
    }
  if (memcmp(iv2, iv, blocksize))
    {
      xfree (mem);
#ifdef HAVE_SYSLOG
      syslog (LOG_USER|LOG_WARNING, "Libgcrypt warning: "
              "%s-CTR-%d test failed (IV mismatch, bulk)", cipher,
              blocksize * 8);
#endif
      return "selftest for CTR failed - see syslog for details";
    }

  /* Test parallelized code paths (check counter overflow handling) */
  for (diff = 0; diff < nblocks; diff++) {
    memset(iv, 0xff, blocksize);
    iv[blocksize-1] -= diff;
    iv[0] = iv[1] = 0;
    iv[2] = 0x07;

    for (i = 0; i < blocksize * nblocks; i++)
      plaintext[i] = i;

    /* Create CTR ciphertext manually.  */
    for (i = 0; i < blocksize * nblocks; i+=blocksize)
      {
        encrypt_one (ctx, &ciphertext[i], iv);
        for (j = 0; j < blocksize; j++)
          ciphertext[i+j] ^= plaintext[i+j];
        for (j = blocksize; j > 0; j--)
          {
            iv[j-1]++;
            if (iv[j-1])
              break;
          }
      }

    /* Decrypt using bulk CTR and compare result.  */
    memset(iv2, 0xff, blocksize);
    iv2[blocksize-1] -= diff;
    iv2[0] = iv2[1] = 0;
    iv2[2] = 0x07;

    bulk_ops.ctr_enc (ctx, iv2, plaintext2, ciphertext, nblocks);

    if (memcmp (plaintext2, plaintext, blocksize * nblocks))
      {
        xfree (mem);
#ifdef HAVE_SYSLOG
        syslog (LOG_USER|LOG_WARNING, "Libgcrypt warning: "
                "%s-CTR-%d test failed (plaintext mismatch, diff: %d)", cipher,
		blocksize * 8, diff);
#endif
        return "selftest for CTR failed - see syslog for details";
      }
    if (memcmp(iv2, iv, blocksize))
      {
        xfree (mem);
#ifdef HAVE_SYSLOG
        syslog (LOG_USER|LOG_WARNING, "Libgcrypt warning: "
                "%s-CTR-%d test failed (IV mismatch, diff: %d)", cipher,
		blocksize * 8, diff);
#endif
        return "selftest for CTR failed - see syslog for details";
      }
  }

  xfree (mem);
  return NULL;
}
