/* Copyright (c) 2024, Hubert Kario, Red Hat
 * Released under BSD 2-Clause License, see LICENSE for details
 */
#include <config.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#include <string.h>
#include "mpi-internal.h"
#include "longlong.h"

/* For multiplication we're using schoolbook multiplication,
 * so if we have two numbers, each with 6 "digits" (words)
 * the multiplication is calculated as follows:
 *                        A B C D E F
 *                     x  I J K L M N
 *                     --------------
 *                                N*F
 *                              N*E
 *                            N*D
 *                          N*C
 *                        N*B
 *                      N*A
 *                              M*F
 *                            M*E
 *                          M*D
 *                        M*C
 *                      M*B
 *                    M*A
 *                            L*F
 *                          L*E
 *                        L*D
 *                      L*C
 *                    L*B
 *                  L*A
 *                          K*F
 *                        K*E
 *                      K*D
 *                    K*C
 *                  K*B
 *                K*A
 *                        J*F
 *                      J*E
 *                    J*D
 *                  J*C
 *                J*B
 *              J*A
 *                      I*F
 *                    I*E
 *                  I*D
 *                I*C
 *              I*B
 *         +  I*A
 *         ==========================
 *                        N*B N*D N*F
 *                    + N*A N*C N*E
 *                    + M*B M*D M*F
 *                  + M*A M*C M*E
 *                  + L*B L*D L*F
 *                + L*A L*C L*E
 *                + K*B K*D K*F
 *              + K*A K*C K*E
 *              + J*B J*D J*F
 *            + J*A J*C J*E
 *            + I*B I*D I*F
 *          + I*A I*C I*E
 *
 *                1+1 1+3 1+5
 *              1+0 1+2 1+4
 *              0+1 0+3 0+5
 *            0+0 0+2 0+4
 *
 *            0 1 2 3 4 5 6
 * which requires n^2 multiplications and 2n full length additions
 * as we can keep every other result of limb multiplication in two separate
 * limbs
 */

typedef mpi_limb_t limb_t;
#if BYTES_PER_MPI_LIMB == SIZEOF_UNSIGNED_LONG_LONG
#define LIMB_BIT_SIZE 64
#define LIMB_BYTE_SIZE 8
#elif BYTES_PER_MPI_LIMB == SIZEOF_UNSIGNED_LONG
#define LIMB_BIT_SIZE 32
#define LIMB_BYTE_SIZE 4
/* if we're on a 32 bit platform */
#else
#define LIMB_BIT_SIZE 16
#define LIMB_BYTE_SIZE 2
/*
 * if the compiler doesn't have either a 128bit data type nor a "return
 * high 64 bits of multiplication"
 */
#endif

/* add two limbs with carry in, return carry out */
static limb_t
_add_limb (limb_t *ret, limb_t a, limb_t b, limb_t carry)
{
  limb_t carry1, carry2, t;
  add_ssaaaa (carry1, t, 0, a, 0, carry);
  add_ssaaaa (carry2, t, 0, b, 0, t);
  *ret = t;
  return carry1 + carry2;
}

/* add two numbers of the same size, return overflow
 *
 * add a to b, place result in ret; all arrays need to be n limbs long
 * return overflow from addition (0 or 1)
 */
static limb_t
add (limb_t *ret, limb_t *a, limb_t *b, size_t n)
{
  limb_t c = 0;
  for (ssize_t i = n - 1; i > -1; i--)
    {
      c = _add_limb (&ret[i], a[i], b[i], c);
    }
  return c;
}

/* multiply two numbers of the same size
 *
 * multiply a by b, place result in ret; a and b need to be n limbs long
 * ret needs to be 2*n limbs long, tmp needs to be 2 * n 2 limbs
 * long
 */
void
mul_cs (limb_t *ret, limb_t *a, limb_t *b, size_t n, limb_t *tmp)
{
  limb_t *r_odd, *r_even;
  r_odd = tmp;
  r_even = &tmp[2 * n];

  for (size_t i = 0; i < 2 * n; i++)
    {
      ret[i] = 0;
    }

  for (size_t i=0; i<n; i++)
    {
      for (size_t k=0; k<i+n+1; k++)
        {
          r_even[k] = 0;
          r_odd[k] = 0;
        }
      for (size_t j=0; j<n; j++)
        {
          /* place results from even and odd limbs in separate arrays so that
           * we don't have to calculate overflow every time we get individual
           * limb multiplication result */
          if (j % 2 == 0)
            {
              umul_ppmm (r_even[i+j], r_even[i+j+1], a[i], b[j]);
            }
          else
            {
              umul_ppmm (r_odd[i+j], r_odd[i+j+1], a[i], b[j]);
            }
        }
      /* skip the least significant limbs when adding multiples of
       * more significant limbs (they're zero anyway) */
      add (ret, ret, r_even, n+i+1);
      add (ret, ret, r_odd, n+i+1);
    }
}

/* modifies the value in place by performing a right shift by one bit */
static void
rshift1 (limb_t *val, size_t n)
{
  limb_t shift_in = 0, shift_out = 0;
  for (size_t i = 0; i < n; i++)
    {
      shift_out = val[i] & 1;
      val[i] = shift_in << (LIMB_BIT_SIZE-1) | (val[i] >> 1);
      shift_in = shift_out;
    }
}

/* copy from either a or b to ret based on flag
 * when flag == 0, then copies from b
 * when flag == 1, then copies from a
 */
static void
cselect (limb_t flag, limb_t *ret, limb_t *a, limb_t *b, size_t n)
{
  /* would be more efficient with non volatile mask, but then gcc
   * generates code with jumps */
  limb_t mask1 = ct_limb_gen_mask (flag);
  limb_t mask2 = ct_limb_gen_inv_mask (flag);
  for (size_t i = 0; i < n; i++)
    {
      ret[i] = (mask1 & a[i]) | (mask2 & b[i]);
    }
}

static limb_t
_sub_limb (limb_t *ret, limb_t a, limb_t b, limb_t borrow)
{
  limb_t borrow1, borrow2, t;
  sub_ddmmss (borrow1, t, 0, a, 0, borrow);
  sub_ddmmss (borrow2, t, 0, t, 0, b);
  *ret = t;
  return -(borrow1 + borrow2);
}

/* place the result of a - b into ret, return the borrow bit.
 * All arrays need to be n limbs long
 */
static limb_t
sub (limb_t *ret, limb_t *a, limb_t *b, size_t n)
{
  limb_t borrow = 0;
  for (ssize_t i=n-1; i>-1; i--)
    {
      borrow = _sub_limb (&ret[i], a[i], b[i], borrow);
    }
  return borrow;
}

/* return the number of limbs necessary to allocate for the mod() tmp operand */
size_t
mod_limb_numb (size_t anum, size_t modnum)
{
    return (anum + modnum) * 3;
}

/* calculate a % mod, place the result in ret
 * size of a is defined by anum, size of ret and mod is modnum,
 * size of tmp is returned by mod_limb_numb()
 */
void
mod_cs (limb_t *ret, limb_t *a, size_t anum, limb_t *mod, size_t modnum, limb_t *tmp)
{
  limb_t *atmp, *modtmp, *rettmp;
  limb_t res;

  memset (tmp, 0, mod_limb_numb(anum, modnum) * LIMB_BYTE_SIZE);

  atmp = tmp;
  modtmp = &tmp[anum+modnum];
  rettmp = &tmp[(anum+modnum)*2];

  for (size_t i=modnum; i<modnum+anum; i++)
    {
      atmp[i] = a[i-modnum];
    }
  for (size_t i=0; i<modnum; i++)
    {
      modtmp[i] = mod[i];
    }

  for (size_t i=0; i<anum*LIMB_BIT_SIZE; i++)
    {
      rshift1 (modtmp, anum+modnum);
      res = sub (rettmp, atmp, modtmp, anum+modnum);
      cselect (res, atmp, atmp, rettmp, anum+modnum);
    }

  memcpy (ret, &atmp[anum], sizeof(limb_t)*modnum);
}
