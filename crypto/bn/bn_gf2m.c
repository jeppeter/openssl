/*
 * Copyright 2002-2021 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2002, Oracle and/or its affiliates. All rights reserved
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include "internal/cryptlib.h"
#include "bn_local.h"
#include "internal/intern_log.h"

#ifndef OPENSSL_NO_EC2M

/*
 * Maximum number of iterations before BN_GF2m_mod_solve_quad_arr should
 * fail.
 */
# define MAX_ITERATIONS 50

# define SQR_nibble(w)   ((((w) & 8) << 3) \
                       |  (((w) & 4) << 2) \
                       |  (((w) & 2) << 1) \
                       |   ((w) & 1))


/* Platform-specific macros to accelerate squaring. */
# if defined(SIXTY_FOUR_BIT) || defined(SIXTY_FOUR_BIT_LONG)
#  define SQR1(w) \
    SQR_nibble((w) >> 60) << 56 | SQR_nibble((w) >> 56) << 48 | \
    SQR_nibble((w) >> 52) << 40 | SQR_nibble((w) >> 48) << 32 | \
    SQR_nibble((w) >> 44) << 24 | SQR_nibble((w) >> 40) << 16 | \
    SQR_nibble((w) >> 36) <<  8 | SQR_nibble((w) >> 32)
#  define SQR0(w) \
    SQR_nibble((w) >> 28) << 56 | SQR_nibble((w) >> 24) << 48 | \
    SQR_nibble((w) >> 20) << 40 | SQR_nibble((w) >> 16) << 32 | \
    SQR_nibble((w) >> 12) << 24 | SQR_nibble((w) >>  8) << 16 | \
    SQR_nibble((w) >>  4) <<  8 | SQR_nibble((w)      )
# endif
# ifdef THIRTY_TWO_BIT
#  define SQR1(w) \
    SQR_nibble((w) >> 28) << 24 | SQR_nibble((w) >> 24) << 16 | \
    SQR_nibble((w) >> 20) <<  8 | SQR_nibble((w) >> 16)
#  define SQR0(w) \
    SQR_nibble((w) >> 12) << 24 | SQR_nibble((w) >>  8) << 16 | \
    SQR_nibble((w) >>  4) <<  8 | SQR_nibble((w)      )
# endif

# if !defined(OPENSSL_BN_ASM_GF2m)
/*
 * Product of two polynomials a, b each with degree < BN_BITS2 - 1, result is
 * a polynomial r with degree < 2 * BN_BITS - 1 The caller MUST ensure that
 * the variables have the right amount of space allocated.
 */
#  ifdef THIRTY_TWO_BIT
static void bn_GF2m_mul_1x1(BN_ULONG *r1, BN_ULONG *r0, const BN_ULONG a,
                            const BN_ULONG b)
{
    register BN_ULONG h, l, s;
    BN_ULONG tab[8], top2b = a >> 30;
    register BN_ULONG a1, a2, a4;

    a1 = a & (0x3FFFFFFF);
    a2 = a1 << 1;
    a4 = a2 << 1;

    tab[0] = 0;
    tab[1] = a1;
    tab[2] = a2;
    tab[3] = a1 ^ a2;
    tab[4] = a4;
    tab[5] = a1 ^ a4;
    tab[6] = a2 ^ a4;
    tab[7] = a1 ^ a2 ^ a4;

    s = tab[b & 0x7];
    l = s;
    s = tab[b >> 3 & 0x7];
    l ^= s << 3;
    h = s >> 29;
    s = tab[b >> 6 & 0x7];
    l ^= s << 6;
    h ^= s >> 26;
    s = tab[b >> 9 & 0x7];
    l ^= s << 9;
    h ^= s >> 23;
    s = tab[b >> 12 & 0x7];
    l ^= s << 12;
    h ^= s >> 20;
    s = tab[b >> 15 & 0x7];
    l ^= s << 15;
    h ^= s >> 17;
    s = tab[b >> 18 & 0x7];
    l ^= s << 18;
    h ^= s >> 14;
    s = tab[b >> 21 & 0x7];
    l ^= s << 21;
    h ^= s >> 11;
    s = tab[b >> 24 & 0x7];
    l ^= s << 24;
    h ^= s >> 8;
    s = tab[b >> 27 & 0x7];
    l ^= s << 27;
    h ^= s >> 5;
    s = tab[b >> 30];
    l ^= s << 30;
    h ^= s >> 2;

    /* compensate for the top two bits of a */

    if (top2b & 01) {
        l ^= b << 30;
        h ^= b >> 2;
    }
    if (top2b & 02) {
        l ^= b << 31;
        h ^= b >> 1;
    }

    *r1 = h;
    *r0 = l;
}
#  endif
#  if defined(SIXTY_FOUR_BIT) || defined(SIXTY_FOUR_BIT_LONG)
static void bn_GF2m_mul_1x1(BN_ULONG *r1, BN_ULONG *r0, const BN_ULONG a,
                            const BN_ULONG b)
{
    register BN_ULONG h, l, s;
    BN_ULONG tab[16], top3b = a >> 61;
    register BN_ULONG a1, a2, a4, a8;

    a1 = a & (0x1FFFFFFFFFFFFFFFULL);
    a2 = a1 << 1;
    a4 = a2 << 1;
    a8 = a4 << 1;

    tab[0] = 0;
    tab[1] = a1;
    tab[2] = a2;
    tab[3] = a1 ^ a2;
    tab[4] = a4;
    tab[5] = a1 ^ a4;
    tab[6] = a2 ^ a4;
    tab[7] = a1 ^ a2 ^ a4;
    tab[8] = a8;
    tab[9] = a1 ^ a8;
    tab[10] = a2 ^ a8;
    tab[11] = a1 ^ a2 ^ a8;
    tab[12] = a4 ^ a8;
    tab[13] = a1 ^ a4 ^ a8;
    tab[14] = a2 ^ a4 ^ a8;
    tab[15] = a1 ^ a2 ^ a4 ^ a8;

    s = tab[b & 0xF];
    l = s;
    OSSL_DEBUG("l 0x%x", l);

    s = tab[b >> 4 & 0xF];
    l ^= s << 4;
    h = s >> 60;
    OSSL_DEBUG("%d l 0x%x h 0x%x",4,l,h);

    s = tab[b >> 8 & 0xF];
    l ^= s << 8;
    h ^= s >> 56;
    OSSL_DEBUG("%d l 0x%x h 0x%x",8,l,h);

    s = tab[b >> 12 & 0xF];
    l ^= s << 12;
    h ^= s >> 52;
    OSSL_DEBUG("%d l 0x%x h 0x%x",12,l,h);

    s = tab[b >> 16 & 0xF];
    l ^= s << 16;
    h ^= s >> 48;
    OSSL_DEBUG("%d l 0x%x h 0x%x",16,l,h);

    s = tab[b >> 20 & 0xF];
    l ^= s << 20;
    h ^= s >> 44;
    OSSL_DEBUG("%d l 0x%x h 0x%x",20,l,h);
    
    s = tab[b >> 24 & 0xF];
    l ^= s << 24;
    h ^= s >> 40;
    OSSL_DEBUG("%d l 0x%x h 0x%x",24,l,h);
    
    s = tab[b >> 28 & 0xF];
    l ^= s << 28;
    h ^= s >> 36;
    OSSL_DEBUG("%d l 0x%x h 0x%x",28,l,h);
    
    s = tab[b >> 32 & 0xF];
    l ^= s << 32;
    h ^= s >> 32;
    OSSL_DEBUG("%d l 0x%x h 0x%x",32,l,h);
    
    s = tab[b >> 36 & 0xF];
    l ^= s << 36;
    h ^= s >> 28;
    OSSL_DEBUG("%d l 0x%x h 0x%x",36,l,h);
    
    s = tab[b >> 40 & 0xF];
    l ^= s << 40;
    h ^= s >> 24;
    OSSL_DEBUG("%d l 0x%x h 0x%x",40,l,h);
    
    s = tab[b >> 44 & 0xF];
    l ^= s << 44;
    h ^= s >> 20;
    OSSL_DEBUG("%d l 0x%x h 0x%x",44,l,h);
    
    s = tab[b >> 48 & 0xF];
    l ^= s << 48;
    h ^= s >> 16;
    OSSL_DEBUG("%d l 0x%x h 0x%x",48,l,h);
    
    s = tab[b >> 52 & 0xF];
    l ^= s << 52;
    h ^= s >> 12;
    OSSL_DEBUG("%d l 0x%x h 0x%x",52,l,h);
    
    s = tab[b >> 56 & 0xF];
    l ^= s << 56;
    h ^= s >> 8;
    OSSL_DEBUG("%d l 0x%x h 0x%x",56,l,h);
    
    s = tab[b >> 60];
    l ^= s << 60;
    h ^= s >> 4;
    OSSL_DEBUG("%d l 0x%x h 0x%x",60,l,h);
    

    /* compensate for the top three bits of a */

    if (top3b & 01) {
        l ^= b << 61;
        h ^= b >> 3;
    }
    if (top3b & 02) {
        l ^= b << 62;
        h ^= b >> 2;
    }
    if (top3b & 04) {
        l ^= b << 63;
        h ^= b >> 1;
    }

    *r1 = h;
    *r0 = l;
}
#  endif

/*
 * Product of two polynomials a, b each with degree < 2 * BN_BITS2 - 1,
 * result is a polynomial r with degree < 4 * BN_BITS2 - 1 The caller MUST
 * ensure that the variables have the right amount of space allocated.
 */
static void bn_GF2m_mul_2x2(BN_ULONG *r, const BN_ULONG a1, const BN_ULONG a0,
                            const BN_ULONG b1, const BN_ULONG b0)
{
    BN_ULONG m1, m0;
    /* r[3] = h1, r[2] = h0; r[1] = l1; r[0] = l0 */
    bn_GF2m_mul_1x1(r + 3, r + 2, a1, b1);
    bn_GF2m_mul_1x1(r + 1, r, a0, b0);
    bn_GF2m_mul_1x1(&m1, &m0, a0 ^ a1, b0 ^ b1);
    /* Correction on m1 ^= l1 ^ h1; m0 ^= l0 ^ h0; */
    r[2] ^= m1 ^ r[1] ^ r[3];   /* h0 ^= m1 ^ l1 ^ h1; */
    r[1] = r[3] ^ r[2] ^ r[0] ^ m1 ^ m0; /* l1 ^= l0 ^ h0 ^ m0; */
}
# else

/*bn_GF2m_mul_2x2 SET */
#if 1
void bn_GF2m_mul_2x2(BN_ULONG *r, BN_ULONG a1, BN_ULONG a0, BN_ULONG b1,
                     BN_ULONG b0);
#else
static void bn_GF2m_mul_1x1(BN_ULONG *r1, BN_ULONG *r0, const BN_ULONG a,
                            const BN_ULONG b)
{
    register BN_ULONG h, l, s;
    BN_ULONG tab[16], top3b = a >> 61;
    register BN_ULONG a1, a2, a4, a8;
    int i;

    a1 = a & (0x1FFFFFFFFFFFFFFFULL);
    a2 = a1 << 1;
    a4 = a2 << 1;
    a8 = a4 << 1;

    tab[0] = 0;
    tab[1] = a1;
    tab[2] = a2;
    tab[3] = a1 ^ a2;
    tab[4] = a4;
    tab[5] = a1 ^ a4;
    tab[6] = a2 ^ a4;
    tab[7] = a1 ^ a2 ^ a4;
    tab[8] = a8;
    tab[9] = a1 ^ a8;
    tab[10] = a2 ^ a8;
    tab[11] = a1 ^ a2 ^ a8;
    tab[12] = a4 ^ a8;
    tab[13] = a1 ^ a4 ^ a8;
    tab[14] = a2 ^ a4 ^ a8;
    tab[15] = a1 ^ a2 ^ a4 ^ a8;

    for(i=0;i<16;i++) {
        //OSSL_DEBUG("tab[%d]=[0x%lx]",i,tab[i]);
    }

    OSSL_DEBUG("a 0x%lx b 0x%lx", a,b);

    s = tab[b & 0xF];
    l = s;
    //OSSL_DEBUG("l 0x%lx", l);

    s = tab[b >> 4 & 0xF];
    l ^= s << 4;
    h = s >> 60;
    //OSSL_DEBUG("%d l 0x%lx h 0x%lx",4,l,h);

    s = tab[b >> 8 & 0xF];
    l ^= s << 8;
    h ^= s >> 56;
    //OSSL_DEBUG("%d l 0x%lx h 0x%lx",8,l,h);

    s = tab[b >> 12 & 0xF];
    l ^= s << 12;
    h ^= s >> 52;
    //OSSL_DEBUG("%d l 0x%lx h 0x%lx",12,l,h);

    s = tab[b >> 16 & 0xF];
    l ^= s << 16;
    h ^= s >> 48;
    //OSSL_DEBUG("%d l 0x%lx h 0x%lx",16,l,h);

    s = tab[b >> 20 & 0xF];
    l ^= s << 20;
    h ^= s >> 44;
    //OSSL_DEBUG("%d l 0x%lx h 0x%lx",20,l,h);
    
    s = tab[b >> 24 & 0xF];
    l ^= s << 24;
    h ^= s >> 40;
    //OSSL_DEBUG("%d l 0x%lx h 0x%lx",24,l,h);
    
    s = tab[b >> 28 & 0xF];
    l ^= s << 28;
    h ^= s >> 36;
    //OSSL_DEBUG("%d l 0x%lx h 0x%lx",28,l,h);
    
    s = tab[b >> 32 & 0xF];
    l ^= s << 32;
    h ^= s >> 32;
    //OSSL_DEBUG("%d l 0x%lx h 0x%lx",32,l,h);
    
    s = tab[b >> 36 & 0xF];
    l ^= s << 36;
    h ^= s >> 28;
    //OSSL_DEBUG("%d l 0x%lx h 0x%lx",36,l,h);
    
    s = tab[b >> 40 & 0xF];
    l ^= s << 40;
    h ^= s >> 24;
    //OSSL_DEBUG("%d l 0x%lx h 0x%lx",40,l,h);
    
    s = tab[b >> 44 & 0xF];
    l ^= s << 44;
    h ^= s >> 20;
    //OSSL_DEBUG("%d l 0x%lx h 0x%lx",44,l,h);
    
    s = tab[b >> 48 & 0xF];
    l ^= s << 48;
    h ^= s >> 16;
    //OSSL_DEBUG("%d l 0x%lx h 0x%lx",48,l,h);
    
    s = tab[b >> 52 & 0xF];
    l ^= s << 52;
    h ^= s >> 12;
    //OSSL_DEBUG("%d l 0x%lx h 0x%lx",52,l,h);
    
    s = tab[b >> 56 & 0xF];
    l ^= s << 56;
    h ^= s >> 8;
    //OSSL_DEBUG("%d l 0x%lx h 0x%lx",56,l,h);
    
    s = tab[b >> 60];
    l ^= s << 60;
    h ^= s >> 4;
    //OSSL_DEBUG("%d l 0x%lx h 0x%lx",60,l,h);
    

    /* compensate for the top three bits of a */

    if (top3b & 01) {
        l ^= b << 61;
        h ^= b >> 3;
    }
    if (top3b & 02) {
        l ^= b << 62;
        h ^= b >> 2;
    }
    if (top3b & 04) {
        l ^= b << 63;
        h ^= b >> 1;
    }

    *r1 = h;
    *r0 = l;
    OSSL_DEBUG("h 0x%lx l 0x%lx",h,l);
}


/*
 * Product of two polynomials a, b each with degree < 2 * BN_BITS2 - 1,
 * result is a polynomial r with degree < 4 * BN_BITS2 - 1 The caller MUST
 * ensure that the variables have the right amount of space allocated.
 */
static void bn_GF2m_mul_2x2(BN_ULONG *r, const BN_ULONG a1, const BN_ULONG a0,
                            const BN_ULONG b1, const BN_ULONG b0)
{
    BN_ULONG m1, m0;
    OSSL_DEBUG("x0 0x%lx x1 0x%lx y0 0x%lx y1 0x%lx",a0,a1,b0,b1);
    /* r[3] = h1, r[2] = h0; r[1] = l1; r[0] = l0 */
    bn_GF2m_mul_1x1(r + 3, r + 2, a1, b1);
    OSSL_DEBUG("r[3] 0x%lx r[2] 0x%lx", r[3],r[2]);
    bn_GF2m_mul_1x1(r + 1, r, a0, b0);
    OSSL_DEBUG("r[1] 0x%lx r[0] 0x%lx", r[1],r[0]);
    bn_GF2m_mul_1x1(&m1, &m0, a0 ^ a1, b0 ^ b1);
    OSSL_DEBUG("m1 0x%lx m0 0x%lx", m1,m0);
    /* Correction on m1 ^= l1 ^ h1; m0 ^= l0 ^ h0; */
    r[2] ^= m1 ^ r[1] ^ r[3];   /* h0 ^= m1 ^ l1 ^ h1; */
    r[1] = r[3] ^ r[2] ^ r[0] ^ m1 ^ m0; /* l1 ^= l0 ^ h0 ^ m0; */
    OSSL_DEBUG("retv 0x%lx 0x%lx 0x%lx 0x%lx",r[3],r[2],r[1],r[0]);
}

#endif

# endif

/*
 * Add polynomials a and b and store result in r; r could be a or b, a and b
 * could be equal; r is the bitwise XOR of a and b.
 */
int BN_GF2m_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b)
{
    int i;
    const BIGNUM *at, *bt;

    bn_check_top(a);
    bn_check_top(b);

    if (a->top < b->top) {
        at = b;
        bt = a;
    } else {
        at = a;
        bt = b;
    }

    if (bn_wexpand(r, at->top) == NULL)
        return 0;

    for (i = 0; i < bt->top; i++) {
        r->d[i] = at->d[i] ^ bt->d[i];
    }
    for (; i < at->top; i++) {
        r->d[i] = at->d[i];
    }

    r->top = at->top;
    bn_correct_top(r);

    return 1;
}

/*-
 * Some functions allow for representation of the irreducible polynomials
 * as an int[], say p.  The irreducible f(t) is then of the form:
 *     t^p[0] + t^p[1] + ... + t^p[k]
 * where m = p[0] > p[1] > ... > p[k] = 0.
 */

/* Performs modular reduction of a and store result in r.  r could be a. */
int BN_GF2m_mod_arr(BIGNUM *r, const BIGNUM *a, const int p[])
{
    int j, k;
    int n, dN, d0, d1;
    BN_ULONG zz, *z;

    bn_check_top(a);

    if (p[0] == 0) {
        /* reduction mod 1 => return 0 */
        BN_zero(r);
        return 1;
    }

    /*
     * Since the algorithm does reduction in the r value, if a != r, copy the
     * contents of a into r so we can do reduction in r.
     */
    if (a != r) {
        if (!bn_wexpand(r, a->top))
            return 0;
        for (j = 0; j < a->top; j++) {
            r->d[j] = a->d[j];
        }
        r->top = a->top;
    }
    z = r->d;

    /* start reduction */
    dN = p[0] / BN_BITS2;
    for (j = r->top - 1; j > dN;) {
        zz = z[j];
        if (z[j] == 0) {
            //OSSL_DEBUG("[%d] 0",j);
            j--;
            continue;
        }
        z[j] = 0;

        for (k = 1; p[k] != 0; k++) {
            /* reducing component t^p[k] */
            n = p[0] - p[k];
            //OSSL_DEBUG("p[0] %d - p[%d] %d = %d",p[0],k,p[k],n);
            d0 = n % BN_BITS2;
            d1 = BN_BITS2 - d0;
            n /= BN_BITS2;
            //OSSL_DEBUG("z[%d] (0x%lx) ^ (0x%lx >> %d) = 0x%lx", j-n,z[j-n],zz,d0,z[j-n] ^ (zz >> d0));
            z[j - n] ^= (zz >> d0);
            if (d0){
                //OSSL_DEBUG("z[%d] (0x%lx) ^ (0x%lx << %d) = 0x%lx", j-n-1,z[j-n-1],zz,d1,z[j-n - 1] ^ (zz << d1));
                z[j - n - 1] ^= (zz << d1);
            }
            //OSSL_DEBUG("p[%d+1] = %d", k,p[k+1]);
        }

        /* reducing component t^0 */
        n = dN;
        d0 = p[0] % BN_BITS2;
        d1 = BN_BITS2 - d0;
        //OSSL_DEBUG("z[%d] (0x%lx) ^ (0x%lx >> %d) = 0x%lx", j-n,z[j-n],zz,d0,z[j-n] ^ (zz >> d0));
        z[j - n] ^= (zz >> d0);
        if (d0){
            //OSSL_DEBUG("z[%d] (0x%lx) ^ (0x%lx << %d) = 0x%lx", j-n-1,z[j-n-1],zz,d1,z[j-n - 1] ^ (zz << d1));
            z[j - n - 1] ^= (zz << d1);
        }
    }

    /* final round of reduction */
    while (j == dN) {

        d0 = p[0] % BN_BITS2;
        zz = z[dN] >> d0;
        //OSSL_DEBUG("z[%d] 0x%lx >> d0 %d = zz 0x%lx",dN, z[dN],d0,zz);
        if (zz == 0){
            //OSSL_DEBUG(" ");
            break;
        }
        d1 = BN_BITS2 - d0;

        /* clear up the top d1 bits */
        if (d0){
            //OSSL_DEBUG("z[%d] (0x%lx << %d) >> %d = 0x%lx", dN, z[dN] ,d1,d1, (z[dN] << d1) >> d1);
            z[dN] = (z[dN] << d1) >> d1;
        }
        else{
            //OSSL_DEBUG("z[%d] = 0", dN);
            z[dN] = 0;
        }
        //OSSL_DEBUG("z[0] 0x%lx ^ 0x%lx = 0x%lx", z[0],zz,z[0] ^ zz);
        z[0] ^= zz;             /* reduction t^0 component */

        for (k = 1; p[k] != 0; k++) {
            BN_ULONG tmp_ulong;

            /* reducing component t^p[k] */
            n = p[k] / BN_BITS2;
            d0 = p[k] % BN_BITS2;
            d1 = BN_BITS2 - d0;
            //OSSL_DEBUG("p[%d] 0x%x n %d d0 %d d1 %d",k,p[k],n,d0,d1);
            //OSSL_DEBUG("z[%d] 0x%lx ^ (zz 0x%lx << d0 %d) = 0x%lx", n,z[n],zz,d0,z[n] ^ (zz << d0));
            z[n] ^= (zz << d0);
            if (d0 && (tmp_ulong = zz >> d1)){
                //OSSL_DEBUG("z[%d] 0x%lx ^ tmp_ulong 0x%lx = 0x%lx", n+1,z[n+1],tmp_ulong,z[n+1]^tmp_ulong);
                z[n + 1] ^= tmp_ulong;
            }
            //OSSL_DEBUG("p[%d+1] = %d", k,p[k+1]);
        }

    }

    bn_correct_top(r);
    return 1;
}

/*
 * Performs modular reduction of a by p and store result in r.  r could be a.
 * This function calls down to the BN_GF2m_mod_arr implementation; this wrapper
 * function is only provided for convenience; for best performance, use the
 * BN_GF2m_mod_arr function.
 */
int BN_GF2m_mod(BIGNUM *r, const BIGNUM *a, const BIGNUM *p)
{
    int ret = 0;
    bn_check_top(a);
    bn_check_top(p);
#if 0    
    int arr[6];
    ret = BN_GF2m_poly2arr(p, arr, OSSL_NELEM(arr));
    if (!ret || ret > (int)OSSL_NELEM(arr)) {
        ERR_raise(ERR_LIB_BN, BN_R_INVALID_LENGTH);
        return 0;
    }
    ret = BN_GF2m_mod_arr(r, a, arr);
#else
    int *carr = NULL;
    int cnum = 16;
try_again:
    if (carr != NULL) {
        OPENSSL_free(carr);
    }
    carr = NULL;
    carr = OPENSSL_malloc(sizeof(carr[0]) * cnum);
    memset(carr,0,sizeof(carr[0]) * cnum);
    ret = BN_GF2m_poly2arr(p,carr,cnum);
    if (ret == 0 || ret >= cnum) {
        cnum <<= 1;
        goto try_again;
    }
    //OSSL_BUFFER_DEBUG(carr,sizeof(carr[0]) * cnum, "carr [%d]",ret);
    ret = BN_GF2m_mod_arr(r,a,carr);
    OPENSSL_free(carr);
    carr = NULL;
#endif    
    bn_check_top(r);
    return ret;
}

/*
 * Compute the product of two polynomials a and b, reduce modulo p, and store
 * the result in r.  r could be a or b; a could be b.
 */
int BN_GF2m_mod_mul_arr(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
                        const int p[], BN_CTX *ctx)
{
    int zlen, i, j, k, ret = 0;
    BIGNUM *s;
    BN_ULONG x1, x0, y1, y0, zz[4];

    bn_check_top(a);
    bn_check_top(b);

    if (a == b) {
        return BN_GF2m_mod_sqr_arr(r, a, p, ctx);
    }

    BN_CTX_start(ctx);
    if ((s = BN_CTX_get(ctx)) == NULL)
        goto err;

    zlen = a->top + b->top + 4;
    if (!bn_wexpand(s, zlen))
        goto err;
    s->top = zlen;

    for (i = 0; i < zlen; i++)
        s->d[i] = 0;

    for (j = 0; j < b->top; j += 2) {
        y0 = b->d[j];
        y1 = ((j + 1) == b->top) ? 0 : b->d[j + 1];
        for (i = 0; i < a->top; i += 2) {
            x0 = a->d[i];
            x1 = ((i + 1) == a->top) ? 0 : a->d[i + 1];
            bn_GF2m_mul_2x2(zz, x1, x0, y1, y0);
            for (k = 0; k < 4; k++){
                //OSSL_DEBUG("[%d+%d+%d] 0x%lx ^ [%d] 0x%lx => 0x%lx",i,j,k,s->d[i+j+k],k ,zz[k], s->d[i+j+k] ^ zz[k]);
                s->d[i + j + k] ^= zz[k];
            }
        }
    }

    bn_correct_top(s);
    //OSSL_DEBUG_BN((16,s,&xptr,NULL),"s = 0x%s",xptr);
    if (BN_GF2m_mod_arr(r, s, p))
        ret = 1;
    bn_check_top(r);

 err:
    BN_CTX_end(ctx);
    return ret;
}

/*
 * Compute the product of two polynomials a and b, reduce modulo p, and store
 * the result in r.  r could be a or b; a could equal b. This function calls
 * down to the BN_GF2m_mod_mul_arr implementation; this wrapper function is
 * only provided for convenience; for best performance, use the
 * BN_GF2m_mod_mul_arr function.
 */
int BN_GF2m_mod_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
                    const BIGNUM *p, BN_CTX *ctx)
{
    int ret = 0;
    const int max = BN_num_bits(p) + 1;
    int *arr;

    bn_check_top(a);
    bn_check_top(b);
    bn_check_top(p);

    arr = OPENSSL_malloc(sizeof(*arr) * max);
    if (arr == NULL) {
        ERR_raise(ERR_LIB_BN, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    ret = BN_GF2m_poly2arr(p, arr, max);
    if (!ret || ret > max) {
        ERR_raise(ERR_LIB_BN, BN_R_INVALID_LENGTH);
        goto err;
    }
    ret = BN_GF2m_mod_mul_arr(r, a, b, arr, ctx);
    bn_check_top(r);
 err:
    OPENSSL_free(arr);
    return ret;
}

/* Square a, reduce the result mod p, and store it in a.  r could be a. */
int BN_GF2m_mod_sqr_arr(BIGNUM *r, const BIGNUM *a, const int p[],
                        BN_CTX *ctx)
{
    int i, ret = 0;
    BIGNUM *s;

    bn_check_top(a);
    BN_CTX_start(ctx);
    if ((s = BN_CTX_get(ctx)) == NULL)
        goto err;
    if (!bn_wexpand(s, 2 * a->top))
        goto err;

    for (i = a->top - 1; i >= 0; i--) {
        s->d[2 * i + 1] = SQR1(a->d[i]);
        s->d[2 * i] = SQR0(a->d[i]);
    }

    s->top = 2 * a->top;
    bn_correct_top(s);
    if (!BN_GF2m_mod_arr(r, s, p))
        goto err;
    bn_check_top(r);
    ret = 1;
 err:
    BN_CTX_end(ctx);
    return ret;
}

/*
 * Square a, reduce the result mod p, and store it in a.  r could be a. This
 * function calls down to the BN_GF2m_mod_sqr_arr implementation; this
 * wrapper function is only provided for convenience; for best performance,
 * use the BN_GF2m_mod_sqr_arr function.
 */
int BN_GF2m_mod_sqr(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx)
{
    int ret = 0;
    const int max = BN_num_bits(p) + 1;
    int *arr;

    bn_check_top(a);
    bn_check_top(p);

    arr = OPENSSL_malloc(sizeof(*arr) * max);
    if (arr == NULL) {
        ERR_raise(ERR_LIB_BN, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    ret = BN_GF2m_poly2arr(p, arr, max);
    if (!ret || ret > max) {
        ERR_raise(ERR_LIB_BN, BN_R_INVALID_LENGTH);
        goto err;
    }
    ret = BN_GF2m_mod_sqr_arr(r, a, arr, ctx);
    bn_check_top(r);
 err:
    OPENSSL_free(arr);
    return ret;
}

/*
 * Invert a, reduce modulo p, and store the result in r. r could be a. Uses
 * Modified Almost Inverse Algorithm (Algorithm 10) from Hankerson, D.,
 * Hernandez, J.L., and Menezes, A.  "Software Implementation of Elliptic
 * Curve Cryptography Over Binary Fields".
 */
static int BN_GF2m_mod_inv_vartime(BIGNUM *r, const BIGNUM *a,
                                   const BIGNUM *p, BN_CTX *ctx)
{
    BIGNUM *b, *c = NULL, *u = NULL, *v = NULL, *tmp;
    int ret = 0;
    //char* xptr=NULL,*yptr=NULL,*zptr=NULL;

    bn_check_top(a);
    bn_check_top(p);

    BN_CTX_start(ctx);

    b = BN_CTX_get(ctx);
    c = BN_CTX_get(ctx);
    u = BN_CTX_get(ctx);
    v = BN_CTX_get(ctx);
    if (v == NULL)
        goto err;

    if (!BN_GF2m_mod(u, a, p))
        goto err;
    //OSSL_DEBUG_BN((16,a,&xptr,u,&yptr,p,&zptr,NULL),"a 0x%s u 0x%s p 0x%s",xptr,yptr,zptr);
    if (BN_is_zero(u))
        goto err;

    if (!BN_copy(v, p))
        goto err;
# if 1
    if (!BN_one(b))
        goto err;

    while (1) {
        //OSSL_DEBUG_BN((16,b,&xptr,c,&yptr,NULL),"b 0x%s c 0x%s",xptr,yptr);
        while (!BN_is_odd(u)) {
            //OSSL_DEBUG_BN((16,u,&xptr,NULL),"u 0x%s", xptr);
            if (BN_is_zero(u))
                goto err;
            if (!BN_rshift1(u, u))
                goto err;
            //OSSL_DEBUG_BN((16,u,&xptr,b,&yptr,NULL),"u 0x%s b 0x%s", xptr,yptr);
            if (BN_is_odd(b)) {
                if (!BN_GF2m_add(b, b, p))
                    goto err;
                //OSSL_DEBUG_BN((16,b,&xptr,NULL),"b 0x%s",xptr);
            }
            if (!BN_rshift1(b, b))
                goto err;
            //OSSL_DEBUG_BN((16,b,&xptr,NULL),"b 0x%s",xptr);
        }

        if (BN_abs_is_word(u, 1)){
            //OSSL_DEBUG_BN((16,u,&xptr,NULL),"u 0x%s",xptr);
            break;
        }

        //OSSL_DEBUG_BN((16,u,&xptr,v,&yptr,NULL),"u 0x%s v 0x%s",xptr,yptr);
        if (BN_num_bits(u) < BN_num_bits(v)) {
            //OSSL_DEBUG("bits u [0x%x] bits v [0x%x]", BN_num_bits(u),BN_num_bits(v));
            tmp = u;
            u = v;
            v = tmp;
            tmp = b;
            b = c;
            c = tmp;
            //OSSL_DEBUG("u <=> v");
        }

        if (!BN_GF2m_add(u, u, v))
            goto err;
        if (!BN_GF2m_add(b, b, c))
            goto err;
        //OSSL_DEBUG_BN((16,u,&xptr,b,&yptr,NULL),"u 0x%s b 0x%s",xptr,yptr);
    }
# else
    {
        int i;
        int ubits = BN_num_bits(u);
        int vbits = BN_num_bits(v); /* v is copy of p */
        int top = p->top;
        BN_ULONG *udp, *bdp, *vdp, *cdp;

        if (!bn_wexpand(u, top))
            goto err;
        udp = u->d;
        for (i = u->top; i < top; i++){
            OSSL_DEBUG("[%d] set 0",i);
            udp[i] = 0;
        }
        u->top = top;
        if (!bn_wexpand(b, top))
          goto err;
        bdp = b->d;
        bdp[0] = 1;
        for (i = 1; i < top; i++)
            bdp[i] = 0;
        b->top = top;
        if (!bn_wexpand(c, top))
          goto err;
        cdp = c->d;
        for (i = 0; i < top; i++)
            cdp[i] = 0;
        c->top = top;
        vdp = v->d;             /* It pays off to "cache" *->d pointers,
                                 * because it allows optimizer to be more
                                 * aggressive. But we don't have to "cache"
                                 * p->d, because *p is declared 'const'... */
        while (1) {
            OSSL_DEBUG("ubits [0x%x] udp[0] 0x%lx", ubits,udp[0]);
            while (ubits && !(udp[0] & 1)) {
                BN_ULONG u0, u1, b0, b1, mask;

                u0 = udp[0];
                b0 = bdp[0];
                mask = (BN_ULONG)0 - (b0 & 1);
                OSSL_DEBUG("b0 0x%lx => b0 0x%lx = p->d[0] 0x%lx & mask 0x%lx", b0,b0 ^ (p->d[0] & mask), p->d[0],mask);
                b0 ^= p->d[0] & mask;
                for (i = 0; i < top - 1; i++) {
                    u1 = udp[i + 1];
                    OSSL_DEBUG("udp[%d] 0x%lx => udp[%d] 0x%lx = ((0x%lx >> 1) | (0x%lx << (BN_BITS2 - 1))) & 0x%lx",i,udp[i],i,((u0 >> 1) | (u1 << (BN_BITS2 - 1))) & BN_MASK2,u0,u1,BN_MASK2);
                    udp[i] = ((u0 >> 1) | (u1 << (BN_BITS2 - 1))) & BN_MASK2;
                    OSSL_DEBUG("u0 0x%lx => 0x%lx", u0,u1);
                    u0 = u1;
                    OSSL_DEBUG("b1 0x%lx => 0x%lx = (bdp[%d+1] 0x%lx) ^ (p->d[%d + 1] 0x%lx &  mask 0x%lx)",b1,bdp[i + 1] ^ (p->d[i + 1] & mask),i,bdp[i+1],i,p->d[i+1],mask);
                    b1 = bdp[i + 1] ^ (p->d[i + 1] & mask);
                    OSSL_DEBUG("bdp[%d] 0x%lx => 0x%lx = ((b0 0x%lx >> 1) | (b1 0x%lx << (BN_BITS2 0x%x - 1))) & BN_MASK2 0x%lx", i,bdp[i],((b0 >> 1) | (b1 << (BN_BITS2 - 1))) & BN_MASK2,b0,b1,BN_BITS2,BN_MASK2);
                    bdp[i] = ((b0 >> 1) | (b1 << (BN_BITS2 - 1))) & BN_MASK2;
                    OSSL_DEBUG("b0 0x%lx => 0x%lx",b0,b1);
                    b0 = b1;
                }
                OSSL_DEBUG("udp[%d] 0x%lx => 0x%lx (u0 0x%lx >> 1)",i,udp[i],(u0 >> 1),u0);
                udp[i] = u0 >> 1;
                OSSL_DEBUG("bdp[%d] 0x%lx => 0x%lx (b0 0x%lx >> 1)",i,bdp[i],(b0 >> 1),b0);
                bdp[i] = b0 >> 1;
                ubits--;
            }

            if (ubits <= BN_BITS2) {
                if (udp[0] == 0) /* poly was reducible */{
                    OSSL_DEBUG("error in inv");
                    goto err;
                }
                if (udp[0] == 1){
                    break;
                }
            }

            if (ubits < vbits) {
                i = ubits;
                ubits = vbits;
                vbits = i;
                tmp = u;
                u = v;
                v = tmp;
                tmp = b;
                b = c;
                c = tmp;
                udp = vdp;
                vdp = v->d;
                bdp = cdp;
                cdp = c->d;
                OSSL_DEBUG("ubits <=> vbits");
            }
            for (i = 0; i < top; i++) {
                OSSL_DEBUG("udp[%d] 0x%lx => 0x%lx (0x%lx ^ vdp[%d] 0x%lx)", i,udp[i],udp[i] ^ vdp[i],udp[i],i,vdp[i]);
                udp[i] ^= vdp[i];
                OSSL_DEBUG("bdp[%d] 0x%lx => 0x%lx (0x%lx ^ cdp[%d] 0x%lx)", i,bdp[i],bdp[i] ^ cdp[i],bdp[i],i,cdp[i]);
                bdp[i] ^= cdp[i];
            }
            if (ubits == vbits) {
                BN_ULONG ul;
                int utop = (ubits - 1) / BN_BITS2;

                while ((ul = udp[utop]) == 0 && utop){
                    utop--;
                }
                ubits = utop * BN_BITS2 + BN_num_bits_word(ul);
            }
        }
        bn_correct_top(b);
    }
# endif

    if (!BN_copy(r, b))
        goto err;
    bn_check_top(r);
    ret = 1;

 err:
# ifdef BN_DEBUG
    /* BN_CTX_end would complain about the expanded form */
    bn_correct_top(c);
    bn_correct_top(u);
    bn_correct_top(v);
# endif
    BN_CTX_end(ctx);
    return ret;
}

/*-
 * Wrapper for BN_GF2m_mod_inv_vartime that blinds the input before calling.
 * This is not constant time.
 * But it does eliminate first order deduction on the input.
 */
int BN_GF2m_mod_inv(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx)
{
    int ret = 0;
    //char *xptr=NULL,*yptr=NULL,*zptr=NULL;

    BN_CTX_start(ctx);
#if 0
    BIGNUM *b = NULL;
    if ((b = BN_CTX_get(ctx)) == NULL)
        goto err;
    /* generate blinding value */
    do {
        if (!BN_priv_rand_ex(b, BN_num_bits(p) - 1,
                             BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY, 0, ctx))
            goto err;
    } while (BN_is_zero(b));

    /* r := a * b */
    if (!BN_GF2m_mod_mul(r, a, b, p, ctx))
        goto err;

    //OSSL_DEBUG_BN((16,a,&xptr,b,&yptr,r,&zptr,NULL),"a 0x%s b 0x%s r 0x%s",xptr,yptr,zptr);
    /* r := 1/(a * b) */
    if (!BN_GF2m_mod_inv_vartime(r, r, p, ctx))
        goto err;

    /* r := b/(a * b) = 1/a */
    if (!BN_GF2m_mod_mul(r, r, b, p, ctx))
        goto err;
#else
    if (!BN_GF2m_mod_inv_vartime(r,a,p,ctx)) {
        goto err;
    }
#endif

    ret = 1;

 err:
    BN_CTX_end(ctx);
    return ret;
}

/*
 * Invert xx, reduce modulo p, and store the result in r. r could be xx.
 * This function calls down to the BN_GF2m_mod_inv implementation; this
 * wrapper function is only provided for convenience; for best performance,
 * use the BN_GF2m_mod_inv function.
 */
int BN_GF2m_mod_inv_arr(BIGNUM *r, const BIGNUM *xx, const int p[],
                        BN_CTX *ctx)
{
    BIGNUM *field;
    int ret = 0;

    bn_check_top(xx);
    BN_CTX_start(ctx);
    if ((field = BN_CTX_get(ctx)) == NULL)
        goto err;
    if (!BN_GF2m_arr2poly(p, field))
        goto err;

    ret = BN_GF2m_mod_inv(r, xx, field, ctx);
    bn_check_top(r);

 err:
    BN_CTX_end(ctx);
    return ret;
}

/*
 * Divide y by x, reduce modulo p, and store the result in r. r could be x
 * or y, x could equal y.
 */
int BN_GF2m_mod_div(BIGNUM *r, const BIGNUM *y, const BIGNUM *x,
                    const BIGNUM *p, BN_CTX *ctx)
{
    BIGNUM *xinv = NULL;
    int ret = 0;
    char *xptr=NULL,*yptr=NULL,*zptr=NULL,*pptr=NULL;

    bn_check_top(y);
    bn_check_top(x);
    bn_check_top(p);

    BN_CTX_start(ctx);
    xinv = BN_CTX_get(ctx);
    if (xinv == NULL)
        goto err;

    if (!BN_GF2m_mod_inv(xinv, x, p, ctx))
        goto err;
    OSSL_DEBUG_BN((16,xinv,&xptr,x,&yptr,p,&zptr,NULL),"0x%s * 0x%s = 1 %% 0x%s", xptr,yptr,zptr);
    if (!BN_GF2m_mod_mul(r, y, xinv, p, ctx))
        goto err;
    OSSL_DEBUG_BN((16,r,&xptr,y,&yptr,xinv,&zptr,p,&pptr,NULL),"r 0x%s = ( y 0x%s * xinv 0x%s %% p 0x%s )",xptr,yptr,zptr,pptr);
    bn_check_top(r);
    ret = 1;

 err:
    BN_CTX_end(ctx);
    return ret;
}

/*
 * Divide yy by xx, reduce modulo p, and store the result in r. r could be xx
 * * or yy, xx could equal yy. This function calls down to the
 * BN_GF2m_mod_div implementation; this wrapper function is only provided for
 * convenience; for best performance, use the BN_GF2m_mod_div function.
 */
int BN_GF2m_mod_div_arr(BIGNUM *r, const BIGNUM *yy, const BIGNUM *xx,
                        const int p[], BN_CTX *ctx)
{
    BIGNUM *field;
    int ret = 0;

    bn_check_top(yy);
    bn_check_top(xx);

    BN_CTX_start(ctx);
    if ((field = BN_CTX_get(ctx)) == NULL)
        goto err;
    if (!BN_GF2m_arr2poly(p, field))
        goto err;

    ret = BN_GF2m_mod_div(r, yy, xx, field, ctx);
    bn_check_top(r);

 err:
    BN_CTX_end(ctx);
    return ret;
}

/*
 * Compute the bth power of a, reduce modulo p, and store the result in r.  r
 * could be a. Uses simple square-and-multiply algorithm A.5.1 from IEEE
 * P1363.
 */
int BN_GF2m_mod_exp_arr(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
                        const int p[], BN_CTX *ctx)
{
    int ret = 0, i, n;
    BIGNUM *u;

    bn_check_top(a);
    bn_check_top(b);

    if (BN_is_zero(b))
        return BN_one(r);

    if (BN_abs_is_word(b, 1))
        return (BN_copy(r, a) != NULL);

    BN_CTX_start(ctx);
    if ((u = BN_CTX_get(ctx)) == NULL)
        goto err;

    if (!BN_GF2m_mod_arr(u, a, p))
        goto err;

    n = BN_num_bits(b) - 1;
    for (i = n - 1; i >= 0; i--) {
        if (!BN_GF2m_mod_sqr_arr(u, u, p, ctx))
            goto err;
        if (BN_is_bit_set(b, i)) {
            if (!BN_GF2m_mod_mul_arr(u, u, a, p, ctx))
                goto err;
        }
    }
    if (!BN_copy(r, u))
        goto err;
    bn_check_top(r);
    ret = 1;
 err:
    BN_CTX_end(ctx);
    return ret;
}

/*
 * Compute the bth power of a, reduce modulo p, and store the result in r.  r
 * could be a. This function calls down to the BN_GF2m_mod_exp_arr
 * implementation; this wrapper function is only provided for convenience;
 * for best performance, use the BN_GF2m_mod_exp_arr function.
 */
int BN_GF2m_mod_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
                    const BIGNUM *p, BN_CTX *ctx)
{
    int ret = 0;
    const int max = BN_num_bits(p) + 1;
    int *arr;

    bn_check_top(a);
    bn_check_top(b);
    bn_check_top(p);

    arr = OPENSSL_malloc(sizeof(*arr) * max);
    if (arr == NULL) {
        ERR_raise(ERR_LIB_BN, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    ret = BN_GF2m_poly2arr(p, arr, max);
    if (!ret || ret > max) {
        ERR_raise(ERR_LIB_BN, BN_R_INVALID_LENGTH);
        goto err;
    }
    ret = BN_GF2m_mod_exp_arr(r, a, b, arr, ctx);
    bn_check_top(r);
 err:
    OPENSSL_free(arr);
    return ret;
}

/*
 * Compute the square root of a, reduce modulo p, and store the result in r.
 * r could be a. Uses exponentiation as in algorithm A.4.1 from IEEE P1363.
 */
int BN_GF2m_mod_sqrt_arr(BIGNUM *r, const BIGNUM *a, const int p[],
                         BN_CTX *ctx)
{
    int ret = 0;
    BIGNUM *u;

    bn_check_top(a);

    if (p[0] == 0) {
        /* reduction mod 1 => return 0 */
        BN_zero(r);
        return 1;
    }

    BN_CTX_start(ctx);
    if ((u = BN_CTX_get(ctx)) == NULL)
        goto err;

    if (!BN_set_bit(u, p[0] - 1))
        goto err;
    ret = BN_GF2m_mod_exp_arr(r, a, u, p, ctx);
    bn_check_top(r);

 err:
    BN_CTX_end(ctx);
    return ret;
}

/*
 * Compute the square root of a, reduce modulo p, and store the result in r.
 * r could be a. This function calls down to the BN_GF2m_mod_sqrt_arr
 * implementation; this wrapper function is only provided for convenience;
 * for best performance, use the BN_GF2m_mod_sqrt_arr function.
 */
int BN_GF2m_mod_sqrt(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx)
{
    int ret = 0;
    const int max = BN_num_bits(p) + 1;
    int *arr;

    bn_check_top(a);
    bn_check_top(p);

    arr = OPENSSL_malloc(sizeof(*arr) * max);
    if (arr == NULL) {
        ERR_raise(ERR_LIB_BN, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    ret = BN_GF2m_poly2arr(p, arr, max);
    if (!ret || ret > max) {
        ERR_raise(ERR_LIB_BN, BN_R_INVALID_LENGTH);
        goto err;
    }
    ret = BN_GF2m_mod_sqrt_arr(r, a, arr, ctx);
    bn_check_top(r);
 err:
    OPENSSL_free(arr);
    return ret;
}

/*
 * Find r such that r^2 + r = a mod p.  r could be a. If no r exists returns
 * 0. Uses algorithms A.4.7 and A.4.6 from IEEE P1363.
 */
int BN_GF2m_mod_solve_quad_arr(BIGNUM *r, const BIGNUM *a_, const int p[],
                               BN_CTX *ctx)
{
    int ret = 0, count = 0, j;
    BIGNUM *a, *z, *rho, *w, *w2, *tmp;

    bn_check_top(a_);

    if (p[0] == 0) {
        /* reduction mod 1 => return 0 */
        BN_zero(r);
        return 1;
    }

    BN_CTX_start(ctx);
    a = BN_CTX_get(ctx);
    z = BN_CTX_get(ctx);
    w = BN_CTX_get(ctx);
    if (w == NULL)
        goto err;

    if (!BN_GF2m_mod_arr(a, a_, p))
        goto err;

    if (BN_is_zero(a)) {
        BN_zero(r);
        ret = 1;
        goto err;
    }

    if (p[0] & 0x1) {           /* m is odd */
        /* compute half-trace of a */
        if (!BN_copy(z, a))
            goto err;
        for (j = 1; j <= (p[0] - 1) / 2; j++) {
            if (!BN_GF2m_mod_sqr_arr(z, z, p, ctx))
                goto err;
            if (!BN_GF2m_mod_sqr_arr(z, z, p, ctx))
                goto err;
            if (!BN_GF2m_add(z, z, a))
                goto err;
        }

    } else {                    /* m is even */

        rho = BN_CTX_get(ctx);
        w2 = BN_CTX_get(ctx);
        tmp = BN_CTX_get(ctx);
        if (tmp == NULL)
            goto err;
        do {
            if (!BN_priv_rand_ex(rho, p[0], BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY,
                                 0, ctx))
                goto err;
            if (!BN_GF2m_mod_arr(rho, rho, p))
                goto err;
            BN_zero(z);
            if (!BN_copy(w, rho))
                goto err;
            for (j = 1; j <= p[0] - 1; j++) {
                if (!BN_GF2m_mod_sqr_arr(z, z, p, ctx))
                    goto err;
                if (!BN_GF2m_mod_sqr_arr(w2, w, p, ctx))
                    goto err;
                if (!BN_GF2m_mod_mul_arr(tmp, w2, a, p, ctx))
                    goto err;
                if (!BN_GF2m_add(z, z, tmp))
                    goto err;
                if (!BN_GF2m_add(w, w2, rho))
                    goto err;
            }
            count++;
        } while (BN_is_zero(w) && (count < MAX_ITERATIONS));
        if (BN_is_zero(w)) {
            ERR_raise(ERR_LIB_BN, BN_R_TOO_MANY_ITERATIONS);
            goto err;
        }
    }

    if (!BN_GF2m_mod_sqr_arr(w, z, p, ctx))
        goto err;
    if (!BN_GF2m_add(w, z, w))
        goto err;
    if (BN_GF2m_cmp(w, a)) {
        ERR_raise(ERR_LIB_BN, BN_R_NO_SOLUTION);
        goto err;
    }

    if (!BN_copy(r, z))
        goto err;
    bn_check_top(r);

    ret = 1;

 err:
    BN_CTX_end(ctx);
    return ret;
}

/*
 * Find r such that r^2 + r = a mod p.  r could be a. If no r exists returns
 * 0. This function calls down to the BN_GF2m_mod_solve_quad_arr
 * implementation; this wrapper function is only provided for convenience;
 * for best performance, use the BN_GF2m_mod_solve_quad_arr function.
 */
int BN_GF2m_mod_solve_quad(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                           BN_CTX *ctx)
{
    int ret = 0;
    const int max = BN_num_bits(p) + 1;
    int *arr;

    bn_check_top(a);
    bn_check_top(p);

    arr = OPENSSL_malloc(sizeof(*arr) * max);
    if (arr == NULL) {
        ERR_raise(ERR_LIB_BN, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    ret = BN_GF2m_poly2arr(p, arr, max);
    if (!ret || ret > max) {
        ERR_raise(ERR_LIB_BN, BN_R_INVALID_LENGTH);
        goto err;
    }
    ret = BN_GF2m_mod_solve_quad_arr(r, a, arr, ctx);
    bn_check_top(r);
 err:
    OPENSSL_free(arr);
    return ret;
}

/*
 * Convert the bit-string representation of a polynomial ( \sum_{i=0}^n a_i *
 * x^i) into an array of integers corresponding to the bits with non-zero
 * coefficient.  Array is terminated with -1. Up to max elements of the array
 * will be filled.  Return value is total number of array elements that would
 * be filled if array was large enough.
 */
int BN_GF2m_poly2arr(const BIGNUM *a, int p[], int max)
{
    int i, j, k = 0;
    BN_ULONG mask;

    if (BN_is_zero(a))
        return 0;

    for (i = a->top - 1; i >= 0; i--) {
        if (!a->d[i])
            /* skip word if a->d[i] == 0 */
            continue;
        mask = BN_TBIT;
        for (j = BN_BITS2 - 1; j >= 0; j--) {
            if (a->d[i] & mask) {
                if (k < max){
                    p[k] = BN_BITS2 * i + j;
                }
                k++;
            }
            mask >>= 1;
        }
    }

    if (k < max) {
        p[k] = -1;
        k++;
    }
    if (k < max) {
        p[k] = 0;
    }

    return k;
}

/*
 * Convert the coefficient array representation of a polynomial to a
 * bit-string.  The array must be terminated by -1.
 */
int BN_GF2m_arr2poly(const int p[], BIGNUM *a)
{
    int i;

    bn_check_top(a);
    BN_zero(a);
    for (i = 0; p[i] != -1; i++) {
        if (BN_set_bit(a, p[i]) == 0)
            return 0;
    }
    bn_check_top(a);

    return 1;
}

#endif
