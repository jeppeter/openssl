/*
 * Copyright 2000-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/cryptlib.h"
#include "bn_local.h"

/* least significant word */
#define BN_lsw(n) (((n)->top == 0) ? (BN_ULONG) 0 : (n)->d[0])

#define BN_KRON_DEBUG            1

#if BN_KRON_DEBUG
#define KRON_DEBUG_BN(...)             OSSL_DEBUG_BN(__VA_ARGS__)
#define KRON_DEBUG(...)                OSSL_DEBUG(__VA_ARGS__)
#else
#define KRON_DEBUG_BN(...)             do{}while(0)
#define KRON_DEBUG(...)                do{}while(0)
#endif

/* Returns -2 for errors because both -1 and 0 are valid results. */
int BN_kronecker(const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx)
{
    int i;
    int ret = -2;               /* avoid 'uninitialized' warning */
    int err = 0;
    BIGNUM *A, *B, *tmp;
#if BN_KRON_DEBUG    
    char *xptr=NULL,*yptr=NULL,*zptr=NULL;
#endif
    /*-
     * In 'tab', only odd-indexed entries are relevant:
     * For any odd BIGNUM n,
     *     tab[BN_lsw(n) & 7]
     * is $(-1)^{(n^2-1)/8}$ (using TeX notation).
     * Note that the sign of n does not matter.
     */
    static const int tab[8] = { 0, 1, 0, -1, 0, -1, 0, 1 };

    bn_check_top(a);
    bn_check_top(b);

    BN_CTX_start(ctx);
    A = BN_CTX_get(ctx);
    B = BN_CTX_get(ctx);
    if (B == NULL)
        goto end;

    err = !BN_copy(A, a);
    if (err)
        goto end;
    err = !BN_copy(B, b);
    if (err)
        goto end;

    KRON_DEBUG_BN((16,A,&xptr,B,&yptr,NULL),"A 0x%s B 0x%s",xptr,yptr);
    /*
     * Kronecker symbol, implemented according to Henri Cohen,
     * "A Course in Computational Algebraic Number Theory"
     * (algorithm 1.4.10).
     */

    /* Cohen's step 1: */

    if (BN_is_zero(B)) {
        ret = BN_abs_is_word(A, 1);
        OSSL_DEBUG("ret %d",ret);
        goto end;
    }

    /* Cohen's step 2: */

    if (!BN_is_odd(A) && !BN_is_odd(B)) {
        ret = 0;
        OSSL_DEBUG("ret 0");
        goto end;
    }

    /* now  B  is non-zero */
    i = 0;
    while (!BN_is_bit_set(B, i))
        i++;
    KRON_DEBUG_BN((16,B,&zptr,NULL),"B 0x%s i %d",zptr,i);
    err = !BN_rshift(B, B, i);
    if (err)
        goto end;
    KRON_DEBUG_BN((16,B,&xptr,NULL),"B 0x%s",xptr);
    if (i & 1) {
        /* i is odd */
        /* (thus  B  was even, thus  A  must be odd!)  */

        /* set 'ret' to $(-1)^{(A^2-1)/8}$ */
        ret = tab[BN_lsw(A) & 7];
        KRON_DEBUG_BN((16,A,&xptr,NULL),"ret %d tab[BN_lsw(0x%s)&7 = 0x%lx]",ret,xptr,BN_lsw(A) & 7);
    } else {
        /* i is even */
        ret = 1;
        OSSL_DEBUG("ret 1");
    }

    if (B->neg) {
        B->neg = 0;
        if (A->neg){
            ret = -ret;
            OSSL_DEBUG("A net ret %d",ret);
        }
    }

    /*
     * now B is positive and odd, so what remains to be done is to compute
     * the Jacobi symbol (A/B) and multiply it by 'ret'
     */

    while (1) {
        /* Cohen's step 3: */

        /*  B  is positive and odd */

        if (BN_is_zero(A)) {
            ret = BN_is_one(B) ? ret : 0;
            KRON_DEBUG_BN((16,B,&xptr,NULL),"B 0x%s ret %d",xptr,ret);
            goto end;
        }

        /* now  A  is non-zero */
        i = 0;
        while (!BN_is_bit_set(A, i))
            i++;
        KRON_DEBUG_BN((16,A,&xptr,NULL),"A 0x%s i %d",xptr,i);
        err = !BN_rshift(A, A, i);
        if (err)
            goto end;
        KRON_DEBUG_BN((16,A,&xptr,NULL),"A 0x%s",xptr);
        if (i & 1) {
            /* i is odd */
            /* multiply 'ret' by  $(-1)^{(B^2-1)/8}$ */
            KRON_DEBUG_BN((16,A,&xptr,NULL),"ret %d = ret %d * tab[BN_lsw(0x%s)&7 = 0x%lx]",ret * tab[BN_lsw(B) & 7],ret,xptr,BN_lsw(A) & 7);
            ret = ret * tab[BN_lsw(B) & 7];
        }

        /* Cohen's step 4: */
        /* multiply 'ret' by  $(-1)^{(A-1)(B-1)/4}$ */
        if ((A->neg ? ~BN_lsw(A) : BN_lsw(A)) & BN_lsw(B) & 2){
            KRON_DEBUG_BN((16,A,&xptr,B,&yptr,NULL),"A->neg %d A 0x%s B 0x%s",A->neg,xptr,yptr);
            ret = -ret;
        }

        /* (A, B) := (B mod |A|, |A|) */
        err = !BN_nnmod(B, B, A, ctx);
        if (err)
            goto end;
        KRON_DEBUG_BN((16,B,&xptr,A,&yptr,NULL),"nnmod(B 0x%s,B,A 0x%s)",xptr,yptr);
        tmp = A;
        A = B;
        B = tmp;
        KRON_DEBUG_BN((16,A,&xptr,B,&yptr,NULL),"A 0x%s B 0x%s",xptr,yptr);
        tmp->neg = 0;
    }
 end:
    BN_CTX_end(ctx);
    if (err)
        return -2;
    else
        return ret;
}
