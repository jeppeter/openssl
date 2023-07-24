/*
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Details about Montgomery multiplication algorithms can be found at
 * http://security.ece.orst.edu/publications.html, e.g.
 * http://security.ece.orst.edu/koc/papers/j37acmon.pdf and
 * sections 3.8 and 4.2 in http://security.ece.orst.edu/koc/papers/r01rsasw.pdf
 */

#include "internal/cryptlib.h"
#include "bn_local.h"
#include "internal/intern_log.h"

#define MONT_WORD               /* use the faster word-based algorithm */

#define USE_MONT_DEBUG 0

#if USE_MONT_DEBUG

#define MONT_BN(...) OSSL_DEBUG_BN(__VA_ARGS__)
#define MONT_DEBUG(...)  OSSL_DEBUG(__VA_ARGS__)
#define MONT_BUFFER_DEBUG(...)  OSSL_BUFFER_DEBUG(__VA_ARGS__)

#else

#define MONT_BN(...) do{}while(0)
#define MONT_DEBUG(...) do{}while(0)
#define MONT_BUFFER_DEBUG(...) do{}while(0)

#endif

#ifdef MONT_WORD
static int bn_from_montgomery_word(BIGNUM *ret, BIGNUM *r, BN_MONT_CTX *mont);
#endif

int BN_mod_mul_montgomery(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
                          BN_MONT_CTX *mont, BN_CTX *ctx)
{
    int ret = bn_mul_mont_fixed_top(r, a, b, mont, ctx);

    bn_correct_top(r);
    bn_check_top(r);

    return ret;
}

int bn_mul_mont_fixed_top(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
                          BN_MONT_CTX *mont, BN_CTX *ctx)
{
    BIGNUM *tmp;
    int ret = 0;
    int num = mont->N.top;
#if USE_MONT_DEBUG
    char *rptr=NULL,*aptr=NULL,*bptr=NULL,*nptr=NULL;
#endif
    BIGNUM *copya=NULL, *copyb=NULL;

#if USE_MONT_DEBUG == 0
#if defined(OPENSSL_BN_ASM_MONT) && defined(MONT_WORD)
    if (copya == NULL) {
        copya = BN_new();
        if (copya) {
            BN_copy(copya,a);
        }        
    }
    if (copyb == NULL) {
        copyb = BN_new();
        if (copyb) {
            BN_copy(copyb,b);
        }        
    }

    if (num > 1 && a->top == num && b->top == num) {
        if (bn_wexpand(r, num) == NULL)
            return 0;
        if (bn_mul_mont(r->d, a->d, b->d, mont->N.d, mont->n0, num)) {
            r->neg = a->neg ^ b->neg;
            r->top = num;
            r->flags |= BN_FLG_FIXED_TOP;
            if (copya && copyb) {
                MONT_BN((16,r,&rptr,copya,&aptr,copyb,&bptr,&(mont->N),&nptr,NULL),"r 0x%s = (a 0x%s * b 0x%s) %% mont->N 0x%s",rptr, aptr,bptr,nptr);                
            }
            if (copya) {
                BN_free(copya);
            }
            copya = NULL;
            if (copyb) {
                BN_free(copyb);
            }
            copyb = NULL;
            return 1;
        }
    }
#endif
#endif

    if ((a->top + b->top) > 2 * num){
            if (copya) {
                BN_free(copya);
            }
            copya = NULL;
            if (copyb) {
                BN_free(copyb);
            }
            copyb = NULL;
        return 0;
    }

    BN_CTX_start(ctx);
    tmp = BN_CTX_get(ctx);
    if (tmp == NULL)
        goto err;

    bn_check_top(tmp);
    if (copya == NULL) {
        copya = BN_new();
        if (copya) {
            BN_copy(copya,a);
        }        
    }
    if (copyb == NULL) {
        copyb = BN_new();
        if (copyb) {
            BN_copy(copyb,b);
        }        
    }
    if (a == b) {
        if (!bn_sqr_fixed_top(tmp, a, ctx))
            goto err;
    } else {
        if (!bn_mul_fixed_top(tmp, a, b, ctx))
            goto err;
    }

    MONT_BN((16,tmp,&rptr,copya,&aptr,copyb,&bptr,NULL),"tmp 0x%s = a 0x%s * b 0x%s",rptr,aptr,bptr);
    /* reduce from aRR to aR */
#ifdef MONT_WORD
    if (!bn_from_montgomery_word(r, tmp, mont))
        goto err;
#else
    if (!BN_from_montgomery(r, tmp, mont, ctx))
        goto err;
#endif

    if (copya && copyb) {
        MONT_BN((16,r,&rptr,copya,&aptr,copyb,&bptr,&mont->N,&nptr,NULL),"r 0x%s = (a 0x%s * b 0x%s) %% mont->N 0x%s",rptr,aptr,bptr,nptr);
    }
    ret = 1;
 err:
    if (copyb){
        BN_free(copyb);
    }
    copyb = NULL;
    if (copya) {
        BN_free(copya);
    }
    copya = NULL;
    BN_CTX_end(ctx);
    return ret;
}

#ifdef MONT_WORD
static int bn_from_montgomery_word(BIGNUM *ret, BIGNUM *r, BN_MONT_CTX *mont)
{
    BIGNUM *n;
    BN_ULONG *ap, *np, *rp, n0, v, carry;
    int nl, max, i;
    unsigned int rtop;
#if USE_MONT_DEBUG
    BN_ULONG *orp;
    int rpoff=0;
    char *xptr=NULL,*yptr=NULL,*zptr = NULL;
    BIGNUM* copyr=NULL;
#endif

    n = &(mont->N);
    nl = n->top;
    if (nl == 0) {
        ret->top = 0;
        return 1;
    }
#if USE_MONT_DEBUG    
    copyr = BN_new();
    if (copyr) {
        BN_copy(copyr,r);
    }
#endif

    MONT_BN((16,n,&xptr,r,&yptr,NULL),"mont->N 0x%s r 0x%s",xptr,yptr);

    max = (2 * nl);             /* carry is stored separately */
    if (bn_wexpand(r, max) == NULL){
#if USE_MONT_DEBUG        
        if (copyr) {
            BN_free(copyr);
        }
        copyr = NULL;
#endif        
        return 0;
    }

    r->neg ^= n->neg;
    np = n->d;
    rp = r->d;
#if USE_MONT_DEBUG    
    orp = r->d;
#endif
    /* clear the top words of T */
    for (rtop = r->top, i = 0; i < max; i++) {
        MONT_DEBUG("i 0x%x - rtop 0x%x = 0x%x ",i,rtop,i-rtop);
        MONT_DEBUG("(8 * sizeof(rtop) - 1) 0x%lx ((i - rtop) >> (8 * sizeof(rtop) - 1) 0x%lx", (BN_ULONG)(8 * sizeof(rtop) - 1),(BN_ULONG)((i - rtop) >> (8 * sizeof(rtop) - 1)));
        v = (BN_ULONG)0 - ((i - rtop) >> (8 * sizeof(rtop) - 1));
        MONT_DEBUG("r->d[%d] 0x%lx & v 0x%lx => r->d[%d] 0x%lx",i,rp[i],v,i,rp[i] & v);
        rp[i] &= v;
    }

    r->top = max;
    r->flags |= BN_FLG_FIXED_TOP;
    n0 = mont->n0[0];
    MONT_BN((16,r,&xptr,n,&yptr,NULL),"new r 0x%s n 0x%s n0 0x%lx",xptr,yptr,n0);

    /*
     * Add multiples of |n| to |r| until R = 2^(nl * BN_BITS2) divides it. On
     * input, we had |r| < |n| * R, so now |r| < 2 * |n| * R. Note that |r|
     * includes |carry| which is stored separately.
     */
    for (carry = 0, i = 0; i < nl; i++, rp++) {
#if USE_MONT_DEBUG        
        rpoff = ((rp - orp) / sizeof(rp[0]));
#endif        
        MONT_BN((16,r,&xptr,n,&yptr,NULL),"nl[%d][%d] r 0x%s n 0x%s rp[%d] 0x%lx w 0x%lX",nl,i,xptr,yptr,rpoff,rp[0],(rp[0] * n0) & BN_MASK2);
        v = bn_mul_add_words(rp, np, nl, (rp[0] * n0) & BN_MASK2);
        MONT_DEBUG("v 0x%lX", v);
        v = (v + carry + rp[nl]) & BN_MASK2;
        carry |= (v != rp[nl]);
        carry &= (v <= rp[nl]);
        MONT_DEBUG("r->d[%d] = 0x%lx",rpoff + nl,v);
        rp[nl] = v;
    }
    MONT_BN((16,r,&xptr,n,&yptr,NULL),"second r 0x%s n 0x%s",xptr,yptr);

    if (bn_wexpand(ret, nl) == NULL){
#if USE_MONT_DEBUG        
        if (copyr) {
            BN_free(copyr);
        }
        copyr  =NULL;
#endif        
        return 0;
    }
    ret->top = nl;
    ret->flags |= BN_FLG_FIXED_TOP;
    ret->neg = r->neg;

    rp = ret->d;

    /*
     * Shift |nl| words to divide by R. We have |ap| < 2 * |n|. Note that |ap|
     * includes |carry| which is stored separately.
     */
    ap = &(r->d[nl]);

    carry -= bn_sub_words(rp, ap, np, nl);
    /*
     * |carry| is -1 if |ap| - |np| underflowed or zero if it did not. Note
     * |carry| cannot be 1. That would imply the subtraction did not fit in
     * |nl| words, and we know at most one subtraction is needed.
     */
    for (i = 0; i < nl; i++) {
        MONT_DEBUG("r->d[%d] 0x%lx",i,rp[i]);
        rp[i] = (carry & ap[i]) | (~carry & rp[i]);
        MONT_DEBUG("r->d[%d] 0x%lx a->[%d] 0x%lx carry 0x%lx",i,rp[i],i,ap[i],carry);
        ap[i] = 0;
    }
    MONT_BN((16,copyr,&xptr,&(mont->N),&yptr,ret,&zptr,NULL),"r 0x%s * mont->N 0x%s = ret 0x%s",xptr,yptr,zptr);

#if USE_MONT_DEBUG
    if (copyr) {
        BN_free(copyr);
    }
    copyr = NULL;
#endif
    return 1;
}
#endif                          /* MONT_WORD */

int BN_from_montgomery(BIGNUM *ret, const BIGNUM *a, BN_MONT_CTX *mont,
                       BN_CTX *ctx)
{
    int retn;

    retn = bn_from_mont_fixed_top(ret, a, mont, ctx);
    bn_correct_top(ret);
    bn_check_top(ret);

    return retn;
}

int bn_from_mont_fixed_top(BIGNUM *ret, const BIGNUM *a, BN_MONT_CTX *mont,
                           BN_CTX *ctx)
{
    int retn = 0;
#ifdef MONT_WORD
    BIGNUM *t;

    BN_CTX_start(ctx);
    if ((t = BN_CTX_get(ctx)) && BN_copy(t, a)) {
        retn = bn_from_montgomery_word(ret, t, mont);
    }
    BN_CTX_end(ctx);
#else                           /* !MONT_WORD */
    BIGNUM *t1, *t2;
#if USE_MONT_DEBUG    
    char *xptr=NULL,*yptr=NULL,*zptr=NULL;
#endif

    BN_CTX_start(ctx);
    t1 = BN_CTX_get(ctx);
    t2 = BN_CTX_get(ctx);
    if (t2 == NULL)
        goto err;

    if (!BN_copy(t1, a))
        goto err;
    BN_mask_bits(t1, mont->ri);
    MONT_BN((16,t1,&xptr,NULL),"t1 0x%s",xptr);

    if (!BN_mul(t2, t1, &mont->Ni, ctx))
        goto err;
    MONT_BN((16,t1,&xptr,t2,&yptr,&mont->Ni,&zptr,NULL),"t1 0x%s * mont->Ni 0x%s = t2 0x%s",xptr,yptr,zptr);
    BN_mask_bits(t2, mont->ri);
    MONT_BN((16,t2,&xptr,NULL,mont->ri,&yptr,NULL),"t2 0x%s mont->ri 0x%s",xptr,yptr);

    if (!BN_mul(t1, t2, &mont->N, ctx))
        goto err;
    MONT_BN((16,t1,&xptr,&mont->N,&yptr,t2,&zptr,NULL),"t2 0x%s * mont->N 0x%s = t1 0x%s",zptr,yptr,xptr);
    if (!BN_add(t2, a, t1))
        goto err;
    MONT_BN((16,a,&xptr,t1,&yptr,t2,&zptr,NULL),"a 0x%s * t1 0x%s = t2 0x%s", xptr,yptr,zptr);
    if (!BN_rshift(ret, t2, mont->ri))
        goto err;
    MONT_BN((16,t2,&xptr,ret,&yptr,NULL),"t2 0x%s >> 0x%x = ret 0x%s",xptr,mont->ri,yptr);

    if (BN_ucmp(ret, &(mont->N)) >= 0) {
        if (!BN_usub(ret, ret, &(mont->N)))
            goto err;
    }
    MONT_BN((16,ret,&xptr,&(mont->N),&yptr,NULL),"ret 0x%s mont->N 0x%s",xptr,yptr);
    retn = 1;
    bn_check_top(ret);
 err:
    BN_CTX_end(ctx);
#endif                          /* MONT_WORD */
    return retn;
}

int bn_to_mont_fixed_top(BIGNUM *r, const BIGNUM *a, BN_MONT_CTX *mont,
                         BN_CTX *ctx)
{
    int ret;
    char *xptr=NULL;
#if USE_MONT_DEBUG    
    char  *yptr=NULL,*zptr=NULL,*nptr=NULL;
    BIGNUM* copya=NULL;

    copya = BN_new();
    if (copya) {
        BN_copy(copya,a);    
    }    
#endif

    ret = bn_mul_mont_fixed_top(r, a, &(mont->RR), mont, ctx);
#if USE_MONT_DEBUG    
    if (ret > 0 && copya != NULL) {
        MONT_BN((16,copya,&xptr,&(mont->RR),&yptr,r,&zptr,&(mont->N),&nptr,NULL),"a 0x%s * mont->RR 0x%s = r 0x%s %% 0x%s",xptr,yptr,zptr,nptr);
    }
    if (copya) {
        BN_free(copya);
    }
    copya = NULL;
#endif    
    OSSL_DEBUG_BN((16,&(mont->N),&xptr,NULL),"mont->N 0x%s",xptr);
    return ret;
}

BN_MONT_CTX *BN_MONT_CTX_new(void)
{
    BN_MONT_CTX *ret;

    if ((ret = OPENSSL_malloc(sizeof(*ret))) == NULL) {
        ERR_raise(ERR_LIB_BN, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    BN_MONT_CTX_init(ret);
    ret->flags = BN_FLG_MALLOCED;
    return ret;
}

void BN_MONT_CTX_init(BN_MONT_CTX *ctx)
{
    ctx->ri = 0;
    bn_init(&ctx->RR);
    bn_init(&ctx->N);
    bn_init(&ctx->Ni);
    ctx->n0[0] = ctx->n0[1] = 0;
    ctx->flags = 0;
}

void BN_MONT_CTX_free(BN_MONT_CTX *mont)
{
    if (mont == NULL)
        return;
    BN_clear_free(&mont->RR);
    BN_clear_free(&mont->N);
    BN_clear_free(&mont->Ni);
    if (mont->flags & BN_FLG_MALLOCED)
        OPENSSL_free(mont);
}

int BN_MONT_CTX_set(BN_MONT_CTX *mont, const BIGNUM *mod, BN_CTX *ctx)
{
    int i, ret = 0;
    BIGNUM *Ri, *R;
#if USE_MONT_DEBUG    
    char *xptr=NULL,*yptr=NULL,*zptr=NULL;
#endif

    if (BN_is_zero(mod))
        return 0;

    BN_CTX_start(ctx);
    if ((Ri = BN_CTX_get(ctx)) == NULL)
        goto err;
    R = &(mont->RR);            /* grab RR as a temp */
    if (!BN_copy(&(mont->N), mod))
        goto err;               /* Set N */
    if (BN_get_flags(mod, BN_FLG_CONSTTIME) != 0)
        BN_set_flags(&(mont->N), BN_FLG_CONSTTIME);
    mont->N.neg = 0;

#ifdef MONT_WORD
    {
        BIGNUM tmod;
        BN_ULONG buf[2];

        bn_init(&tmod);
        tmod.d = buf;
        tmod.dmax = 2;
        tmod.neg = 0;

        if (BN_get_flags(mod, BN_FLG_CONSTTIME) != 0)
            BN_set_flags(&tmod, BN_FLG_CONSTTIME);

        mont->ri = (BN_num_bits(mod) + (BN_BITS2 - 1)) / BN_BITS2 * BN_BITS2;
        MONT_DEBUG("ri 0x%x", mont->ri);

# if defined(OPENSSL_BN_ASM_MONT) && (BN_BITS2<=32)
        /*
         * Only certain BN_BITS2<=32 platforms actually make use of n0[1],
         * and we could use the #else case (with a shorter R value) for the
         * others.  However, currently only the assembler files do know which
         * is which.
         */

        BN_zero(R);
        if (!(BN_set_bit(R, 2 * BN_BITS2)))
            goto err;

        tmod.top = 0;
        if ((buf[0] = mod->d[0]))
            tmod.top = 1;
        if ((buf[1] = mod->top > 1 ? mod->d[1] : 0))
            tmod.top = 2;

        if (BN_is_one(&tmod))
            BN_zero(Ri);
        else if ((BN_mod_inverse(Ri, R, &tmod, ctx)) == NULL)
            goto err;
        if (!BN_lshift(Ri, Ri, 2 * BN_BITS2))
            goto err;           /* R*Ri */
        if (!BN_is_zero(Ri)) {
            if (!BN_sub_word(Ri, 1))
                goto err;
        } else {                /* if N mod word size == 1 */

            if (bn_expand(Ri, (int)sizeof(BN_ULONG) * 2) == NULL)
                goto err;
            /* Ri-- (mod double word size) */
            Ri->neg = 0;
            Ri->d[0] = BN_MASK2;
            Ri->d[1] = BN_MASK2;
            Ri->top = 2;
        }
        if (!BN_div(Ri, NULL, Ri, &tmod, ctx))
            goto err;
        /*
         * Ni = (R*Ri-1)/N, keep only couple of least significant words:
         */
        mont->n0[0] = (Ri->top > 0) ? Ri->d[0] : 0;
        mont->n0[1] = (Ri->top > 1) ? Ri->d[1] : 0;
# else
        BN_zero(R);
        if (!(BN_set_bit(R, BN_BITS2)))
            goto err;           /* R */

        buf[0] = mod->d[0];     /* tmod = N mod word size */
        MONT_DEBUG("mod->d[0] 0x%lx" , mod->d[0]);
        buf[1] = 0;
        tmod.top = buf[0] != 0 ? 1 : 0;
        /* Ri = R^-1 mod N */
        if (BN_is_one(&tmod))
            BN_zero(Ri);
        else if ((BN_mod_inverse(Ri, R, &tmod, ctx)) == NULL)
            goto err;
        MONT_BN((16,Ri,&xptr,R,&yptr,&tmod,&zptr,NULL), "Ri 0x%s R 0x%s tmod 0x%s",xptr,yptr,zptr);
        if (!BN_lshift(Ri, Ri, BN_BITS2))
            goto err;           /* R*Ri */
        MONT_BN((16,Ri,&xptr,NULL),"Ri 0x%s", xptr);
        if (!BN_is_zero(Ri)) {
            if (!BN_sub_word(Ri, 1))
                goto err;
            MONT_BN((16,Ri,&xptr,NULL),"Ri 0x%s",xptr);
        } else {                /* if N mod word size == 1 */

            if (!BN_set_word(Ri, BN_MASK2))
                goto err;       /* Ri-- (mod word size) */
            MONT_BN((16,Ri,&xptr,NULL),"Ri 0x%s", xptr);
        }
        MONT_BN((16,&tmod,&xptr,NULL),"tmod 0x%s",xptr);
        if (!BN_div(Ri, NULL, Ri, &tmod, ctx))
            goto err;
        MONT_BN((16,Ri,&xptr,NULL),"Ri 0x%s", xptr);
        /*
         * Ni = (R*Ri-1)/N, keep only least significant word:
         */
        mont->n0[0] = (Ri->top > 0) ? Ri->d[0] : 0;
        mont->n0[1] = 0;
        MONT_DEBUG("n0[0] 0x%lx", mont->n0[0]);
# endif
    }
#else                           /* !MONT_WORD */
    {                           /* bignum version */
        mont->ri = BN_num_bits(&mont->N);
        BN_zero(R);
        if (!BN_set_bit(R, mont->ri))
            goto err;           /* R = 2^ri */
        /* Ri = R^-1 mod N */
        if ((BN_mod_inverse(Ri, R, &mont->N, ctx)) == NULL)
            goto err;
        MONT_BN((16,Ri,&xptr,R,&yptr,NULL),"Ri 0x%s R 0x%s",xptr,yptr);
        if (!BN_lshift(Ri, Ri, mont->ri))
            goto err;           /* R*Ri */
        MONT_BN((16,Ri,&xptr,NULL),"Ri 0x%s", xptr);
        if (!BN_sub_word(Ri, 1))
            goto err;
        MONT_BN((16,Ri,&xptr,NULL),"Ri 0x%s", xptr);
        /*
         * Ni = (R*Ri-1) / N
         */
        if (!BN_div(&(mont->Ni), NULL, Ri, &mont->N, ctx))
            goto err;
        MONT_BN((16,Ri,&xptr,NULL),"Ri 0x%s", xptr);
    }
#endif

    /* setup RR for conversions */
    BN_zero(&(mont->RR));
    if (!BN_set_bit(&(mont->RR), mont->ri * 2))
        goto err;
    MONT_BN((16,&(mont->RR),&xptr,NULL),"mont->RR 0x%s ri 0x%x", xptr,mont->ri);
    if (!BN_mod(&(mont->RR), &(mont->RR), &(mont->N), ctx))
        goto err;
    MONT_BN((16,&(mont->RR),&xptr,&(mont->N),&yptr,NULL),"mont->RR 0x%s mont->N 0x%s", xptr,yptr);
    for (i = mont->RR.top, ret = mont->N.top; i < ret; i++)
        mont->RR.d[i] = 0;
    mont->RR.top = ret;
    mont->RR.flags |= BN_FLG_FIXED_TOP;
    MONT_BN((16,&(mont->RR),&xptr,&(mont->N),&yptr,&(mont->Ni),&zptr,NULL),"mont->RR 0x%s mont->N 0x%s mont->Ni 0x%s mont->n0[0] 0x%lx mont->n0[1] 0x%lx mont->ri 0x%x",xptr,yptr,zptr,mont->n0[0],mont->n0[1],mont->ri);

    ret = 1;
 err:
    BN_CTX_end(ctx);
    return ret;
}

BN_MONT_CTX *BN_MONT_CTX_copy(BN_MONT_CTX *to, BN_MONT_CTX *from)
{
    if (to == from)
        return to;

    if (!BN_copy(&(to->RR), &(from->RR)))
        return NULL;
    if (!BN_copy(&(to->N), &(from->N)))
        return NULL;
    if (!BN_copy(&(to->Ni), &(from->Ni)))
        return NULL;
    to->ri = from->ri;
    to->n0[0] = from->n0[0];
    to->n0[1] = from->n0[1];
    return to;
}

BN_MONT_CTX *BN_MONT_CTX_set_locked(BN_MONT_CTX **pmont, CRYPTO_RWLOCK *lock,
                                    const BIGNUM *mod, BN_CTX *ctx)
{
    BN_MONT_CTX *ret;

    if (!CRYPTO_THREAD_read_lock(lock))
        return NULL;
    ret = *pmont;
    CRYPTO_THREAD_unlock(lock);
    if (ret)
        return ret;

    /*
     * We don't want to serialize globally while doing our lazy-init math in
     * BN_MONT_CTX_set. That punishes threads that are doing independent
     * things. Instead, punish the case where more than one thread tries to
     * lazy-init the same 'pmont', by having each do the lazy-init math work
     * independently and only use the one from the thread that wins the race
     * (the losers throw away the work they've done).
     */
    ret = BN_MONT_CTX_new();
    if (ret == NULL)
        return NULL;
    if (!BN_MONT_CTX_set(ret, mod, ctx)) {
        BN_MONT_CTX_free(ret);
        return NULL;
    }

    /* The locked compare-and-set, after the local work is done. */
    if (!CRYPTO_THREAD_write_lock(lock)) {
        BN_MONT_CTX_free(ret);
        return NULL;
    }

    if (*pmont) {
        BN_MONT_CTX_free(ret);
        ret = *pmont;
    } else
        *pmont = ret;
    CRYPTO_THREAD_unlock(lock);
    return ret;
}
