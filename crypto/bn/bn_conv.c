/*
 * Copyright 1995-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/err.h>
#include "crypto/ctype.h"
#include "bn_local.h"

static const char Hex[] = "0123456789ABCDEF";

/* Must 'OPENSSL_free' the returned data */
char *BN_bn2hex(const BIGNUM *a)
{
    int i, j, v, z = 0;
    char *buf;
    char *p;

    if (BN_is_zero(a))
        return OPENSSL_strdup("0");
    buf = OPENSSL_malloc(a->top * BN_BYTES * 2 + 2);
    if (buf == NULL) {
        ERR_raise(ERR_LIB_BN, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    p = buf;
    if (a->neg)
        *p++ = '-';
    for (i = a->top - 1; i >= 0; i--) {
        for (j = BN_BITS2 - 8; j >= 0; j -= 8) {
            /* strip leading zeros */
            v = (int)((a->d[i] >> j) & 0xff);
            if (z || v != 0) {
                *p++ = Hex[v >> 4];
                *p++ = Hex[v & 0x0f];
                z = 1;
            }
        }
    }
    *p = '\0';
 err:
    return buf;
}

#ifndef FIPS_MODULE
/* No BIO_snprintf in FIPS_MODULE */
/* Must 'OPENSSL_free' the returned data */
char *BN_bn2dec(const BIGNUM *a)
{
    int i = 0, num, ok = 0, n, tbytes;
    char *buf = NULL;
    char *p;
    BIGNUM *t = NULL;
    BN_ULONG *bn_data = NULL, *lp;
    int bn_data_num;

    /*-
     * get an upper bound for the length of the decimal integer
     * num <= (BN_num_bits(a) + 1) * log(2)
     *     <= 3 * BN_num_bits(a) * 0.101 + log(2) + 1     (rounding error)
     *     <= 3 * BN_num_bits(a) / 10 + 3 * BN_num_bits / 1000 + 1 + 1
     */
    i = BN_num_bits(a) * 3;
    num = (i / 10 + i / 1000 + 1) + 1;
    tbytes = num + 3;   /* negative and terminator and one spare? */
    bn_data_num = num / BN_DEC_NUM + 1;
    bn_data = OPENSSL_malloc(bn_data_num * sizeof(BN_ULONG));
    buf = OPENSSL_malloc(tbytes);
    if (buf == NULL || bn_data == NULL) {
        ERR_raise(ERR_LIB_BN, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    if ((t = BN_dup(a)) == NULL)
        goto err;

    p = buf;
    lp = bn_data;
    if (BN_is_zero(t)) {
        *p++ = '0';
        *p++ = '\0';
    } else {
        if (BN_is_negative(t))
            *p++ = '-';

        while (!BN_is_zero(t)) {
            if (lp - bn_data >= bn_data_num)
                goto err;
            *lp = BN_div_word(t, BN_DEC_CONV);
            if (*lp == (BN_ULONG)-1)
                goto err;
            lp++;
        }
        lp--;
        /*
         * We now have a series of blocks, BN_DEC_NUM chars in length, where
         * the last one needs truncation. The blocks need to be reversed in
         * order.
         */
        n = BIO_snprintf(p, tbytes - (size_t)(p - buf), BN_DEC_FMT1, *lp);
        if (n < 0)
            goto err;
        p += n;
        while (lp != bn_data) {
            lp--;
            n = BIO_snprintf(p, tbytes - (size_t)(p - buf), BN_DEC_FMT2, *lp);
            if (n < 0)
                goto err;
            p += n;
        }
    }
    ok = 1;
 err:
    OPENSSL_free(bn_data);
    BN_free(t);
    if (ok)
        return buf;
    OPENSSL_free(buf);
    return NULL;
}
#endif

int BN_hex2bn(BIGNUM **bn, const char *a)
{
    BIGNUM *ret = NULL;
    BN_ULONG l = 0;
    int neg = 0, h, m, i, j, k, c;
    int num;

    if (a == NULL || *a == '\0')
        return 0;

    if (*a == '-') {
        neg = 1;
        a++;
    }

    for (i = 0; i <= INT_MAX / 4 && ossl_isxdigit(a[i]); i++)
        continue;

    if (i == 0 || i > INT_MAX / 4)
        return 0;

    num = i + neg;
    if (bn == NULL)
        return num;

    /* a is the start of the hex digits, and it is 'i' long */
    if (*bn == NULL) {
        if ((ret = BN_new()) == NULL)
            return 0;
    } else {
        ret = *bn;
        if (BN_get_flags(ret, BN_FLG_STATIC_DATA)) {
            ERR_raise(ERR_LIB_BN, ERR_R_PASSED_INVALID_ARGUMENT);
            return 0;
        }
        BN_zero(ret);
    }

    /* i is the number of hex digits */
    if (bn_expand(ret, i * 4) == NULL)
        goto err;

    j = i;                      /* least significant 'hex' */
    m = 0;
    h = 0;
    while (j > 0) {
        m = (BN_BYTES * 2 <= j) ? BN_BYTES * 2 : j;
        l = 0;
        for (;;) {
            c = a[j - m];
            k = OPENSSL_hexchar2int(c);
            if (k < 0)
                k = 0;          /* paranoia */
            l = (l << 4) | k;

            if (--m <= 0) {
                ret->d[h++] = l;
                break;
            }
        }
        j -= BN_BYTES * 2;
    }
    ret->top = h;
    bn_correct_top(ret);

    *bn = ret;
    bn_check_top(ret);
    /* Don't set the negative flag if it's zero. */
    if (ret->top != 0)
        ret->neg = neg;
    return num;
 err:
    if (*bn == NULL)
        BN_free(ret);
    return 0;
}

int BN_dec2bn(BIGNUM **bn, const char *a)
{
    BIGNUM *ret = NULL;
    BN_ULONG l = 0;
    int neg = 0, i, j;
    int num;

    if (a == NULL || *a == '\0')
        return 0;
    if (*a == '-') {
        neg = 1;
        a++;
    }

    for (i = 0; i <= INT_MAX / 4 && ossl_isdigit(a[i]); i++)
        continue;

    if (i == 0 || i > INT_MAX / 4)
        goto err;

    num = i + neg;
    if (bn == NULL)
        return num;

    /*
     * a is the start of the digits, and it is 'i' long. We chop it into
     * BN_DEC_NUM digits at a time
     */
    if (*bn == NULL) {
        if ((ret = BN_new()) == NULL)
            return 0;
    } else {
        ret = *bn;
        BN_zero(ret);
    }

    /* i is the number of digits, a bit of an over expand */
    if (bn_expand(ret, i * 4) == NULL)
        goto err;

    j = BN_DEC_NUM - i % BN_DEC_NUM;
    if (j == BN_DEC_NUM)
        j = 0;
    l = 0;
    while (--i >= 0) {
        l *= 10;
        l += *a - '0';
        a++;
        if (++j == BN_DEC_NUM) {
            if (!BN_mul_word(ret, BN_DEC_CONV)
                || !BN_add_word(ret, l))
                goto err;
            l = 0;
            j = 0;
        }
    }

    bn_correct_top(ret);
    *bn = ret;
    bn_check_top(ret);
    /* Don't set the negative flag if it's zero. */
    if (ret->top != 0)
        ret->neg = neg;
    return num;
 err:
    if (*bn == NULL)
        BN_free(ret);
    return 0;
}

int BN_asc2bn(BIGNUM **bn, const char *a)
{
    const char *p = a;

    if (*p == '-')
        p++;

    if (p[0] == '0' && (p[1] == 'X' || p[1] == 'x')) {
        if (!BN_hex2bn(bn, p + 2))
            return 0;
    } else {
        if (!BN_dec2bn(bn, p))
            return 0;
    }
    /* Don't set the negative flag if it's zero. */
    if (*a == '-' && (*bn)->top != 0)
        (*bn)->neg = 1;
    return 1;
}

int BN_format_safe(int base, ...)
{
    va_list oldap,ap;
    const BIGNUM* curbn=NULL;
    char** ppcur=NULL;
    int retlen = 0;
    int i;
    int ret = -1;
    char*** ppptmp = NULL;    
    char* curalloc=NULL;
    char* curptr =NULL;
    int dellen = 0;
    int slen = 0;
    va_start(ap,base);
    va_copy(oldap,ap);

    while(1) {
        curbn = va_arg(ap,const BIGNUM*);
        if (curbn == NULL) {
            break;
        }
        ppcur = va_arg(ap,char**);
        if (ppcur == NULL) {
            ret = -EINVAL;
            goto fail;
        }
        retlen += 1;
    }

    if (retlen == 0) {
        ret = -EINVAL;
        goto fail;
    }

    ppptmp = malloc(sizeof(ppptmp[0]) * retlen);
    if (ppptmp == NULL) {
        ret = -errno;
        goto fail;
    }

    va_copy(ap,oldap);

    memset(ppptmp,0,sizeof(ppptmp[0]) * retlen);
    for(i=0;i<retlen;i++) {
        curbn = va_arg(ap,const BIGNUM*);
        if (curbn == NULL) {
            ret = -EINVAL;
            goto fail;
        }
        ppcur = va_arg(ap,char**);
        if (ppcur == NULL) {
            ret = -EINVAL;
            goto fail;
        }
        if (*ppcur != NULL) {
            free(*ppcur);
            *ppcur = NULL;
        }
        ppptmp[i] = ppcur;
    }

    va_copy(ap,oldap);
    for(i=0;i<retlen;i++) {
        curbn = va_arg(ap,const BIGNUM*);
        if (curbn == NULL) {
            ret = -EINVAL;
            goto fail;
        }
        va_arg(ap,char**);
        ppcur = ppptmp[i];
        if (base == 16) {
            *ppcur = BN_bn2hex(curbn);
        } else {
            *ppcur = BN_bn2dec(curbn);
        }

        if (*ppcur == NULL) {
            ret = -ENOMEM;
            goto fail;
        }
        curptr = *ppcur;
        if (*curptr == '0') {
            dellen = 0;
            while (*curptr == '0') {
                dellen ++;
                curptr ++;
            }
            if (*curptr == 0x0)  {
                /*make sure the last one*/
                dellen --;
                curptr --;
            }

            if (curalloc != NULL) {
                free(curalloc);
            }
            curalloc = NULL;
            slen = strlen(*ppcur);
            slen -= dellen;
            if (slen <= 0) {
                fprintf(stderr,"slen == 0\n");
                curalloc = malloc(2);
            } else {
                curalloc = malloc(slen + 1);    
            }            
            if (curalloc == NULL) {
                ret = -ENOMEM;
                goto fail;
            }
            if (slen == 0) {
                memset(curalloc,0,2);
                curalloc[0] = '0';
            } else {                
                memset(curalloc,0,slen + 1);
                memcpy(curalloc,curptr,slen);
            }
            if (*ppcur) {
                free(*ppcur);
            }
            *ppcur = curalloc;
            curalloc = NULL;
        }
    }

    if (curalloc) {
        free(curalloc);
    }
    curalloc = NULL;

    if (ppptmp) {
        free(ppptmp);
    }
    ppptmp = NULL;



    return retlen;
fail:
    if (ppptmp != NULL) {
        for (i=0;i<retlen;i++) {
            if (ppptmp[i] != NULL) {
                ppcur = ppptmp[i];
                if (*ppcur) {
                    free(*ppcur);
                }
                *ppcur = NULL;
                ppptmp[i] = NULL;
            }
        }
        free(ppptmp);
    }
    ppptmp = NULL;

    if (curalloc) {
        free(curalloc);
    }
    curalloc = NULL;

    if (ret < 0) {
        errno = -ret;    
    }    
    return ret;
}

void BN_free_safe(int base, ...)
{
    va_list oldap,ap;
    const BIGNUM* curbn = NULL;
    char** ppcur = NULL;
    va_start(ap,base);
    va_copy(oldap,ap);

    while(1) {
        curbn = va_arg(ap,const BIGNUM*);
        if (curbn == NULL) {
            break;
        }
        ppcur = va_arg(ap,char**);
        if (ppcur != NULL && *ppcur != NULL) {
            free(*ppcur);
            *ppcur = NULL;
        }
    }
    return;
}