/*
 * Copyright 2008-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/crypto.h>
#include "crypto/modes.h"
#include "prov/der_log.h"

#if defined(__GNUC__) && !defined(STRICT_ALIGNMENT)
typedef size_t size_t_aX __attribute((__aligned__(1)));
#else
typedef size_t size_t_aX;
#endif

/*
 * The input and output encrypted as though 128bit cfb mode is being used.
 * The extra state information to record how much of the 128bit block we have
 * used is contained in *num;
 */
void CRYPTO_cfb128_encrypt(const unsigned char *in, unsigned char *out,
                           size_t len, const void *key,
                           unsigned char ivec[16], int *num,
                           int enc, block128_f block)
{
    unsigned int n;
    size_t l = 0;

    if (*num < 0) {
        /* There is no good way to signal an error return from here */
        *num = -1;
        return;
    }
    n = *num;

    if (enc) {
#if !defined(OPENSSL_SMALL_FOOTPRINT)
        if (16 % sizeof(size_t) == 0) { /* always true actually */
            do {
                while (n && len) {
                    *(out++) = ivec[n] ^= *(in++);
                    --len;
                    n = (n + 1) % 16;
                }
# if defined(STRICT_ALIGNMENT)
                if (((size_t)in | (size_t)out | (size_t)ivec) %
                    sizeof(size_t) != 0)
                    break;
# endif
                while (len >= 16) {
                    (*block) (ivec, ivec, key);
                    for (; n < 16; n += sizeof(size_t)) {
                        *(size_t_aX *)(out + n) =
                            *(size_t_aX *)(ivec + n)
                                ^= *(size_t_aX *)(in + n);
                    }
                    len -= 16;
                    out += 16;
                    in += 16;
                    n = 0;
                }
                if (len) {
                    CMN_OSSL_BUFFER_DEBUG(ivec,16,"input");
                    (*block) (ivec, ivec, key);
                    CMN_OSSL_BUFFER_DEBUG(ivec,16,"output");
                    while (len--) {
                        out[n] = ivec[n] ^= in[n];
                        ++n;
                    }
                }
                *num = n;
                CMN_OSSL_BUFFER_DEBUG(ivec,16,"ivec");
                CMN_OSSL_BUFFER_DEBUG(out,16,"out");
                return;
            } while (0);
        }
        /* the rest would be commonly eliminated by x86* compiler */
#endif
        while (l < len) {
            if (n == 0) {
                CMN_OSSL_BUFFER_DEBUG(ivec,16,"ivec input");
                (*block) (ivec, ivec, key);
                CMN_OSSL_BUFFER_DEBUG(ivec,16,"ivec output");
            }
            out[l] = ivec[n] ^= in[l];
            ++l;
            n = (n + 1) % 16;
        }
        CMN_OSSL_BUFFER_DEBUG(out,16,"out");
        CMN_OSSL_BUFFER_DEBUG(ivec,16,"ivec");
        *num = n;
    } else {
#if !defined(OPENSSL_SMALL_FOOTPRINT)
        if (16 % sizeof(size_t) == 0) { /* always true actually */
            do {
                while (n && len) {
                    unsigned char c;
                    *(out++) = ivec[n] ^ (c = *(in++));
                    ivec[n] = c;
                    --len;
                    n = (n + 1) % 16;
                }
# if defined(STRICT_ALIGNMENT)
                if (((size_t)in | (size_t)out | (size_t)ivec) %
                    sizeof(size_t) != 0)
                    break;
# endif
                while (len >= 16) {
                    (*block) (ivec, ivec, key);
                    for (; n < 16; n += sizeof(size_t)) {
                        size_t t = *(size_t_aX *)(in + n);
                        *(size_t_aX *)(out + n)
                            = *(size_t_aX *)(ivec + n) ^ t;
                        *(size_t_aX *)(ivec + n) = t;
                    }
                    len -= 16;
                    out += 16;
                    in += 16;
                    n = 0;
                }
                if (len) {
                    (*block) (ivec, ivec, key);
                    while (len--) {
                        unsigned char c;
                        out[n] = ivec[n] ^ (c = in[n]);
                        ivec[n] = c;
                        ++n;
                    }
                }
                *num = n;
                return;
            } while (0);
        }
        /* the rest would be commonly eliminated by x86* compiler */
#endif
        while (l < len) {
            unsigned char c;
            if (n == 0) {
                (*block) (ivec, ivec, key);
            }
            out[l] = ivec[n] ^ (c = in[l]);
            ivec[n] = c;
            ++l;
            n = (n + 1) % 16;
        }
        *num = n;
    }
}

/*
 * This expects a single block of size nbits for both in and out. Note that
 * it corrupts any extra bits in the last byte of out
 */
static void cfbr_encrypt_block(const unsigned char *in, unsigned char *out,
                               int nbits, const void *key,
                               unsigned char ivec[16], int enc,
                               block128_f block)
{
    int n, rem, num;
    unsigned char ovec[16 * 2 + 1]; /* +1 because we dereference (but don't
                                     * use) one byte off the end */

    if (nbits <= 0 || nbits > 128)
        return;

    CMN_OSSL_BUFFER_DEBUG(key,16,"key");
    CMN_OSSL_BUFFER_DEBUG(ovec,16,"ovec");
    /* fill in the first half of the new IV with the current IV */
    memcpy(ovec, ivec, 16);
    /* construct the new IV */
    CMN_OSSL_BUFFER_DEBUG(ovec,16,"ovec");
    CMN_OSSL_BUFFER_DEBUG(ivec,16,"ivec");    
    (*block) (ivec, ivec, key);
    CMN_OSSL_BUFFER_DEBUG(ivec,16,"ivec");
    num = (nbits + 7) / 8;
    if (enc)                    /* encrypt the input */
        for (n = 0; n < num; ++n){            
            CMN_OSSL_DEBUG("out[%d]ovec[16+%d] [0x%x] => [0x%x] (0x%0x ^ 0x%x)", n, n,ovec[16+n],in[n] ^ ivec[n], in[n],ivec[n]);
            out[n] = (ovec[16 + n] = in[n] ^ ivec[n]);
        }
    else                        /* decrypt the input */
        for (n = 0; n < num; ++n)
            out[n] = (ovec[16 + n] = in[n]) ^ ivec[n];
    /* shift ovec left... */
    CMN_OSSL_BUFFER_DEBUG(ovec,16,"ovec");
    //CMN_OSSL_BUFFER_DEBUG(out,16,"out");
    rem = nbits % 8;
    num = nbits / 8;
    if (rem == 0){
        memcpy(ivec, ovec + num, 16);
    }
    else{        
        for (n = 0; n < 16; ++n){
            ivec[n] = ovec[n + num] << rem | ovec[n + num + 1] >> (8 - rem);
        }
        CMN_OSSL_BUFFER_DEBUG(ivec,16,"ivec");
        CMN_OSSL_BUFFER_DEBUG(ovec,16+num,"ovec");
    }

    /* it is not necessary to cleanse ovec, since the IV is not secret */
}

/* N.B. This expects the input to be packed, MS bit first */
void CRYPTO_cfb128_1_encrypt(const unsigned char *in, unsigned char *out,
                             size_t bits, const void *key,
                             unsigned char ivec[16], int *num,
                             int enc, block128_f block)
{
    size_t n;
    unsigned char c[1], d[1];
    unsigned char tmp1,tmp2;

    CMN_OSSL_BUFFER_DEBUG(in,16,"----in");
    CMN_OSSL_BUFFER_DEBUG(ivec,16,"----ivec");
    for (n = 0; n < bits; ++n) {
        c[0] = (in[n / 8] & (1 << (7 - n % 8))) ? 0x80 : 0;
        cfbr_encrypt_block(c, d, 1, key, ivec, enc, block);
        CMN_OSSL_DEBUG("out[%ld/8] = 0x%x d[0] = 0x%x",n,out[n/8],d[0]);
        tmp1 = (out[n / 8] & ~(1 << (unsigned int)(7 - n % 8)));
        tmp2 = ((d[0] & 0x80) >> (unsigned int)(n % 8));
        CMN_OSSL_DEBUG("tmp1 0x%x = out[%ld / 8] [0x%x] & ~(1 << (unsigned int)(7 - %ld %% 8)))",tmp1,n,out[n / 8],n);
        CMN_OSSL_DEBUG("tmp2 0x%x = (d[0] [0x%x] & 0x80) >> (n %ld %% 8)",tmp2,d[0],n);
        out[n / 8] =  tmp1 | tmp2;
        CMN_OSSL_DEBUG("out[%ld /8] = 0x%x ",n,out[n / 8]);
    }
    CMN_OSSL_BUFFER_DEBUG(out,16,"----out");
}

void CRYPTO_cfb128_8_encrypt(const unsigned char *in, unsigned char *out,
                             size_t length, const void *key,
                             unsigned char ivec[16], int *num,
                             int enc, block128_f block)
{
    size_t n;

    for (n = 0; n < length; ++n){
        cfbr_encrypt_block(&in[n], &out[n], 8, key, ivec, enc, block);
    }
    CMN_OSSL_BUFFER_DEBUG(out,length,"out");
}
