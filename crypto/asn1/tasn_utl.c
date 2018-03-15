/* tasn_utl.c */
/* Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project 2000.
 */
/* ====================================================================
 * Copyright (c) 2000-2004 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */


#include <stddef.h>
#include <string.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/objects.h>
#include <openssl/err.h>

/* Utility functions for manipulating fields and offsets */

/* Add 'offset' to 'addr' */
#define offset2ptr(addr, offset) (void *)(((char *) addr) + offset)

char* format_ASN1_ADB_TABLE(const ASN1_ADB_TABLE* adbtbl)
	{
		static char st_asn1_adb_table_buf[2048];
		char* ptr;
		int leftlen = sizeof(st_asn1_adb_table_buf);
		int ret;
		ptr = st_asn1_adb_table_buf;
		if (adbtbl != NULL) {
			ret = snprintf(ptr,leftlen,"ASN1_ADB_TABLE[%p];value[%ld:0x%lx];tt[%s];", adbtbl, adbtbl->value, adbtbl->value,format_ASN1_TEMPLATE(&(adbtbl->tt)));
			if (ret >= 0 && ret < leftlen) {
				ptr += ret;
				leftlen -= ret;
			}
		} else {
			ret = snprintf(ptr,leftlen,"ASN1_ADB_TABLE[nil]");
		}
		return st_asn1_adb_table_buf;
	}

char* format_ASN1_ADB(const ASN1_ADB* adb)
	{
		static char st_asn1_adb_buf[2048];
		char* ptr;
		int leftlen = sizeof(st_asn1_adb_buf);
		int ret;
		int i;

		ptr =st_asn1_adb_buf;
		if (adb != NULL) {
			ret = snprintf(ptr, leftlen, "ASN1_ADB[%p];flags[%ld:0x%lx];offset[%ld:0x%lx];", adb, adb->flags, adb->flags, adb->offset, adb->offset);
			if (ret >= 0 && ret < leftlen) {
				ptr += ret;
				leftlen -= ret;
			}

			if (adb->app_items != NULL) {
				for (i=0;adb->app_items[i] != NULL; i ++) {
					ret = snprintf(ptr, leftlen, "app_items[%d][%p];",i, adb->app_items[i]);
					if (ret >= 0 && ret < leftlen) {
						ptr += ret;
						leftlen -= ret;
					}
				}
			}
			ret = snprintf(ptr, leftlen, "%s",format_ASN1_ADB_TABLE(adb->tbl));
			if (ret < 0) {
				ptr += ret;
				leftlen -= ret;
			}
			ret = snprintf(ptr, leftlen,"tcount[%ld:0x%lx];default_tt[%s];null_tt[%s];",adb->tblcount, adb->tblcount, format_ASN1_TEMPLATE(adb->default_tt),format_ASN1_TEMPLATE(adb->null_tt));
			if (ret >= 0 && ret < leftlen) {
				ptr += ret;
				leftlen -= ret;
			}
		} else {
			ret = snprintf(ptr,leftlen,"ASN1_ADB[nil]");
		}
		

		return st_asn1_adb_buf;
	}

char* format_ASN1_TEMPLATE(const ASN1_TEMPLATE* template) 
	{
		static char st_asn1_template_buf[2048];
		char* ptr;
		int ret;
		int leftlen = sizeof(st_asn1_template_buf);
		ptr = st_asn1_template_buf;

		if (template != NULL) {
			ret = snprintf(ptr,leftlen,"ASN1_TEMPLATE[%p];",template);
			if (ret >= 0 && ret < leftlen) {
				ptr += ret;
				leftlen -= ret;
			}
#ifndef NO_ASN1_FIELD_NAMES
			ret = snprintf(ptr,leftlen,"field_name[%s];", template->field_name);
			if (ret >= 0 && ret < leftlen) {
				ptr += ret;
				leftlen -= ret;
			}
#endif		
			ret = snprintf(ptr,leftlen,"flags[%ld:0x%lx];tag[%ld:0x%lx];offset[%ld:0x%lx];", template->flags,template->flags, template->tag,template->tag, template->offset,template->offset);
			if (ret >= 0 && ret < leftlen) {
				ptr += ret;
				leftlen -= ret;
			}
			ret = snprintf(ptr,leftlen,"item [%p];", template->item);
			if (ret >= 0 && ret < leftlen) {
				ptr += ret;
				leftlen -= ret;
			}
		} else {
			ret = snprintf(ptr,leftlen,"ASN1_TEMPLATE[nil]");
		}
		return st_asn1_template_buf;
	}

char* format_ASN1_ITEM(const ASN1_ITEM* it)
	{
		static char st_asn1_item_buf[2048];
		int ret;
		int leftlen = sizeof(st_asn1_item_buf);
		char* ptr=NULL;
		int i;
		ptr = st_asn1_item_buf;

		if (it != NULL) {
			ret = snprintf(ptr,leftlen,"ASN1_ITEM[%p];",it);
			if (ret >= 0 && ret < leftlen) {
				ptr += ret;
				leftlen -= ret;
			}

#ifndef NO_ASN1_FIELD_NAMES
			ret = snprintf(ptr,leftlen,"name[%s];", it->sname);
			if (ret >= 0 && ret < leftlen) {
				ptr += ret;
				leftlen -= ret;
			}
#endif			
			ret = snprintf(ptr,leftlen,"itype[%d:0x%x];utype[%ld:0x%lx];tcount[%ld];", it->itype,it->itype,it->utype,it->utype,it->tcount);
			if (ret >= 0 && ret < leftlen) {
				ptr += ret;
				leftlen -= ret;
			}

			for (i=0;i<it->tcount ;i ++) {
				ret = snprintf(ptr, leftlen,"\n[%d]%s", i, format_ASN1_TEMPLATE(&(it->templates[i])));
				if (ret >= 0 && ret < leftlen) {
					ptr += ret;
					leftlen -= ret;
				}
			}

			if (it->tcount > 0){
				ret = snprintf(ptr,leftlen,"\n");
				if (ret >= 0 && ret < leftlen) {
					ptr += ret;
					leftlen -= ret;
				}
			}

			ret = snprintf(ptr,leftlen,"funcs[%p];size[%ld:0x%lx];",it->funcs,it->size,it->size);
			if (ret >= 0 && ret < leftlen) {
				ptr += ret;
				leftlen -= ret;
			}
		} else {
			ret = snprintf(ptr,leftlen, "ASN1_ITEM[nil]");
		}
		return st_asn1_item_buf;
	}
/* Given an ASN1_ITEM CHOICE type return
 * the selector value
 */

int asn1_get_choice_selector(ASN1_VALUE **pval, const ASN1_ITEM *it)
	{
	int *sel = offset2ptr(*pval, it->utype);
	return *sel;
	}

/* Given an ASN1_ITEM CHOICE type set
 * the selector value, return old value.
 */

int asn1_set_choice_selector(ASN1_VALUE **pval, int value, const ASN1_ITEM *it)
	{	
	int *sel, ret;
	sel = offset2ptr(*pval, it->utype);
	ret = *sel;
	*sel = value;
	return ret;
	}

/* Do reference counting. The value 'op' decides what to do. 
 * if it is +1 then the count is incremented. If op is 0 count is
 * set to 1. If op is -1 count is decremented and the return value
 * is the current refrence count or 0 if no reference count exists.
 */

int asn1_do_lock(ASN1_VALUE **pval, int op, const ASN1_ITEM *it)
	{
	const ASN1_AUX *aux;
	int *lck, ret;
	if ((it->itype != ASN1_ITYPE_SEQUENCE)
	   && (it->itype != ASN1_ITYPE_NDEF_SEQUENCE))
		return 0;
	aux = it->funcs;
	if (!aux || !(aux->flags & ASN1_AFLG_REFCOUNT))
		return 0;
	lck = offset2ptr(*pval, aux->ref_offset);
	if (op == 0)
		{
		*lck = 1;
		return 1;
		}
	ret = CRYPTO_add(lck, op, aux->ref_lock);
#ifdef REF_PRINT
	fprintf(stderr, "%s: Reference Count: %d\n", it->sname, *lck);
#endif
#ifdef REF_CHECK
	if (ret < 0) 
		fprintf(stderr, "%s, bad reference count\n", it->sname);
#endif
	return ret;
	}

static ASN1_ENCODING *asn1_get_enc_ptr(ASN1_VALUE **pval, const ASN1_ITEM *it)
	{
	const ASN1_AUX *aux;
	if (!pval || !*pval)
		return NULL;
	aux = it->funcs;
	if (!aux || !(aux->flags & ASN1_AFLG_ENCODING))
		return NULL;
	return offset2ptr(*pval, aux->enc_offset);
	}

void asn1_enc_init(ASN1_VALUE **pval, const ASN1_ITEM *it)
	{
	ASN1_ENCODING *enc;
	enc = asn1_get_enc_ptr(pval, it);
	if (enc)
		{
		enc->enc = NULL;
		enc->len = 0;
		enc->modified = 1;
		}
	}

void asn1_enc_free(ASN1_VALUE **pval, const ASN1_ITEM *it)
	{
	ASN1_ENCODING *enc;
	enc = asn1_get_enc_ptr(pval, it);
	if (enc)
		{
		if (enc->enc)
			OPENSSL_free(enc->enc);
		enc->enc = NULL;
		enc->len = 0;
		enc->modified = 1;
		}
	}

int asn1_enc_save(ASN1_VALUE **pval, const unsigned char *in, int inlen,
							 const ASN1_ITEM *it)
	{
	ASN1_ENCODING *enc;
	enc = asn1_get_enc_ptr(pval, it);
	if (!enc)
		return 1;

	if (enc->enc)
		OPENSSL_free(enc->enc);
	enc->enc = OPENSSL_malloc(inlen);
	if (!enc->enc)
		return 0;
	memcpy(enc->enc, in, inlen);
	enc->len = inlen;
	enc->modified = 0;

	return 1;
	}
		
int asn1_enc_restore(int *len, unsigned char **out, ASN1_VALUE **pval,
							const ASN1_ITEM *it)
	{
	ASN1_ENCODING *enc;
	enc = asn1_get_enc_ptr(pval, it);
	if (!enc || enc->modified)
		return 0;
	if (out)
		{
		memcpy(*out, enc->enc, enc->len);
		*out += enc->len;
		}
	if (len)
		*len = enc->len;
	return 1;
	}

/* Given an ASN1_TEMPLATE get a pointer to a field */
ASN1_VALUE ** asn1_get_field_ptr(ASN1_VALUE **pval, const ASN1_TEMPLATE *tt)
	{
	ASN1_VALUE **pvaltmp;
	if (tt->flags & ASN1_TFLG_COMBINE)
		return pval;
	pvaltmp = offset2ptr(*pval, tt->offset);
	/* NOTE for BOOLEAN types the field is just a plain
 	 * int so we can't return int **, so settle for
	 * (int *).
	 */
	return pvaltmp;
	}

/* Handle ANY DEFINED BY template, find the selector, look up
 * the relevant ASN1_TEMPLATE in the table and return it.
 */

const ASN1_TEMPLATE *asn1_do_adb(ASN1_VALUE **pval, const ASN1_TEMPLATE *tt,
								int nullerr)
	{
	const ASN1_ADB *adb;
	const ASN1_ADB_TABLE *atbl;
	long selector;
	ASN1_VALUE **sfld;
	int i;
	if (!(tt->flags & ASN1_TFLG_ADB_MASK))
		return tt;

	/* Else ANY DEFINED BY ... get the table */
	adb = ASN1_ADB_ptr(tt->item);

	/* Get the selector field */
	sfld = offset2ptr(*pval, adb->offset);

	/* Check if NULL */
	if (!sfld)
		{
		if (!adb->null_tt)
			goto err;
		return adb->null_tt;
		}

	/* Convert type to a long:
	 * NB: don't check for NID_undef here because it
	 * might be a legitimate value in the table
	 */
	if (tt->flags & ASN1_TFLG_ADB_OID) 
		selector = OBJ_obj2nid((ASN1_OBJECT *)*sfld);
	else 
		selector = ASN1_INTEGER_get((ASN1_INTEGER *)*sfld);

	/* Try to find matching entry in table
	 * Maybe should check application types first to
	 * allow application override? Might also be useful
	 * to have a flag which indicates table is sorted and
	 * we can do a binary search. For now stick to a
	 * linear search.
	 */

	for (atbl = adb->tbl, i = 0; i < adb->tblcount; i++, atbl++)
		if (atbl->value == selector)
			return &atbl->tt;

	/* FIXME: need to search application table too */

	/* No match, return default type */
	if (!adb->default_tt)
		goto err;		
	return adb->default_tt;
	
	err:
	/* FIXME: should log the value or OID of unsupported type */
	if (nullerr)
		ASN1err(ASN1_F_ASN1_DO_ADB,
			ASN1_R_UNSUPPORTED_ANY_DEFINED_BY_TYPE);
	return NULL;
	}
