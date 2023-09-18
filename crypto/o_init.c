/*
 * Copyright 2011-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "e_os.h"
#include <openssl/err.h>
#include <internal/intern_log.h>
#include <execinfo.h>


/*
 * Perform any essential OpenSSL initialization operations. Currently does
 * nothing.
 */

void OPENSSL_init(void)
{
    return;
}

int get_intern_level()
{
	static int st_intern_level = INTERN_LOG_ERROR;
	static int st_intern_inited = 0;
	char* envstr=NULL;

	if (st_intern_inited != 0) {
		return st_intern_level;
	}

	envstr = getenv("OPENSSL_LOG_LEVEL");
	if (envstr != NULL) {
		st_intern_level = atoi(envstr);
	}
	st_intern_inited = 1;
	return st_intern_level;
}

int check_intern_level(int level)
{
	int inlevel = 0;

	inlevel = get_intern_level();
	if (inlevel >= level) {
		return 1;
	}
	return 0;
}

char* format_intern_level(int level)
{
	if (level <= INTERN_LOG_ERROR) {
		return "ERROR";
	} else if (level > INTERN_LOG_ERROR && level <= INTERN_LOG_WARN) {
		return "WARN";
	} else if (level > INTERN_LOG_WARN && level <= INTERN_LOG_INFO) {
		return "INFO";
	} else if (level > INTERN_LOG_INFO && level <= INTERN_LOG_DEBUG) {
		return "DEBUG";
	}
	return "TRACE";
}

void intern_back_trace(int level,char* file, int lineno,const char* fmt,...)
{
	void** ptracebuf= NULL;
	int tracesize = 16;
	int tracelen = 0;
	int ret;
	char** psymbols=NULL;
	va_list ap;
	int i;

	if (check_intern_level(level) == 0 ){
		return;
	}

	while(1) {
		if (ptracebuf) {
			free(ptracebuf);
		}
		ptracebuf=  NULL;
		ptracebuf = malloc(sizeof(*ptracebuf) * tracesize);
		if (ptracebuf == NULL) {
			break;
		}

		ret = backtrace(ptracebuf,tracesize);
		if (ret >= tracesize) {
			tracesize <<= 1;
			continue;
		}
		tracelen = ret;

		psymbols = backtrace_symbols(ptracebuf,tracelen);
		if (psymbols == NULL) {
			break;
		}

		fprintf(stderr,"[%s:%d] SYMBOLSFUNC <%s> ",file,lineno,format_intern_level(level));
		if (fmt != NULL) {
			va_start(ap,fmt);
			vfprintf(stderr,fmt,ap);
		}

		for(i=1;i<tracelen;i++) {
			fprintf(stderr,"\nFUNC[%d] [%s] [%p]",i-1, psymbols[i],ptracebuf[i]);
		}
		fprintf(stderr,"\n");
		break;
	}

	if (psymbols) {
		free(psymbols);
	}
	psymbols = NULL;

	if (ptracebuf) {
		free(ptracebuf);
	}
	ptracebuf = NULL;
	return;
}

void intern_log(int level,const char* file,int lineno, const char* fmt,...)
{
	va_list ap;

	if (check_intern_level(level) == 0) {
		return ;
	}

	fprintf(stderr,"[%s:%d] <%s> ",file,lineno,format_intern_level(level));
	va_start(ap,fmt);
	vfprintf(stderr,fmt,ap);
	fprintf(stderr,"\n");
	fflush(stderr);
	return;
}

void intern_buffer_log(int level, const char* file,int lineno,void* pbuf,int size,const char* fmt,...)
{
	unsigned char* ptr=(unsigned char*)pbuf;
	int lasti;
	int i;
	va_list ap;

	if (check_intern_level(level) == 0) {
		return;
	}

	fprintf(stderr,"[%s:%d] <%s> [%p] size[%d:0x%x]", file,lineno,format_intern_level(level),ptr,size,size);
	va_start(ap,fmt);
	vfprintf(stderr,fmt,ap);

	lasti = 0;
	for(i=0;i<size;i++) {
		if ((i % 16) == 0) {
			if (i > 0) {
				fprintf(stderr,"    ");
				while(lasti != i) {
					if (ptr[lasti] >= 0x20 && ptr[lasti] <= 0x7e) {
						fprintf(stderr,"%c",ptr[lasti]);
					} else {
						fprintf(stderr, ".");
					}
					lasti ++;
				}
			}
			fprintf(stderr,"\n0x%08x:",i);
		}
		fprintf(stderr," 0x%02x",ptr[i]);
	}

	if (lasti != i) {
		while((i % 16)!=0) {
			fprintf(stderr,"     ");
			i ++;
		}

		fprintf(stderr,"    ");
		while(lasti < size) {
			if (ptr[lasti] >= 0x20 && ptr[lasti] <= 0x7e) {
				fprintf(stderr,"%c",ptr[lasti]);
			} else {
				fprintf(stderr, ".");
			}
			lasti ++;
		}		
 	}
 	fprintf(stderr,"\n");
 	return;
}