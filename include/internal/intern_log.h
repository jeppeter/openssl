#ifndef __INTERN_LOG_H_47D822EB5F5DDD396D70E3833E294350__
#define __INTERN_LOG_H_47D822EB5F5DDD396D70E3833E294350__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus*/

#ifdef __cplusplus
};
#endif /* __cplusplus*/

#define INTERN_LOG_ERROR              0
#define INTERN_LOG_WARN               10
#define INTERN_LOG_INFO               20
#define INTERN_LOG_DEBUG              30
#define INTERN_LOG_TRACE              40


#if 0
#include <execinfo.h>

#define  BACKTRACE_DEBUG(...)                                                                     \
do{                                                                                               \
	void** __pbuf=NULL;                                                                           \
	char** __sym=NULL;                                                                            \
	int __size=4;                                                                                 \
	int __len=0;                                                                                  \
	int __ret;                                                                                    \
	int __i;                                                                                      \
	int __output = 0;                                                                             \
                                                                                                  \
	__pbuf = (void**)malloc(sizeof(*__pbuf) * __size);                                            \
	if (__pbuf != NULL ) {                                                                        \
		while(1) {                                                                                \
			__ret = backtrace(__pbuf, __size);                                                    \
			if (__ret < __size) {                                                                 \
				__len = __ret;                                                                    \
				break;                                                                            \
			}                                                                                     \
			__size <<= 1;                                                                         \
			if (__pbuf) {                                                                         \
				free(__pbuf);                                                                     \
				__pbuf = NULL;                                                                    \
			}                                                                                     \
			__pbuf = (void**) malloc(sizeof(*__pbuf) * __size);                                   \
			if (__pbuf == NULL) {                                                                 \
				break;                                                                            \
			}                                                                                     \
		}                                                                                         \
                                                                                                  \
		if (__pbuf != NULL) {                                                                     \
			__sym = backtrace_symbols(__pbuf,__len);                                              \
			if (__sym != NULL) {                                                                  \
				fprintf(stderr,"[%s:%d] SYMBOLSFUNC <DEBUG> ",__FILE__,__LINE__);                 \
				fprintf(stderr, __VA_ARGS__);                                                     \
				for(__i=0;__i < __len; __i ++) {                                                  \
					fprintf(stderr,"\nFUNC[%d] [%s] [%p]",__i, __sym[__i],__pbuf[__i]);           \
				}                                                                                 \
				fprintf(stderr, "\n");                                                            \
				__output = 1;                                                                     \
			}                                                                                     \
		}                                                                                         \
	}                                                                                             \
                                                                                                  \
	if (__output == 0) {                                                                          \
		fprintf(stderr,"[%s:%d] no symbols dump <DEBUG> ",__FILE__,__LINE__);                     \
		fprintf(stderr,__VA_ARGS__);                                                              \
		fprintf(stderr,"\n");                                                                     \
		__output = 1;                                                                             \
	}                                                                                             \
	if (__sym) {                                                                                  \
		free(__sym);                                                                              \
		__sym = NULL;                                                                             \
	}                                                                                             \
	if (__pbuf) {                                                                                 \
		free(__pbuf);                                                                             \
		__pbuf = NULL;                                                                            \
	}                                                                                             \
} while(0)

#define  OSSL_DEBUG(...)  do { fprintf(stderr,"[%s:%d] <DEBUG> ",__FILE__,__LINE__); fprintf(stderr, __VA_ARGS__); fprintf(stderr,"\n"); fflush(stderr); } while(0)

#define  OSSL_BUFFER_DEBUG(ptr,size,...)                                                          \
do {                                                                                              \
	unsigned char* __ptr = (unsigned char*)(ptr);                                                 \
	int __size = (int) (size);                                                                    \
	int __i,__lasti = 0;	                                                                      \
	fprintf(stderr,"[%s:%d] <DEBUG> [%p] size[%d:0x%x]", __FILE__,__LINE__,__ptr,__size,__size);  \
	fprintf(stderr,__VA_ARGS__);                                                                  \
	__lasti = 0;                                                                                  \
	for(__i=0;__i < __size;__i ++) {                                                              \
		if ((__i % 16) == 0) {                                                                    \
			if (__i > 0) {                                                                        \
				fprintf(stderr,"    ");                                                           \
				while(__lasti != __i) {                                                           \
					if (__ptr[__lasti] >= 0x20 && __ptr[__lasti] <= 0x7e) {                       \
						fprintf(stderr,"%c",__ptr[__lasti]);                                      \
					} else {                                                                      \
						fprintf(stderr,".");                                                      \
					}                                                                             \
					__lasti ++;                                                                   \
				}                                                                                 \
			}                                                                                     \
			fprintf(stderr,"\n0x%08x:",__i);                                                      \
		}                                                                                         \
		fprintf(stderr," 0x%02x",__ptr[__i]);                                                     \
	}                                                                                             \
                                                                                                  \
	if (__lasti != __i) {                                                                         \
		while ((__i % 16) != 0) {                                                                 \
			fprintf(stderr,"     ");                                                              \
			__i ++;                                                                               \
		}                                                                                         \
		fprintf(stderr,"    ");                                                                   \
		while(__lasti < __size) {                                                                 \
			if (__ptr[__lasti] >= 0x20 && __ptr[__lasti] <= 0x7e) {                               \
				fprintf(stderr,"%c",__ptr[__lasti]);                                              \
			} else {                                                                              \
				fprintf(stderr,".");                                                              \
			}                                                                                     \
			__lasti ++;                                                                           \
		}                                                                                         \
	}                                                                                             \
	fprintf(stderr,"\n");                                                                         \
} while(0)


#else

#define  BACK_TRACE_DUMP(...)  do { fprintf(stderr,"[%s:%d] <DEBUG> ",__FILE__,__LINE__); fprintf(stderr, __VA_ARGS__); fprintf(stderr,"\n"); } while(0)

#define BACKTRACE_DEBUG(...)  do{ intern_back_trace(INTERN_LOG_DEBUG,__FILE__,__LINE__,__VA_ARGS__); }while(0)
#define OSSL_DEBUG(...)       intern_log(INTERN_LOG_DEBUG,__FILE__,__LINE__,__VA_ARGS__);
#define OSSL_BUFFER_DEBUG(ptr,size,...)  intern_buffer_log(INTERN_LOG_DEBUG,__FILE__,__LINE__,(void*)(ptr),(int)(size),__VA_ARGS__);

#endif



#define OSSL_DEBUG_BN(X,...)                                                                      \
do{                                                                                               \
	int __retv;                                                                                   \
	BN_free_safe X;                                                                               \
	__retv = BN_format_safe X;                                                                    \
	if (__retv > 0) {                                                                             \
		OSSL_DEBUG(__VA_ARGS__);                                                                  \
	}                                                                                             \
	BN_free_safe X;                                                                               \
} while(0)

void intern_back_trace(int level,char* file, int lineno,const char* fmt,...);
void intern_log(int level,const char* file,int lineno, const char* fmt,...);
void intern_buffer_log(int level, const char* file,int lineno,void* pbuf,int size,const char* fmt,...);

#endif /* __INTERN_LOG_H_47D822EB5F5DDD396D70E3833E294350__ */
