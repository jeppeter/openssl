#ifndef __INTERN_LOG_H_47D822EB5F5DDD396D70E3833E294350__
#define __INTERN_LOG_H_47D822EB5F5DDD396D70E3833E294350__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus*/

#ifdef __cplusplus
};
#endif /* __cplusplus*/

#define  OSSL_DEBUG(...)                                                                           \
do{                                                                                                \
	fprintf(stderr,"[%s:%d]:",__FILE__,__LINE__);                                                  \
	fprintf(stderr,__VA_ARGS__);                                                                   \
	fprintf(stderr,"\n");                                                                          \
	fflush(stderr);                                                                                \
}while(0)



#endif /* __INTERN_LOG_H_47D822EB5F5DDD396D70E3833E294350__ */
