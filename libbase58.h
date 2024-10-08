#ifndef LIBBASE58_H
#define LIBBASE58_H

#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif

extern bool (*b58_sha256_impl)(void *, const void *, size_t);

//2-times call , first one to grab size
extern bool b58tobin(void *bin, size_t *binsz, const char *b58, size_t b58sz); 

extern bool b58enc(char *b58, size_t *b58sz, const void *bin, size_t binsz);

#ifdef __cplusplus
}
#endif

#endif
