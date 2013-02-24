#ifndef _DNS_CACHE_
#define _DNS_CACHE_

//#include "common.h"
#include "dnsrelated.h"
#include "extendablebuffer.h"

int DNSCache_Init(void);

BOOL Cache_IsInited(void);

int DNSCache_AddItemsToCache(char *DNSBody);

int DNSCache_GetByQuestion(__in char *Question, __inout ExtendableBuffer *Buffer, __out int *RecordsLength);

void DNSCacheClose(void);

#endif /* _DNS_CACHE_ */
